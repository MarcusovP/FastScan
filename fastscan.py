#!/usr/bin/env python3
import asyncio
import socket
import json
import re
import argparse
from time import perf_counter

import aiohttp
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live

######## CONFIG ########
DEFAULT_TIMEOUT     = 1.0     # сек. на TCP-connect
DEFAULT_HTTP_TOUT   = 3.0     # сек. на HTTP GET
DEFAULT_CONCURRENCY = 500     # одновременные TCP-коннекты
HTTPS_PORTS         = {443, 8443, 9443}
MAX_TITLE_LEN       = 100
########################

console = Console()

####################################################################
async def scan_port(ip: str, port: int, sem: asyncio.Semaphore,
                    http_session: aiohttp.ClientSession, hostname_for_http: str,
                    do_web: bool) -> dict | None:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=DEFAULT_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            return None                                   # порт закрыт / фильтруется

        # --- Порт открыт ---
        port_info = {"port": port}

        if not do_web:                                    # только TCP-скан
            port_info.update(status=None, title="")
            return port_info

        proto = "https" if port in HTTPS_PORTS else "http"
        url   = f"{proto}://{hostname_for_http}:{port}"

        try:
            async with http_session.get(url, allow_redirects=True) as resp:
                port_info["status"] = resp.status
                text = await resp.text(errors="ignore")
                m = re.search(r"(?is)<title>(.*?)</title>", text)
                title = (m.group(1).strip() if m else "")[:MAX_TITLE_LEN]
                if len(title) == MAX_TITLE_LEN:
                    title += "..."
                port_info["title"] = title
        except Exception:
            port_info.update(status=None, title="")       # не HTTP-сервис или TLS-ошибка

        return port_info
####################################################################

async def run_scan(target_host: str, start_port: int, end_port: int,
                   concurrency: int, do_web: bool, output_file: str | None):
    # DNS один раз – получаем IP
    try:
        ip_addr = socket.gethostbyname(target_host)
    except socket.gaierror as e:
        console.print(f"[red]Не удалось резолвить {target_host}: {e}[/red]")
        return

    total_ports = end_port - start_port + 1
    console.print(f"[bold cyan]⟹ Сканирую[/bold cyan] [magenta]{target_host}[/magenta] "
                  f"({ip_addr}) : {start_port}-{end_port}  "
                  f"([yellow]{total_ports}[/yellow] портов, "
                  f"конкурентность {concurrency})")

    # Таблица для открытых портов
    tbl_cols = ("Port", "Status", "Title") if do_web else ("Port",)
    table = Table(*tbl_cols, title=f"Open Ports on {target_host}")

    # Прогресс-бар
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    p_task = progress.add_task("Scanning", total=total_ports)

    conn = aiohttp.TCPConnector(limit=concurrency, ssl=False)   # ssl=False → IGNORE cert
    async with aiohttp.ClientSession(connector=conn,
                                     timeout=aiohttp.ClientTimeout(total=DEFAULT_HTTP_TOUT)) as http_sess:
        sem   = asyncio.Semaphore(concurrency)
        start = perf_counter()

        tasks = [
            asyncio.create_task(
                scan_port(ip_addr, port, sem, http_sess,       # TCP по IP
                          target_host, do_web)                 # HTTP по hostname  # FIX
            )
            for port in range(start_port, end_port + 1)
        ]

        live_render = Group(table, Panel(progress, title="Progress", border_style="green", padding=(1,1), height=5))
        with Live(live_render, console=console, refresh_per_second=10, vertical_overflow="visible") as live:
            for coro in asyncio.as_completed(tasks):
                res = await coro
                progress.advance(p_task)
                if res:                                        # порт открыт
                    if do_web:
                        status = str(res["status"]) if res["status"] is not None else "-"
                        title  = res["title"]
                        table.add_row(str(res["port"]), status, title)
                    else:
                        table.add_row(str(res["port"]))
                    live.refresh()

        elapsed = perf_counter() - start
        console.print(f"[bold green]✔ Готово[/bold green] за {elapsed:.1f} с. "
                      f"Найдено портов: [yellow]{len(table.rows)}[/yellow]")

        if output_file:
            data_to_dump = [row.cells for row in table.rows]   # simple list
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data_to_dump, f, indent=2, ensure_ascii=False)
                console.print(f"[grey]Сохранено в {output_file}[/grey]")
            except Exception as e:
                console.print(f"[red]Ошибка записи {output_file}: {e}[/red]")

def parse_args():
    ap = argparse.ArgumentParser(description="Async-сканер TCP/HTTP с Rich-UI")
    ap.add_argument("target", help="IP или домен цели")
    ap.add_argument("--start", type=int, default=1, help="Начальный порт (1)")
    ap.add_argument("--end",   type=int, default=65535, help="Конечный порт (65535)")
    ap.add_argument("--threads", type=int, default=DEFAULT_CONCURRENCY,
                    help=f"Параллельных TCP-коннектов (def {DEFAULT_CONCURRENCY})")
    ap.add_argument("--web", action="store_true",
                    help="GET HTTP/HTTPS, показать status/title")
    ap.add_argument("-o", "--output", help="Файл JSON для результатов")
    return ap.parse_args()

if __name__ == "__main__":
    try:
        args = parse_args()
        asyncio.run(run_scan(args.target, args.start, args.end,
                             args.threads, args.web, args.output))
    except KeyboardInterrupt:
        console.print("\n[red]Прервано пользователем[/red]")
