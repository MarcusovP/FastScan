#!/usr/bin/env python3
from __future__ import annotations
import argparse, contextlib, html, json, logging, re, signal, socket, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Final, Iterable, NamedTuple, Self
import requests
from requests.exceptions import RequestException
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
DEFAULT_RANGE: Final[str] = "1-65535"
MAX_WORKERS: Final[int] = 1000
MAX_PARALLEL: Final[int] = 1000
SOCK_TIMEOUT: Final[float] = 0.05
HTTP_TIMEOUT: Final[float] = 2.0
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
console = Console(highlight=False)
class ScanResult(NamedTuple):
    port: int
    service: str
    title: str | None
class PortScanner:
    def __init__(self, host: str, ports: Iterable[int], *, workers: int = MAX_WORKERS, sock_timeout: float = SOCK_TIMEOUT, http_timeout: float = HTTP_TIMEOUT) -> None:
        self.host, self.ports = host, tuple(ports)
        self.workers, self.sock_timeout, self.http_timeout = workers, sock_timeout, http_timeout
        self._sem = threading.BoundedSemaphore(MAX_PARALLEL)
        self._executor: ThreadPoolExecutor | None = None
        self._latency: float | None = None
        self._scanned = 0
    def __enter__(self) -> Self:
        self._executor = ThreadPoolExecutor(max_workers=self.workers)
        return self
    def __exit__(self, *_exc) -> bool:
        if self._executor:
            self._executor.shutdown(wait=True, cancel_futures=True)
        return False
    def scan(self) -> list[ScanResult]:
        futs = {self._executor.submit(self._probe, p): p for p in self.ports}
        res: list[ScanResult] = []
        for fut in as_completed(futs):
            self._scanned += 1
            r = fut.result()
            if r:
                res.append(r)
        return res
    def _probe(self, port: int) -> ScanResult | None:
        try:
            t0 = time.perf_counter()
            with self._sem:
                if not self._tcp_open(port):
                    return None
            dt = time.perf_counter() - t0
            if self._latency is None or dt < self._latency:
                self._latency = dt
            service, title = self._http_info(port)
            return ScanResult(port, service, title)
        except Exception:
            return None
    def _tcp_open(self, port: int) -> bool:
        try:
            for fam, typ, pr, _, addr in socket.getaddrinfo(self.host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP):
                with contextlib.closing(socket.socket(fam, typ, pr)) as s:
                    s.settimeout(self.sock_timeout)
                    if s.connect_ex(addr) == 0:
                        return True
        except OSError:
            pass
        return False
    def _http_info(self, port: int) -> tuple[str, str | None]:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = ""
        sess = requests.Session()
        for scheme in ("http", "https"):
            url = f"{scheme}://{self.host}:{port}/"
            try:
                head = sess.head(url, timeout=self.http_timeout, allow_redirects=True, verify=False)
            except RequestException:
                continue
            if 100 <= head.status_code < 600:
                try:
                    body = sess.get(url, timeout=self.http_timeout, allow_redirects=True, verify=False).text
                    t = self._extract_title(body)
                    if t:
                        return service or scheme, t
                except RequestException:
                    pass
                return service or scheme, ""
        return service, None
    @staticmethod
    def _extract_title(doc: str) -> str | None:
        m = _TITLE_RE.search(doc)
        return html.unescape(m.group(1)).strip() if m else None
def parse_ports(spec: str) -> list[int]:
    out: set[int] = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-", 1))
            out.update(range(a, b + 1))
        else:
            out.add(int(part))
    return sorted(out)
def header_text(host: str, ip: str, filt: int, lat: float) -> Text:
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return Text.assemble(("Starting FastScan 1.0", "bold yellow"), (" ( https://github.com/MarcusovP/FastScan ) at ", "yellow"), (now + "\n", "yellow"), ("Scan report for ", "bold"), (host, "cyan bold"), (" (", ""), (ip, "magenta"), (")\n", ""), ("Host is up ", "green"), (f"({lat:.3f}s latency).\n", ""), ("Not shown: ", "dim"), (f"{filt:,}", "dim"), (" filtered tcp ports (no-response)\n\n", "dim"))
def build_table(results: list[ScanResult]) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("PORT", style="cyan", width=8)
    t.add_column("STATE", style="green")
    t.add_column("SERVICE", style="magenta")
    t.add_column("TITLE")
    for r in sorted(results, key=lambda x: x.port):
        t.add_row(f"{r.port}/tcp", "open", r.service or "?", r.title or "")
    return t
def print_summary(elapsed: float) -> None:
    console.print(Text.assemble(("\nFastScan done: 1 IP address (1 host up) scanned in ", "dim"), (f"{elapsed:.2f}", "bold"), (" seconds\n", "dim")))
def save_json(path: str, results: list[ScanResult]) -> None:
    json.dump([r._asdict() for r in results], open(path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("-r", "--range", default=DEFAULT_RANGE)
    p.add_argument("-w", "--workers", type=int, default=MAX_WORKERS)
    p.add_argument("-j", "--json")
    args = p.parse_args()
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    logging.basicConfig(level=logging.WARNING)
    ports = parse_ports(args.range)
    bar = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(), console=console, transient=True)
    task = bar.add_task(f"[yellow]Scanning {args.host}", total=len(ports))
    t0 = time.perf_counter()
    with bar, PortScanner(args.host, ports, workers=args.workers) as scanner:
        box: list[list[ScanResult]] = []
        thr = threading.Thread(target=lambda: box.append(scanner.scan()))
        thr.start()
        while thr.is_alive():
            time.sleep(0.1)
            bar.update(task, completed=scanner._scanned)
        thr.join()
    elapsed = time.perf_counter() - t0
    results = box[0]
    ip = socket.gethostbyname(args.host)
    console.print(header_text(args.host, ip, len(ports) - len(results), scanner._latency or 0.0))
    console.print(build_table(results))
    print_summary(elapsed)
    if args.json:
        save_json(args.json, results)
        console.print(f"[blue]Saved JSON → {args.json}[/]")
    sys.exit(0)
if __name__ == "__main__":
    main()
