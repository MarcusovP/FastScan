# FastScan

> A lightning‑fast, nmap‑style TCP/HTTP scanner.

FastScan combines the familiar report format of **nmap** with modern Python concurrency and eye‑pleasing terminal graphics. It performs a full TCP Connect scan, identifies live web services, extracts `<title>` tags, and prints everything in a neat, colour‑coded table.

---

## Installation

### 1 — Clone from GitHub

```bash
$ git clone https://github.com/MarcusovP/FastScan.git
$ cd fastscan
```

### 2 — Install requirements

Create a virtual environment (optional but recommended) and install dependencies:

```bash
$ python -m venv .venv
$ source .venv/bin/activate  # Windows: .venv\Scripts\activate
$ python -m pip install -r requirements.txt
```

<details>
<summary>Minimal install (without dev/test extras)</summary>

```bash
python -m pip install rich requests
```

</details>

FastScan is now ready to run:

```bash
$ python fastscan.py example.com
```

---

## Quick Start

```bash
# Full IPv4 range, 1 000 worker threads (base 500)
python fastscan.py 127.0.0.1 --web --threads 1000

# Scan first 4k ports with 600 threads, save JSON
python3 fastscan.py 127.0.0.1 --web -o results.json --threads 1000 --start 1 --end 4000
```

The output looks like this:

```text
python3 scanner.py example.com --web -o results.json --threads 1000
⟹ Сканирую example.com (257.257.0.1) : 1-65535  (65535 портов, конкурентность 1000)
    Open Ports on bugbounty.securitm.ru    
┏━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ Status ┃ Title                   ┃
┡━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 443  │ 200    │ Вход                    │
│ 80   │ 200    │ Вход                    │
└──────┴────────┴─────────────────────────┘
╭────────────────────────────────────────────────────── Progress ──────────────────────────────────────────────────────╮
│                                                                                                                      │
│ Scanning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 65535/65535 0:01:06 │
│                                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✔ Готово за 66.4 с. Найдено портов: 2

```
