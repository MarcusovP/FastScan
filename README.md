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
# Full IPv4 range, 1 000 worker threads (default)
python fastscan.py 127.0.0.1

# Scan first 4k ports with 600 threads, save JSON
python fastscan.py 127.0.0.1 -r 1-4096 -w 600 -j audit.json
```

The output looks like this:

```text
Starting FastScan 1.0 ( https://github.com/MarcusovP/FastScan ) at 2025-07-04 23:42 MSK
Scan report for 127.0.0.1 (127.0.0.1)
Host is up (0.000s latency).
Not shown: 65,514 filtered tcp ports (no-response)

┏━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ PORT     ┃ STATE ┃ SERVICE  ┃ TITLE                                    ┃
┡━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 80/tcp   │ open  │ http     │ Severr                                   │
│ 1883/tcp │ open  │ ?        │                                          │
│ 3306/tcp │ open  │ mysql    │                                          │
│ 4222/tcp │ open  │ ?        │                                          │
│ 5216/tcp │ open  │ http     │                                          │
│ 7880/tcp │ open  │ https    │                                          │
│ 8000/tcp │ open  │ http     │                                          │
│ 8030/tcp │ open  │ http     │ Site A                                   │
│ 8031/tcp │ open  │ http     │ Site B                                   │
│ 8080/tcp │ open  │ http-alt │ Burp Suite Professional                  │
│ 8090/tcp │ open  │ http     │ Site B                                   │
│ 9005/tcp │ open  │ ?        │                                          │
│ 9007/tcp │ open  │ ?        │                                          │
│ 33458/t… │ open  │ ?        │                                          │
│ 34707/t… │ open  │ ?        │                                          │
│ 35432/t… │ open  │ ?        │                                          │
│ 43617/t… │ open  │ ?        │                                          │
│ 44164/t… │ open  │ ?        │                                          │
└──────────┴───────┴──────────┴──────────────────────────────────────────┘

FastScan done: 1 IP address (1 host up) scanned in 3.66 seconds

```
