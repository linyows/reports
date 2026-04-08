<br><br><br><br><br><br>

<p align="center">
  <strong>Reports</strong>
  <br><br>
  DMARC and MTA-STS report viewer
</p>

<br><br><br><br>

<p align="center">
  <a href="https://github.com/linyows/reports/actions/workflows/test.yml">
    <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/linyows/reports/test.yml?branch=main&style=for-the-badge&labelColor=666666">
  </a>
  <a href="https://github.com/linyows/reports/releases">
    <img src="http://img.shields.io/github/release/linyows/reports.svg?style=for-the-badge&labelColor=666666&color=DDDDDD" alt="GitHub Release">
  </a>
</p>

## Architecture

```mermaid
graph TD
    subgraph IMAP Servers
        S1[IMAP Server<br>Gmail, etc.]
        S2[IMAP Server<br>Work, etc.]
    end

    subgraph reports
        IMAP[IMAP Client<br><i>libcurl</i>]
        MIME[MIME Parser<br><i>base64 decode</i>]
        DECOMP[Decompress<br><i>gzip/zip via zlib</i>]
        DMARC[DMARC Parser<br><i>libxml2</i>]
        MTASTS[MTA-STS Parser<br><i>std.json</i>]
        STORE[(Store<br>JSON files per account)]
        CLI[CLI / C ABI<br>fetch, list, show, summary]
    end

    S1 -- IMAPS --> IMAP
    S2 -- IMAPS --> IMAP
    IMAP --> MIME --> DECOMP
    DECOMP --> DMARC
    DECOMP --> MTASTS
    DMARC --> STORE
    MTASTS --> STORE
    STORE --> CLI

    CLI --> Terminal[Terminal<br>table output]
    CLI --> JSON[JSON stdout<br>--format json]
    CLI --> Swift[SwiftUI macOS<br>via libreports-core.a]
```

## Features

- Fetch DMARC aggregate reports (RFC 7489) and TLS-RPT reports (RFC 8460) from IMAP
- Multiple IMAP account support with per-account storage
- Parse XML/JSON report formats with ZIP/GZIP decompression
- List, show, and summarize reports with table or JSON output
- Filter by account and domain
- Headless core with C ABI static library for native UI integration

## Installation

### Build from source

Requires Zig 0.15.2 or later.

```bash
$ git clone https://github.com/linyows/reports.git
$ cd reports
$ zig build --release=fast
```

The binary will be available at `./zig-out/bin/reports`.

### Dependencies

- **libxml2** - DMARC XML parsing
- **libcurl** - IMAP connectivity
- **zlib** - gzip/zip decompression

On macOS, these are included in the SDK. On Linux:

```bash
$ sudo apt-get install libxml2-dev libcurl4-openssl-dev zlib1g-dev
```

## Usage

### Configure

Create `~/.config/reports/config.json`:

```json
{
  "accounts": [
    {
      "name": "personal",
      "host": "imap.gmail.com",
      "port": 993,
      "username": "you@gmail.com",
      "password": "your-app-password",
      "mailbox": "INBOX",
      "tls": true
    }
  ]
}
```

For Gmail, generate an [App Password](https://myaccount.google.com/apppasswords). Set `mailbox` to the label name if reports are filtered (e.g., `"dmarc"`).

Legacy single-account format (`"imap": {...}`) is also supported and treated as a `"default"` account.

### Fetch reports

```bash
$ reports fetch
$ reports fetch --account personal
```

### List reports

```bash
$ reports list
ACCOUNT    TYPE     ORGANIZATION         REPORT ID                      DATE              DOMAIN
---------- -------- -------------------- ------------------------------ ----------------- --------------------
personal   DMARC    google.com           12864733003343132926           2026-04-02 00:00  example.com
personal   DMARC    google.com           3504435274969495050            2026-04-01 00:00  example.com
...

$ reports list --account personal --domain example.com
$ reports list --format json
```

### Show report details

```bash
$ reports show 12864733003343132926
Organization: google.com
Report ID:    12864733003343132926
Domain:       example.com
Policy:       none

SOURCE IP        COUNT  DISPOSITION  ENVELOPE FROM             HEADER FROM               DKIM   SPF
---------------- ------ ------------ ------------------------- ------------------------- ------ ------
198.51.100.1    4      none                                   example.com              fail   pass

$ reports show 12864733003343132926 --format json
```

### Summary statistics

```bash
$ reports summary --format table
DMARC Reports:    186
TLS-RPT Reports:  0
Total Messages:   547
DKIM/SPF Pass:    182
DKIM/SPF Fail:    365

$ reports summary --account personal --domain example.com --format json
```

## C ABI / SwiftUI Integration

The build produces a static library and C header for native app integration:

```bash
$ zig build
$ ls zig-out/lib/libreports-core.a
$ ls zig-out/include/reports.h
```

```c
#include "reports.h"

reports_init();
char *json = reports_list(config_json);
// use json...
reports_free_string(json);
reports_deinit();
```

## Development

```bash
# Build
zig build

# Run tests
zig build test

# Format check
zig fmt --check src/

# Run
zig build run -- help
```

## Author

[linyows](https://github.com/linyows)
