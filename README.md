# FOFF Milter v0.10.54

A spam and phishing filter for Sendmail and Postfix, written in Rust. It runs as a
[milter](https://en.wikipedia.org/wiki/Milter), scores each message, and accepts it,
tags it as spam, or rejects it.

## How it works

For each message, foff-milter:

1. **Parses and normalizes** the message: MIME structure (via `mail-parser`), transfer
   encodings, charsets, HTML entities, homoglyphs, zero-width characters and Unicode
   lookalikes, so rules see the text a reader would see.
2. **Checks the sender**: DKIM results and alignment, SPF/DMARC as recorded by your MTA,
   envelope vs. `From` vs. `Return-Path`, SRS-rewritten forwarding, email service
   providers (ESPs), and the sender domain's registration age (WHOIS, cached).
3. **Runs feature extractors**: sender alignment, brand impersonation, link analysis,
   context and content analysis (health, financial, invoice and credential scams), TLD
   risk, domain reputation, attachments (including PDF, ZIP and RAR contents, and
   optionally OCR of images) and more.
4. **Evaluates the built-in rules** (compiled into the binary) and combines everything
   into one score.

The score decides the action:

| Score | Action |
|---|---|
| ≥ `reject_threshold` (default 350) | Reject, or tag as spam when `reject_to_tag = true` (the default) |
| ≥ `spam_threshold` (default 50) | Tag as spam (`X-Spam-Flag: YES`) |
| below | Accept |

Every message gets headers explaining the decision:

```
X-FOFF-Score: 233 - foff-milter v0.10.54 (mx.example.com)
X-FOFF-Rule-Matched: Phishing Threats: ... (mx.example.com) [builtin]
X-FOFF-Feature-Evidence: Link Analysis: ... (mx.example.com) [hash]
X-FOFF-Trust-Analysis: auth=30, infra=10, behavior=15, content=5, total=20, adj=0
```

**Multiple servers.** When one foff-milter instance relays to another, the downstream one
trusts an upstream *spam* verdict instead of re-analyzing (`X-FOFF-Score: ... - trusted
from upstream ...`). It never trusts an upstream "not spam", so forged headers can't be
used to get mail accepted.

## Requirements

- Rust 1.95 or later (the version CI tests)
- Linux or FreeBSD, with Sendmail or Postfix
- For the optional `ocr` feature: Tesseract development files
  (`libtesseract-dev tesseract-ocr tesseract-ocr-eng` on Debian/Ubuntu)

RAR attachment support comes from the `rar` git submodule and is enabled by default.

## Building

```bash
git clone --recursive https://github.com/mwstowe/foff-milter.git
cd foff-milter
cargo build --release                  # or: cargo build --release --features ocr
```

If you cloned without `--recursive`, run `git submodule update --init --recursive`.

## Installation (Linux, systemd)

```bash
sudo cp target/release/foff-milter /usr/local/bin/
sudo mkdir -p /etc/foff-milter/features /var/lib/foff-milter
sudo cp features/*.toml /etc/foff-milter/features/
sudo cp foff-milter.toml /etc/foff-milter.toml    # then edit; see Configuration
sudo cp foff-milter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now foff-milter
```

On FreeBSD, use `/usr/local/etc/foff-milter.toml`, `/usr/local/etc/foff-milter/features/`
and the rc script `foff-milter.rc` (service name `foff_milter`).

### Sendmail

In `sendmail.mc`:

```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, T=S:30s;R:30s')
```

Without an `F=` flag, Sendmail accepts mail when the milter is unavailable; `F=T`
tempfails it instead.

### Postfix

In `main.cf`:

```
smtpd_milters = unix:/var/run/foff-milter.sock
non_smtpd_milters = unix:/var/run/foff-milter.sock
milter_default_action = accept
```

## Configuration

Configuration is a TOML file. **Always pass it with `-c`**: without `-c`, foff-milter
looks for `/etc/foff-milter.yaml` (a leftover default; YAML is no longer supported) and,
when that doesn't exist, silently runs with built-in defaults. The shipped systemd unit
and rc script pass `-c` for you.

Every section is optional. **If you include a section, include all of its fields**:
a partial section is a parse error. The values below are the defaults.

```toml
[system]
socket_path = "/var/run/foff-milter.sock"
reject_to_tag = true                 # tag instead of rejecting

[heuristics]
reject_threshold = 350
spam_threshold = 50
accept_threshold = 0

[features]
enabled = true
config_dir = "/etc/foff-milter/features"   # default: foff-milter/features next to the config file

[statistics]
enabled = true
database_path = "/var/lib/foff-milter/stats.db"
flush_interval_seconds = 60

[whitelist]                          # accepted without analysis
enabled = true
addresses = []
domains = []
domain_patterns = []                 # regexes, e.g. ".*\\.gov$"

[blocklist]                          # tagged as spam without analysis
enabled = true
addresses = []
domains = []
domain_patterns = []

[sender_blocking]
enabled = true
block_patterns = []                  # regexes matched against envelope sender and From
action = "reject"                    # or "tag"

[default_action]
type = "Accept"                      # "Accept", "TagAsSpam" or "Reject"
```

`[rulesets]` is still accepted for compatibility, but the detection rules are compiled
into the binary and no longer read from disk.

### Reloading

`systemctl reload foff-milter` (or `kill -HUP`, or `service foff_milter reload` on FreeBSD)
waits for messages in progress, then re-reads the TOML file and the feature
configuration. Cached domain ages are kept. Rule changes need a new binary.

## Command line

```bash
foff-milter -c /etc/foff-milter.toml                  # run the milter
foff-milter -c /etc/foff-milter.toml -d               # run as a daemon
foff-milter -c /etc/foff-milter.toml -v               # verbose logging

foff-milter --test-config -c /etc/foff-milter.toml    # check the configuration
foff-milter --test-email msg.eml -c /etc/foff-milter.toml   # score a saved message
foff-milter --analyze msg.eml -c /etc/foff-milter.toml      # detailed forensic report
foff-milter --anonymize msg.eml > anon.eml            # strip personal data for a test case

foff-milter --stats -c /etc/foff-milter.toml          # statistics
foff-milter --stats-unmatched -c /etc/foff-milter.toml
foff-milter --stats-reset -c /etc/foff-milter.toml
```

`--test-email` gives the same result as the milter for the same message. Options for
re-testing mail that already passed through foff-milter:

- X-FOFF headers are stripped first; `--keep-xfoff-headers` keeps them.
- `--force-reanalysis` ignores an upstream spam verdict.
- `--disable-same-server` turns off the "sent from this server" shortcut.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --features ocr -- -D warnings
cargo test --features ocr
cargo build --release && ./tests/run_tests.sh
```

`tests/run_tests.sh` scores every message in `tests/positive/` (must be tagged or
rejected) and `tests/negative/` (must be accepted). To add a case, anonymize the message
with `--anonymize`, check that the anonymized copy still gets the expected result, and
put it in the matching directory.

[THEORY_OF_OPERATION.md](THEORY_OF_OPERATION.md) describes the processing pipeline in
more detail.

## License

MIT; see [LICENSE](LICENSE).
