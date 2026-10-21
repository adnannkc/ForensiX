# ForensiX

ForensiX is a Python tool that helps a digital forensic investigator work through Linux evidence in order. It checks files, reads logs, builds a timeline, links related events, and writes reports.

It uses only the Python standard library, so there is nothing extra to install.

**Important:** ForensiX shows what the evidence says. It does not decide that a system was hacked or that someone did something wrong. Those conclusions belong to the investigator.

## What It Does

Think of it as a careful assistant that never touches the original evidence:

1. It checks a single file and fingerprints it, so you can prove later that it did not change.
2. It looks through a Linux system for logs, logins, user accounts, and startup tasks.
3. It puts everything into one timeline, sorted by time.
4. It checks related events against simple rules and tells you what matched.
5. It reads network capture files and memory dumps, and adds them to the same picture.
6. It writes reports you can open in a browser or a spreadsheet.

The newest command, `forensix run`, does all of this in one step from a single case file.

## Safety Rules

- **Read only.** Evidence files are opened for reading only. Nothing is changed, renamed, or deleted.
- **Never run.** Evidence files are never executed.
- **Separate output.** Reports cannot be saved inside the evidence folder.
- **Offline.** ForensiX does not send anything to the internet. The only network feature is the local dashboard, which runs on your own computer only.
- **One exception.** Memory analysis can call Volatility 3, an outside tool, to read a raw memory image. It runs only when you ask for it, and it never uses a shell.

## Installation

You need Python 3.9 or newer and a Linux system (or another Unix-like system).

```bash
git clone https://github.com/adnannkc/ForensiX.git
cd ForensiX
python3 -m pip install .
forensix --version
```

The last command should print `ForensiX 9.0.0`.

## Quick Start

ForensiX includes a small made-up case so you can try it safely:

```bash
forensix run --config examples/case-synthetic/case.json -o reports/ --overwrite
ls reports/
```

The `reports/` folder will contain:

- a JSON report and an HTML report you can open in a browser
- a custody ledger, which records what happened to the evidence
- `pipeline_manifest.json`, a machine-readable record of each step

Sample outputs from this case are in `docs/examples/case-synthetic/`.

## Commands

| Command | What it does | Version |
|---|---|---|
| `forensix run` | Runs the whole investigation from one case file | V9 |
| `forensix triage` | Checks a Linux evidence folder | V2 |
| `forensix timeline` | Builds a time-ordered timeline you can filter | V3 |
| `forensix investigate` | Links related events and checks simple rules | V4 |
| `forensix pcap` | Reads a network capture file | V5 |
| `forensix memory` | Reads memory dump information | V6 |
| `forensix dashboard` | Opens a local web page to browse reports | V7 |
| `forensix advanced` | Writes a full report with integrity checks | V8 |
| `forensix manifest` | Creates or checks file fingerprints | V8 |
| `forensix custody` | Keeps a record of who handled the evidence | V8 |

For help with any command, run `forensix <command> --help`.

## Exit Codes

`forensix run` finishes with one of these codes:

| Code | Meaning |
|---|---|
| 0 | Success. Every step passed. |
| 1 | Configuration error, such as a wrong path or an output folder inside the evidence. |
| 2 | A check failed, or only part of the investigation finished. |
| 3 | The custody record failed its check. |
| 4 | A file or folder problem, such as a permission error or a file that already exists. |

## Versions

ForensiX was built one version at a time. Each version added one job.

- **V1: Single file check.** Fingerprints one file and writes a report. (v1.0.0)
- **V2: Linux clue finder.** Looks through a Linux system for logs, logins, user accounts, and startup tasks. (v2.0.0, v2.0.1)
- **V3: Timeline.** Puts events in time order, so you can read what happened like a story. (v3.0.0)
- **V4: Linking and rules.** Connects related events and checks them against simple rules. A match means "look at this," not "this is bad." (v4.0.0)
- **V5: Network check.** Reads classic network capture files and matches the traffic with logins. (v5.0.0)
- **V6: Memory check.** Reads information from a memory dump. This version has no separate release tag. (no tag)
- **V7: Web viewer.** A local web page for opening and browsing reports on your own computer. (v7.0.0)
- **V8: Records and report.** Checks that evidence files have not changed, keeps a record of who handled them, and writes a full report. (v8.0.0)
- **V9: One command.** Runs all the steps above from one case file and saves everything in one place. (v9.0.0)

## Project Layout

- `src/forensix/`: the code
- `tests/`: the automated tests
- `examples/case-synthetic/`: a made-up case with fake logs, a fake capture file, and a fake memory file
- `docs/`: design notes for each version
- `docs/examples/case-synthetic/`: sample outputs from the made-up case

## Testing

```bash
PYTHONPATH=src python3 -m pytest -q
```

The expected result is `1768 passed, 284 subtests passed`.

## What ForensiX Does Not Do

- It does not detect malware or label files as malicious.
- It does not give risk scores or severity ratings.
- It does not check threat intelligence feeds or reputation lists.
- It does not declare a system "compromised."
- It does not rebuild attack chains or map them to frameworks.
- It does not send evidence or reports to any cloud service.

## Limits

- Host analysis works on Linux only. It does not read Windows or macOS artifacts.
- Network analysis reads classic PCAP files only. PCAP-NG files are rejected.
- Raw memory images need Volatility 3 installed separately. ForensiX can also read memory information that has already been extracted to JSON.
- Old syslog lines do not include a year. Give the year with `--log-year`, or ForensiX will refuse to guess it.

## Development Roadmap

ForensiX was built one step at a time. Each version added one job, and V9 puts all the jobs together.

The roadmap above lists every version and its release tag.
