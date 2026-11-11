# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Fixed: authentication and log timeline events use evidence-relative source_path (no analyst home directory in output).
- Changed: timeline --source-path expects evidence-relative paths; absolute-path filters return no results.
- Changed: SAME_PATH correlation can now link authentication and filesystem events that share a relative path. Sample count unchanged (152); may differ on other evidence.

## 9.1.0 — 2026-11-09

- Timeline now keeps one event per source log line. Sample detections change from 7 to 5: the sudo rule previously counted the same login and command three times.
- `3c9b26d` feat: add SHA-512 to the hashing module
- `b0d7a97` docs: document forensix case and --show-findings in README
- `a9ce242` feat: add --show-findings terminal output for run and case
- `e05e317` feat: dashboard reads Schema 8.0 reports and adds forensix case command
- `b3e97a6` docs: rewrite README for V1 to V9 in plain language
- `e755823` docs: replace outdated development roadmap

## v9.0.0 (2026-10-21)

- `74ed0e3` docs: regenerate V9 sample outputs under version 9.0.0

## v8.0.0 (2026-10-21)

- `9f35484` Release ForensiX v8.0.0

## v7.0.0 (2026-10-19)

- `c7f59fa` feat: add V7 forensic dashboard

## v5.0.0 (2026-10-12)

- `f8896f8` release: ForensiX v5.0.0
- Note: V6 has no separate tag and is commit `5e327da` (feat: add memory forensics pipeline V6.1-V6.8).

## v4.0.0 (2026-10-04)

- `0f98da9` release: ForensiX v4.0.0

## v3.0.0 (2026-10-02)

- `78aa76d` Release ForensiX V3 Timeline Reconstruction

## v2.0.1 (2026-10-01)

- `d31f930` Release ForensiX v2.0.1

## v2.0.0 (2026-09-30)

- `c346f12` Release ForensiX V2.0.0

## v1.0.0 (2026-09-30)

- `89d5750` Clean up generated package metadata
