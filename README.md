# Android NFC Security Analyzer

A mobile tool for analyzing NFC tags (especially MIFARE Classic) and identifying common security misconfigurations.
This project aims to provide an educational, research-oriented NFC security auditing tool that works on commodity Android hardware.

## Features (Planned)

- Read NFC tag metadata (UID, ATQA, SAK, type, size)

- MIFARE Classic sector layout visualization

- Weak/default key detection

- Dictionary-based key recovery

- Access bits validation

- Automatic security scoring

- Exportable JSON/PDF report

- API-level timing measurement for research

## Why this project?

Most NFC security tools (e.g., Proxmark3) require specialized hardware.
This project demonstrates how much security analysis can be done using only Android’s official NFC APIs, without root, and without low-level RF access.

# Tech Stack

- Android (Kotlin)

- NFC APIs: NfcAdapter, MifareClassic, Tag, IsoDep

- Graph visualization (Jetpack Compose Charts or MPAndroidChart)

- MVVM architecture
