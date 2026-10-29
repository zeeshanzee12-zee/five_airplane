# AI-Powered Cyber Forensic Triage Tool

Read-only triage of evidence folders: extracts forensic features from every file,
scores them with a hybrid engine (explainable rules + ML anomaly detection), and
produces a prioritised list of what an investigator should examine first.

## Features
- SHA-256/MD5 hashing, entropy, magic-byte file typing, timestamps
- Detection of disguised executables, double extensions, packed/encrypted binaries
- IOC patterns: encoded PowerShell, credential tools, persistence, reverse shells,
  anti-forensics, ransom notes, brute-force login logs
- Known-bad hash matching
- IsolationForest anomaly score (falls back to robust z-score without scikit-learn)
- Outputs: terminal ranking, `report.json`, `report.html`, timeline
- Optional LLM analyst summary (`--ai-summary`)

## Install
```bash
git clone https://github.com/<Zzeeshanzee12-zee>/forensic-triage-tool.git
cd forensic-triage-tool
pip install -r requirements.txt   # optional extras only
```

## Usage
```bash
python triage.py /path/to/evidence --out report --top 25
python triage.py /path/to/evidence --known-bad hashes.txt
export ANTHROPIC_API_KEY=...      # then:
python triage.py /path/to/evidence --ai-summary
```
See `examples/sample_report.html` for sample output.

## How scoring works
`priority = min(100, rule_score + 25 * anomaly)`. Levels: CRITICAL >= 70,
HIGH >= 45, MEDIUM >= 25, LOW otherwise. Every score lists its reasons.

## Disclaimer
Automated triage aids prioritisation only. Findings must be validated by a
qualified examiner. Use only on systems and data you are authorised to examine.

## Roadmap
Windows `.evtx` parsing, browser history, YARA rules, disk-image support,
Streamlit dashboard, trained ML model.

## License
MIT
