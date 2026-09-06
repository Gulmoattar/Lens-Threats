# ThreatLens

ThreatLens is a defensive cybersecurity Streamlit app that checks whether an **IP**, **domain**, or **URL** appears **safe**, **suspicious**, or **malicious** using only:

- VirusTotal
- WHOIS

It then uses Gemini to produce an evidence-based explanation from those two sources.

## Project structure

- `/home/runner/work/Lens-Threats/Lens-Threats/app.py` — UI + orchestration
- `/home/runner/work/Lens-Threats/Lens-Threats/input_helpers.py` — source API helper functions
- `/home/runner/work/Lens-Threats/Lens-Threats/requirements.txt` — Python dependencies

## One-way dependency

The dependency direction is strictly:

`app.py → input_helpers.py`

- `app.py` imports helper functions from `input_helpers.py`
- `input_helpers.py` does **not** import `app.py`

`app.py` uses a source registry:

- `SOURCES = {"VirusTotal": get_virustotal, "WHOIS": get_whois}`

The app iterates this registry to run sources, so source handling is not hard-coded.

## API keys

Set environment variables before running:

- `VIRUSTOTAL_API_KEY` (required)
- `GEMINI_API_KEY` (optional for AI insight, required for Gemini output)
- `GEMINI_MODEL` (optional, defaults in code)

Example:

```bash
export VIRUSTOTAL_API_KEY="your_vt_key"
export GEMINI_API_KEY="your_gemini_key"
export GEMINI_MODEL="gemini-1.5-flash"
```

## Install and run

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Adding a future source

To add another source later:

1. Add **one** new source function in `input_helpers.py`
2. Add **one** entry in the `SOURCES` registry in `app.py`

No other app orchestration changes should be required.
