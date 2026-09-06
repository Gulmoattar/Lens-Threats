# ThreatLens

Defensive IP, Domain, and URL reputation checker built with Streamlit.

ThreatLens evaluates an indicator using **only**:
- VirusTotal
- WHOIS

It then asks Gemini to explain the evidence at the selected knowledge level.

## Project structure

- `app.py`
- `input_helpers.py`
- `requirements.txt`

### One-way dependency

`app.py` imports source helpers from `input_helpers.py`.

`input_helpers.py` never imports from `app.py`.

Source orchestration is handled through a registry in `app.py`:

```python
SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
```

To add a future source:
1. Add one new source function to `input_helpers.py`
2. Add one entry to `SOURCES` in `app.py`

No other orchestration changes are required.

## Environment variables

Set API keys before running:

- `VIRUSTOTAL_API_KEY` (required)
- `GEMINI_API_KEY` (required)
- `GEMINI_MODEL` (optional; defaults to `gemini-1.5-flash`)

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```
