---
title: Mobile Permission Risk Analyzer
emoji: 🔐
colorFrom: indigo
colorTo: blue
sdk: gradio
app_file: app.py
pinned: false
---

# Mobile Application Permission Risk Analyzer

An educational Topic 11 model for evaluating fictional mobile apps' requested permissions against their stated purpose. It reports excessive requests and a least-privilege recommendation, then demonstrates a cryptographically protected report transfer.

## Cryptography used

- AES-256-GCM encrypts the report and detects ciphertext changes.
- RSA-OAEP wraps the random AES session key for the analyzer.
- RSA-PSS with SHA-256 signs the report so the analyzer can verify its sender.
- The Cryptography tab demonstrates rejection of modified ciphertext, an incorrect private key, and a modified signature.

The app generates temporary demonstration keys at startup. This is a classroom simulation, not a production key-management design. It analyzes fictional or user-entered permission profiles; it does not inspect apps installed on a phone or prove that an app is malicious. Its score is an explainable heuristic, not an official rating.

## Run locally

Install Python 3.10 or later, then run:

```bash
pip install -r requirements.txt gradio
python app.py
```

## Hugging Face Spaces

Create a new Space with the **Gradio** SDK and add `app.py`, `requirements.txt`, and this README to its repository. Spaces installs extra Python packages listed in `requirements.txt` and rebuilds when files are updated.
