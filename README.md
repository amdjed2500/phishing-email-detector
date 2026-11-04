# 🎣 AI-Powered Phishing Email Detector

A machine learning system that detects phishing emails using NLP, URL analysis, and email header forensics. Built as a portfolio project combining **AI/ML**, **Cybersecurity**, and **Networking**.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## Features
- 📧 **Email parsing** — extracts subject, body, sender, headers, URLs
- 🔍 **Feature engineering** — URL entropy, suspicious TLDs, urgency keywords, sender domain mismatch, SPF/DKIM/DMARC checks
- 🤖 **ML classifier** — Random Forest + TF-IDF on email body (scikit-learn)
- 📊 **Evaluation** — precision/recall/F1, confusion matrix, ROC curve
- 🌐 **CLI** — `python src/predict.py --email sample.eml`

## Quick Start
```bash
pip install -r requirements.txt
python src/train.py          # trains model on data/sample_emails.csv
python src/predict.py --text "Your account has been suspended. Click here to verify."
```

## Project Structure
```
phishing-email-detector/
├── data/              # sample dataset
├── src/               # source code
├── notebooks/         # EDA notebooks
├── tests/             # unit tests
├── models/            # trained model artifacts
└── .github/workflows/ # CI
```

## Dataset
Synthetic dataset of ~200 emails (phishing + legitimate) for demonstration. Replace with real data (Enron, PhishTank) for production.

## Roadmap
- [ ] Deep learning model (LSTM/BERT)
- [ ] Real-time API (FastAPI)
- [ ] Browser extension
- [ ] Threat intel feed integration

## License
MIT
