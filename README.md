# CyberKnight Phishing Detector

**Version:** 1.0.0  
**Language:** Python  
**Platform:** Linux

## Overview

CyberKnight Phishing Detector is a Python-based defensive cybersecurity tool designed to identify suspicious characteristics in email messages.

It uses multiple analysis modules to evaluate email senders, URLs, message content, email headers and potential brand impersonation.

The application combines these indicators into an overall risk assessment and generates both TXT and HTML analysis reports.

## Features

- **Sender Analysis:** Checks email sender addresses for suspicious characteristics.
- **URL Analysis:** Identifies potentially suspicious URL structures and domains.
- **Brand Detection:** Checks for possible brand impersonation.
- **Content Analysis:** Evaluates email text for suspicious language and indicators.
- **Header Analysis:** Examines email headers for inconsistencies.
- **Risk Assessment:** Calculates an overall risk score.
- **TXT Reports:** Generates readable text reports.
- **HTML Reports:** Generates structured HTML reports.
- **Report Retention:** Keeps the 10 most recent reports of each format.
- **Logging:** Uses rotating log files.
- **Input Validation:** Handles invalid and incomplete user input.
- **Automated Testing:** Includes unit tests for core functionality.
- **Demonstration:** Includes a standalone email header analysis demonstration.

## Project Structure

```text
CyberKnightPhishing/
├── analyzers/
│   ├── brand_analyzer.py
│   ├── content_analyzer.py
│   ├── header_analyzer.py
│   ├── sender_analyzer.py
│   └── url_analyzer.py
├── core/
│   ├── detector.py
│   ├── input_handler.py
│   └── logger.py
├── data/
│   └── brand_domains.json
├── demos/
│   └── header_analysis_demo.py
├── reports/
│   ├── generated/
│   ├── html_report_generator.py
│   └── report_generator.py
├── tests/
│   ├── test_analyzers.py
│   ├── test_detector.py
│   ├── test_html_report_retention.py
│   ├── test_input_handler.py
│   ├── test_logger.py
│   └── test_report_retention.py
├── config.py
├── main.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Requirements

- Python 3
- Linux or another compatible operating system
- No third-party Python packages are currently required.

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd CyberKnightPhishing
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

## Usage

### Run the application

```bash
python main.py
```

Follow the interactive prompts to provide the email information for analysis.

Generated reports are saved in:

```text
reports/generated/
```

### Run the header analysis demonstration

```bash
python -m demos.header_analysis_demo
```

This runs a demonstration of the email header analyzer using sample email headers.

## Running Tests

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

The project currently includes **42 automated tests**.

## Security Notice

CyberKnight Phishing Detector uses heuristic analysis. Its results are intended to support security awareness and preliminary email assessment.

A low-risk result does not guarantee that an email is legitimate, and a high-risk result does not independently prove malicious intent.

Always verify suspicious communications through trusted channels.

## Project Status

**Version 1.0.0 — Initial release**

Developed as a defensive cybersecurity learning and portfolio project.

## Author

**Brian Nyamasyo**