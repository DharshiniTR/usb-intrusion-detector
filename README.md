# USB Intrusion Detection System

A Python-based security project designed to detect and help prevent unauthorized USB device activity. The system includes USB monitoring, device verification, and security controls for Windows and Linux environments.

## Features

* **USB Monitoring:** Monitors USB device activity.
* **Device Verification:** Supports USB device verification.
* **Access Control:** Includes mechanisms for allowing or blocking devices.
* **Cross-Platform Support:** Provides separate implementations for Windows and Linux.
* **Machine Learning:** Includes an ML module for security-related analysis.
* **Security Controls:** Includes modules for keyboard and registry-related controls.

## Technologies Used

* Python
* Machine Learning
* Linux
* Windows
* Git and GitHub

## Project Structure

```text
├── allow_block.py
├── allow_block_linux.py
├── captcha.py
├── db.py
├── db_linux.py
├── index.html
├── ml.py
├── ml_linux.py
├── os_detect.py
├── registry_block.py
├── requirements.txt
├── server.py
├── server_linux.py
├── usb_monitor.py
├── usb_monitor_linux.py
├── usb_verification_handler.py
└── usb_verification_handler_linux.py
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/DharshiniTR/usb-intrusion-detector.git
cd usb-intrusion-detector
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

On Linux:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

The application contains separate modules for Windows and Linux. Review the p
