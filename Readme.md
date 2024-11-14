# Project Setup and Usage Guide

This guide covers setting up the project environment, installing necessary dependencies, and accessing available endpoints.

## 1. Setting Up the Virtual Environment

1. **Create a Virtual Environment**

   - Run the following command to create a virtual environment named `venv`:
     ```bash
     python3 -m venv venv
     ```

2. **Activate the Virtual Environment**

   - On **Linux**:
     ```bash
     source venv/bin/activate
     ```
   - On **Windows**:
     ```bash
     venv\Scripts\activate
     ```

3. **Install Required Python Packages**
   - Use the `requirements.txt` file to install all necessary Python dependencies:
     ```bash
     pip install -r requirements.txt
     ```

## 2. System Dependencies for Scans

Ensure the following tools are installed on your system to perform all necessary scans:

1. **Whois** and **dnsenum**: Used for gathering domain information and DNS enumeration.
2. **OWASP ZAP**: A security tool widely used for identifying vulnerabilities in web applications.
3. **Nuclei**: A powerful scanner leveraging templates to detect vulnerabilities.

**Note:** Verify that the `zap.sh` script is located at `/usr/share/zaproxy/zap.sh`. If it is located elsewhere, update the path in the `ddoser.py` script accordingly to avoid errors or conflicts.

## 3. Available API Endpoints

The application provides several endpoints for scanning:

- **Host Discovery**: `http://127.0.0.1:8000/api/scanners/hostcavery/`
- **DDoS Testing**: `http://127.0.0.1:8000/api/scanners/ddoser/`
- **Vulnerability Scanning**: `http://127.0.0.1:8000/api/scanners/nuclei/`

Each endpoint requires a URL parameter for the target website to be scanned.

## 4. Frontend Interface

The frontend for these endpoints uses Django REST Framework’s (DRF) default interface, allowing users to send requests and test the application directly. A custom frontend only provides a landing page and does not include additional functionality.

---

With this setup, you should be ready to execute scans using the available endpoints.
