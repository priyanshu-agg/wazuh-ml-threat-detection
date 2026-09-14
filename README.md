# 🛡️ Wazuh ML Threat Detection

Machine learning-based anomaly detection for Wazuh security logs using Python, Scikit-learn, and Streamlit.

## 📌 Overview

This project analyzes security events collected from Wazuh and applies machine learning techniques to identify potentially anomalous activity in Windows security telemetry.

The project combines:

- Wazuh security event data
- Data preprocessing and feature extraction
- Security-focused feature engineering
- Isolation Forest anomaly detection
- Interactive Streamlit visualization

The goal is to build a practical security analytics pipeline that can help identify unusual activity from large volumes of security logs.

---

## 🎯 Project Objective

Security monitoring systems can generate a large number of events, making manual analysis difficult.

This project explores how machine learning can be used alongside Wazuh security monitoring to:

1. Process large-scale security logs
2. Extract useful security-related features
3. Identify potentially anomalous events
4. Visualize detected activity through an interactive dashboard

---

## 🏗️ Current Architecture

```text
Wazuh Security Logs
        │
        ▼
Data Ingestion
        │
        ▼
Log Preprocessing
        │
        ├── Rule Level
        ├── Rule Description
        ├── Agent Name
        └── Agent IP
        │
        ▼
Feature Engineering
        │
        ├── High Severity Events
        └── Login Failures
        │
        ▼
Isolation Forest
        │
        ▼
Anomaly Detection
        │
        ▼
Streamlit Dashboard
