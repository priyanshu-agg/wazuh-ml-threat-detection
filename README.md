# 🛡️ Wazuh ML Threat Detection

**Machine Learning-Based Anomaly Detection for Wazuh Security Logs**

An end-to-end cybersecurity analytics project that uses **Isolation Forest** to identify potentially anomalous patterns in Wazuh security logs, with an interactive Streamlit dashboard for exploring results.

## 📌 Overview

Security monitoring systems generate large volumes of events that can be difficult to analyze manually. This project combines log preprocessing, feature engineering, and unsupervised machine learning to help identify unusual activity in Wazuh security telemetry.

The dashboard accepts raw Wazuh JSON logs, processes them in chunks, and presents detection statistics, visualizations, and potentially anomalous records.

## ✨ Key Features

- **Raw Log Processing:** Upload raw Wazuh JSON logs directly.
- **Feature Engineering:** Extract five features for machine learning.
- **Anomaly Detection:** Apply a trained Isolation Forest model.
- **Interactive Dashboard:** Explore results using Streamlit and Plotly.
- **Large-File Support:** Process JSON Lines input in chunks.
- **Synthetic Sample Data:** Test the dashboard without real security logs.

## 🏗️ System Architecture

```text
       Raw Wazuh JSON Logs
                |
                v
        Data Preprocessing
                |
                v
        Feature Engineering
                |
       ┌────────┴─────────┐
       |                  |
  Rule Severity      Event Patterns
       |                  |
       └────────┬─────────┘
                |
                v
     Trained Isolation Forest
                |
                v
       Anomaly Classification
                |
                v
       Streamlit Dashboard
                |
                v
    Statistics, Charts & Records
```

## 🧠 Machine Learning

The project uses **Isolation Forest**, an unsupervised algorithm that identifies observations with unusual feature patterns.

The model uses five features:

| Feature | Description |
|---|---|
| `Rule_Level` | Severity level assigned to a Wazuh rule |
| `Is_High_Severity` | Indicates whether rule severity is 10 or higher |
| `Is_Login_Failure` | Indicates a login-failure event based on the rule description |
| `Rule_Frequency` | Frequency of each rule description in the dataset |
| `Agent_Event_Count` | Number of events associated with each agent in the dataset |

The trained model is saved as `isolation_forest_model.pkl` using Joblib and reused by the dashboard.

## 📊 Dashboard

The dashboard presents:

- Total logs processed
- Number of model-identified anomalies
- Anomaly percentage
- Threat-distribution scatter plot
- Table of potentially anomalous records

These results help users explore unusual patterns that may warrant further investigation.

## 🛠️ Tech Stack

`Python` · `Pandas` · `Scikit-learn` · `Isolation Forest` · `Joblib` · `Streamlit` · `Plotly` · `Jupyter Notebook`

## 🚀 Run Locally

**1. Install the dependencies**

```bash
pip install -r requirements.txt
```

**2. Start the dashboard**

```bash
streamlit run dashboard.py
```

**3. Upload a dataset**

Open the local URL provided by Streamlit and upload a raw Wazuh JSON file in JSON Lines format.

You can use `sample_wazuh_alerts_10000.json` to test the dashboard with synthetic demonstration events.

## 📂 Project Structure

```text
wazuh-ml-threat-detection/
├── dashboard.py
├── log_analysis.ipynb
├── isolation_forest_model.pkl
├── requirements.txt
├── sample_wazuh_alerts_10000.json
└── README.md
```

## 🧪 Sample Dataset

The included `sample_wazuh_alerts_10000.json` contains synthetic Wazuh-style events for demonstration and testing. It does not contain actual security telemetry from the internship environment.

## ⚠️ Limitations

Anomalies identified by the model require further investigation and are not necessarily confirmed attacks.

Detection results depend on the input data and the features extracted.
