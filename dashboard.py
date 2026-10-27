import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
from collections import Counter
import tempfile
import os

st.set_page_config(
    page_title="ML Threat Detection Dashboard",
    layout="wide"
)

st.title("🛡️ ML-Based Threat Detection Dashboard")
st.write(
    "Analyze raw Wazuh security logs using a trained Isolation Forest model."
)

# Load trained model
try:
    model = joblib.load("isolation_forest_model.pkl")
    st.success("Trained ML model loaded successfully.")
except FileNotFoundError:
    st.error(
        "Model file not found. Make sure "
        "'isolation_forest_model.pkl' is in the same folder."
    )
    st.stop()

# Upload raw Wazuh JSON
uploaded_file = st.file_uploader(
    "Upload Raw Wazuh JSON",
    type=["json"]
)

if uploaded_file is not None:

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".json"
    ) as temp_file:

        while True:
            data = uploaded_file.read(1024 * 1024)

            if not data:
                break

            temp_file.write(data)

        temp_path = temp_file.name

    st.success("Raw Wazuh JSON uploaded successfully.")

    required_columns = ["rule", "agent", "manager", "id"]
    features = [
        "Rule_Level",
        "Is_High_Severity",
        "Is_Login_Failure",
        "Rule_Frequency",
        "Agent_Event_Count"
    ]

    chunk_size = 10000

    def extract_rule_level(rule):
        if isinstance(rule, dict):
            return rule.get("level", 0)
        return 0

    def extract_rule_description(rule):
        if isinstance(rule, dict):
            return rule.get("description", "Unknown")
        return "Unknown"

    def extract_agent_name(agent):
        if isinstance(agent, dict):
            return agent.get("name", "Unknown")
        return "Unknown"

    # Pass 1: calculate frequencies
    st.info("Processing dataset...")

    rule_counter = Counter()
    agent_counter = Counter()
    total_logs = 0

    for chunk in pd.read_json(
        temp_path,
        lines=True,
        chunksize=chunk_size
    ):

        missing = [
            column
            for column in required_columns
            if column not in chunk.columns
        ]

        if missing:
            os.remove(temp_path)
            st.error(f"Missing required columns: {missing}")
            st.stop()

        chunk = chunk[required_columns].copy()

        chunk["Rule_Level"] = chunk["rule"].apply(
            extract_rule_level
        )

        chunk["Rule_Description"] = chunk["rule"].apply(
            extract_rule_description
        )

        chunk["Agent_Name"] = chunk["agent"].apply(
            extract_agent_name
        )

        chunk["Rule_Level"] = pd.to_numeric(
            chunk["Rule_Level"],
            errors="coerce"
        )

        chunk = chunk.dropna(
            subset=["Rule_Level"]
        )

        chunk["Rule_Level"] = chunk["Rule_Level"].astype(int)

        chunk["Rule_Description"] = (
            chunk["Rule_Description"].fillna("Unknown")
        )

        chunk["Agent_Name"] = (
            chunk["Agent_Name"].fillna("Unknown")
        )

        rule_counter.update(
            chunk["Rule_Description"].tolist()
        )

        agent_counter.update(
            chunk["Agent_Name"].tolist()
        )

        total_logs += len(chunk)

    # Pass 2: feature engineering + prediction
    anomaly_chunks = []
    plot_chunks = []
    total_anomalies = 0

    for chunk in pd.read_json(
        temp_path,
        lines=True,
        chunksize=chunk_size
    ):

        chunk = chunk[required_columns].copy()

        chunk["Rule_Level"] = chunk["rule"].apply(
            extract_rule_level
        )

        chunk["Rule_Description"] = chunk["rule"].apply(
            extract_rule_description
        )

        chunk["Agent_Name"] = chunk["agent"].apply(
            extract_agent_name
        )

        chunk["Rule_Level"] = pd.to_numeric(
            chunk["Rule_Level"],
            errors="coerce"
        )

        chunk = chunk.dropna(
            subset=["Rule_Level"]
        )

        chunk["Rule_Level"] = chunk["Rule_Level"].astype(int)

        chunk["Rule_Description"] = (
            chunk["Rule_Description"].fillna("Unknown")
        )

        chunk["Agent_Name"] = (
            chunk["Agent_Name"].fillna("Unknown")
        )

        chunk["Is_High_Severity"] = (
            chunk["Rule_Level"] >= 10
        ).astype(int)

        chunk["Is_Login_Failure"] = (
            chunk["Rule_Description"]
            .str.contains(
                "Logon Failure",
                case=False,
                na=False
            )
        ).astype(int)

        chunk["Rule_Frequency"] = (
            chunk["Rule_Description"].map(rule_counter)
        )

        chunk["Agent_Event_Count"] = (
            chunk["Agent_Name"].map(agent_counter)
        )

        X = chunk[features].fillna(0)

        chunk["Anomaly_Label"] = model.predict(X)
        chunk["Anomaly_Score"] = model.decision_function(X)

        anomalies = chunk[
            chunk["Anomaly_Label"] == -1
        ]

        if not anomalies.empty:
            anomaly_chunks.append(anomalies)

        total_anomalies += len(anomalies)

        # Keep a small sample for the graph
        if len(chunk) > 0:
            plot_chunks.append(
                chunk.sample(
                    n=min(200, len(chunk)),
                    random_state=42
                )
            )

    os.remove(temp_path)

    if anomaly_chunks:
        anomalies = pd.concat(
            anomaly_chunks,
            ignore_index=True
        )
    else:
        anomalies = pd.DataFrame()

    st.success(
        f"Analysis completed: {total_logs:,} logs processed."
    )

    st.subheader("Threat Detection Results")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Logs",
        f"{total_logs:,}"
    )

    col2.metric(
        "Anomalies",
        f"{total_anomalies:,}"
    )

    anomaly_rate = (
        total_anomalies / total_logs * 100
        if total_logs else 0
    )

    col3.metric(
        "Anomaly Rate",
        f"{anomaly_rate:.2f}%"
    )

    if plot_chunks:

        plot_df = pd.concat(
            plot_chunks,
            ignore_index=True
        )

        fig = px.scatter(
            plot_df,
            x=plot_df.index,
            y="Rule_Level",
            color=plot_df["Anomaly_Label"].astype(str),
            color_discrete_map={
                "-1": "red",
                "1": "blue"
            },
            title="Threat Distribution"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    st.subheader("🚨 Identified Threats")

    st.dataframe(
        anomalies,
        use_container_width=True
    )
