import streamlit as st
import pandas as pd
import plotly.express as px
import joblib

st.set_page_config(
    page_title="ML Threat Detection Dashboard",
    layout="wide"
)

st.title("🛡️ ML-Based Threat Detection Dashboard")
st.write(
    "Analyze processed Wazuh security logs using a trained Isolation Forest model."
)

# Load the trained ML model
try:
    model = joblib.load("isolation_forest_model.pkl")
    st.success("Trained ML model loaded successfully.")
except FileNotFoundError:
    st.error(
        "Model file not found. Make sure "
        "'isolation_forest_model.pkl' is in the same folder as dashboard.py."
    )
    st.stop()

# Upload processed logs
uploaded_file = st.file_uploader(
    "Upload Processed Wazuh Log CSV",
    type=["csv"]
)

if uploaded_file is not None:

    df = pd.read_csv(uploaded_file)

    st.subheader("Log Data Preview")
    st.dataframe(df.head())


    required_features = [
    "Rule_Level",
    "Is_High_Severity",
    "Is_Login_Failure",
    "Rule_Frequency",
    "Agent_Event_Count"
]

    missing_features = [
        feature
        for feature in required_features
        if feature not in df.columns
    ]

    if missing_features:
        st.error(
            f"Missing required features: {missing_features}"
        )
        st.stop()

    if st.button("Detect Threats"):

        X = df[required_features].fillna(0)

        # Use the trained model
        predictions = model.predict(X)
        scores = model.decision_function(X)

        df["Anomaly_Label"] = predictions
        df["Anomaly_Score"] = scores

        anomalies = df[
            df["Anomaly_Label"] == -1
        ]

        st.error(
            f"🚨 Detected {len(anomalies):,} anomalies "
            f"out of {len(df):,} logs."
        )

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Logs",
            f"{len(df):,}"
        )

        col2.metric(
            "Anomalies",
            f"{len(anomalies):,}"
        )

        col3.metric(
            "Anomaly Rate",
            f"{len(anomalies) / len(df) * 100:.2f}%"
        )

        # Threat distribution
        fig = px.scatter(
            df,
            x=df.index,
            y="Rule_Level",
            color=df["Anomaly_Label"].astype(str),
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