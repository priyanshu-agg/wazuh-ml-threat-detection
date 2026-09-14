import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="XDR Threat Dashboard", layout="wide")
st.title("🛡️ Automated Threat Detection Dashboard")
st.write("Upload your processed Wazuh logs to scan for network anomalies.")


uploaded_file = st.file_uploader("Upload csv Log File", type=['csv'])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.write("**Raw Telemetry Preview**", df.head())

    st.sidebar.header("Machine Learning Settings")
    contamination = st.sidebar.slider("Anomaly Sensitivity (%)", 1, 10, 5) / 100.0
    
    if st.button("Detect Threats"):
        features = ['Rule_Level'] 

        model = IsolationForest(contamination=contamination, random_state=42)
        df['Anomaly_Score'] = model.fit_predict(df[features].fillna(0))

        anomalies = df[df['Anomaly_Score'] == -1]

        st.error(f"🚨 Detected {len(anomalies)} anomalies out of {len(df)} total logs!")

        fig = px.scatter(
            df, 
            x=df.index, 
            y='Rule_Level', 
            color=df['Anomaly_Score'].astype(str),
            color_discrete_map={'-1': 'red', '1': 'blue'},
            title="Threat Distribution (Red = Anomaly, Blue = Normal)"
        )
        st.plotly_chart(fig, use_container_width=True)

        st.write("**Identified Threat Details**")
        st.dataframe(anomalies)