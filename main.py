import streamlit as st
import pandas as pd
from utils.log_analyzer import LogAnalyzer
from utils.ml_detector import AnomalyDetector
from utils.visualizer import LogVisualizer
from utils.report_generator import ReportGenerator
import base64

# Page configuration
st.set_page_config(
    page_title="Cybersecurity Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Initialize classes
log_analyzer = LogAnalyzer()
ml_detector = AnomalyDetector()
visualizer = LogVisualizer()
report_generator = ReportGenerator()

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stProgress > div > div > div > div {
        background-color: #ff4b4b;
    }
    </style>
    """, unsafe_allow_html=True)

# Title and description
st.title("🛡️ Cybersecurity Log Analyzer")
st.markdown("""
    Upload your system logs for AI-powered security analysis and threat detection.
    The analyzer will scan for anomalies, potential threats, and generate detailed reports.
""")

# File upload
uploaded_file = st.file_uploader("Upload Log File", type=['txt', 'log'])

if uploaded_file is not None:
    try:
        # Read and parse logs
        with st.spinner("Processing log file..."):
            log_content = uploaded_file.getvalue().decode()
            df = log_analyzer.parse_log(log_content)

        # Get basic statistics
        stats = log_analyzer.get_basic_stats(df)

        # Detect anomalies
        with st.spinner("Detecting anomalies..."):
            anomalies, features = ml_detector.detect_anomalies(df)
            anomaly_details = ml_detector.get_anomaly_details(df, anomalies)

        # Display statistics
        st.header("📊 Analysis Overview")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Entries", stats['total_entries'])
        with col2:
            st.metric("Unique IPs", stats['unique_ips'])
        with col3:
            st.metric("High Severity Events", stats['high_severity'])
        with col4:
            st.metric("Potential Attacks", stats['potential_attacks'])

        # Visualizations
        st.header("📈 Visualizations")
        col1, col2 = st.columns(2)

        with col1:
            st.plotly_chart(visualizer.create_severity_pie_chart(df), use_container_width=True)
            st.plotly_chart(visualizer.create_ip_bar_chart(df), use_container_width=True)

        with col2:
            st.plotly_chart(visualizer.create_timeline_chart(df), use_container_width=True)
            st.plotly_chart(visualizer.create_anomaly_scatter(features, anomalies), use_container_width=True)

        # Anomaly Detection Results
        st.header("🚨 Detected Anomalies")
        if anomaly_details['total_anomalies'] > 0:
            st.warning(f"Detected {anomaly_details['total_anomalies']} anomalies in the log data")
            for i in range(min(5, len(anomaly_details['anomaly_messages']))):
                st.code(f"Time: {anomaly_details['anomaly_timestamps'][i]}\n"
                       f"IP: {anomaly_details['anomaly_ips'][i]}\n"
                       f"Message: {anomaly_details['anomaly_messages'][i]}")
        else:
            st.success("No anomalies detected in the log data")

        # Generate PDF Report
        if st.button("Generate PDF Report"):
            with st.spinner("Generating PDF report..."):
                pdf_buffer = report_generator.generate_pdf_report(stats, anomaly_details)
                b64_pdf = base64.b64encode(pdf_buffer.getvalue()).decode()
                href = f'<a href="data:application/pdf;base64,{b64_pdf}" download="security_report.pdf">Download PDF Report</a>'
                st.markdown(href, unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Error processing log file: {str(e)}")
else:
    # Sample log format
    st.info("Please upload a log file to begin analysis")
    st.markdown("""
    ### Sample Log Format:
    ```
    2024-02-23 10:15:30 192.168.1.100 Failed login attempt - multiple tries from same IP
    2024-02-23 10:15:35 192.168.1.101 Connection established
    2024-02-23 10:16:00 192.168.1.102 SQL injection attempt detected in login form
    ```
    Your log file should contain entries with timestamps, IP addresses, and event descriptions.
    """)