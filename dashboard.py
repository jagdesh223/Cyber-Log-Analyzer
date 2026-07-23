import streamlit as st
import pandas as pd

from log_parser import parse_logs
from threat_detector import detect_attacks
from attack_mapping import get_attack_details


# Page configuration

st.set_page_config(
    page_title="Cyber Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ Cyber Log Analyzer Dashboard")

st.write(
    "Security log monitoring and brute force attack detection"
)


# Upload file

uploaded_file = st.file_uploader(
    "Upload auth.log file",
    type=["log", "txt"]
)



if uploaded_file:

    # Save uploaded file

    with open("uploaded.log", "wb") as f:
        f.write(
            uploaded_file.getbuffer()
        )


    # Analyze logs

    logs = parse_logs("uploaded.log")

    attacks = detect_attacks(logs)



    # Statistics

    failed = len(
        [
            log for log in logs
            if log["status"] == "FAILED"
        ]
    )


    success = len(
        [
            log for log in logs
            if log["status"] == "SUCCESS"
        ]
    )



    st.subheader("📊 Security Summary")


    col1, col2, col3 = st.columns(3)


    col1.metric(
        "Total Logs",
        len(logs)
    )


    col2.metric(
        "Failed Attempts",
        failed
    )


    col3.metric(
        "Threats Detected",
        len(attacks)
    )



    st.divider()



    # Threat Report

    st.subheader("🚨 Threat Report")


    if attacks:


        for attack in attacks:


            details = get_attack_details(
                attack["attack_type"]
            )


            st.warning(
                "Attack Detected"
            )


            st.write(
                "Attack Type:",
                attack["attack_type"]
            )


            st.write(
                "Source IP:",
                attack["ip"]
            )


            st.write(
                "Target User:",
                attack["username"]
            )


            st.write(
                "Attempts:",
                attack["attempts"]
            )


            st.write(
                "Threat Score:",
                str(attack["score"]) + "/100"
            )


            st.write(
                "Risk Level:",
                attack["risk"]
            )


            st.write(
                "MITRE Technique:",
                details["mitre_id"],
                "-",
                details["mitre_name"]
            )


            st.write(
                "Description:",
                details["description"]
            )


            st.divider()



        # Graph

        st.subheader("📈 Attack Frequency")


        df = pd.DataFrame(attacks)


        chart = df[
            [
                "ip",
                "attempts"
            ]
        ]


        chart = chart.set_index(
            "ip"
        )


        st.bar_chart(chart)



    else:

        st.success(
            "No suspicious activity detected"
        )



else:

    st.info(
        "Upload a log file to start analysis"
    )
