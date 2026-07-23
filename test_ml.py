from log_parser import parse_logs
from ml_detector import detect_anomalies


# Read logs

logs = parse_logs("auth.log")


# Run AI detection

results = detect_anomalies(logs)



print("\n========== AI ANOMALY REPORT ==========")


for result in results:

    print("\n----------------")

    print("IP:",
          result["ip"])

    print("Username:",
          result["username"])

    print("Login Status:",
          result["status"])

    print("AI Result:",
          result["anomaly"])
