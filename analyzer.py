from log_parser import parse_logs
from threat_detector import detect_attacks
from report_generator import generate_report


# Read log file
logs = parse_logs("auth.log")


# Count login activity
failed = 0
success = 0


for log in logs:

    if log["status"] == "FAILED":
        failed += 1

    else:
        success += 1



print("\n========== SECURITY SUMMARY ==========")

print("Total Logs Analyzed:", len(logs))

print("Failed Login Attempts:", failed)

print("Successful Logins:", success)



# Detect threats
attacks = detect_attacks(logs)



print("\n========== THREAT REPORT ==========")



if len(attacks) == 0:

    print("No suspicious activity detected.")


else:

    for attack in attacks:

        print("\n-----------------------------")

        print("Attack Type:",
              attack["attack_type"])

        print("Source IP:",
              attack["ip"])

        print("Target Username:",
              attack["username"])

        print("Failed Attempts:",
              attack["attempts"])

        print("Threat Score:",
              attack["score"],
              "/100")

        print("Risk Level:",
              attack["risk"])

        print("First Seen:",
              attack["first_seen"])

        print("Last Seen:",
              attack["last_seen"])



# Generate CSV report

generate_report(attacks)

