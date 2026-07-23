import csv
import json
import os
from datetime import datetime



def generate_report(attacks):

    # Create reports folder
    if not os.path.exists("reports"):
        os.makedirs("reports")


    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


    csv_file = f"reports/security_report_{timestamp}.csv"

    json_file = f"reports/security_report_{timestamp}.json"



    # CSV Report

    with open(csv_file, "w", newline="") as file:

        writer = csv.writer(file)


        writer.writerow([

            "IP Address",
            "Username",
            "Attack Type",
            "Attempts",
            "Threat Score",
            "Risk",
            "First Seen",
            "Last Seen"

        ])



        for attack in attacks:

            writer.writerow([

                attack["ip"],
                attack["username"],
                attack["attack_type"],
                attack["attempts"],
                attack["score"],
                attack["risk"],
                attack["first_seen"],
                attack["last_seen"]

            ])



    # JSON Report

    with open(json_file, "w") as file:

        json.dump(
            attacks,
            file,
            indent=4
        )



    print("\nReports Generated:")
    print(csv_file)
    print(json_file)
