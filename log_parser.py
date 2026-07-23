
import re


def parse_logs(filename):

    logs = []

    with open(filename, "r") as file:

        for line in file:

            time = re.search(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)',
                line
            )


            # Failed login
            if "Failed password" in line:

                ip = re.search(
                    r'from (\d+\.\d+\.\d+\.\d+)',
                    line
                )

                user = re.search(
                    r'for (\w+)',
                    line
                )


                logs.append({

                    "time": time.group(1),
                    "ip": ip.group(1),
                    "username": user.group(1),
                    "status": "FAILED"

                })


            # Successful login
            elif "Accepted password" in line:

                ip = re.search(
                    r'from (\d+\.\d+\.\d+\.\d+)',
                    line
                )

                user = re.search(
                    r'for (\w+)',
                    line
                )


                logs.append({

                    "time": time.group(1),
                    "ip": ip.group(1),
                    "username": user.group(1),
                    "status": "SUCCESS"

                })


    return logs
