from collections import defaultdict


def detect_attacks(logs):

    attackers = defaultdict(list)


    # Group failed attempts by IP
    for log in logs:

        if log["status"] == "FAILED":

            attackers[log["ip"]].append(log)



    attacks = []


    for ip, attempts in attackers.items():

        count = len(attempts)


        usernames = set(
            log["username"]
            for log in attempts
        )


        # Calculate threat score
        score = 0


        # Failed attempts scoring
        if count >= 10:
            score += 50

        elif count >= 5:
            score += 30

        else:
            score += 10



        # Multiple usernames attacked
        if len(usernames) > 1:
            score += 30



        # Risk classification
        if score >= 80:
            risk = "CRITICAL"

        elif score >= 50:
            risk = "HIGH"

        elif score >= 30:
            risk = "MEDIUM"

        else:
            risk = "LOW"



        # Only report suspicious activity
        if count >= 3:

            attacks.append({

                "ip": ip,

                "username": ", ".join(usernames),

                "attempts": count,

                "score": score,

                "risk": risk,

                "attack_type": "Brute Force Login",

                "first_seen": attempts[0]["time"],

                "last_seen": attempts[-1]["time"]

            })


    return attacks
