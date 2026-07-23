def get_attack_details(attack_type):

    attacks = {

        "Brute Force Login": {

            "mitre_id": "T1110",

            "mitre_name": "Brute Force",

            "description":
            "Repeated login attempts to guess credentials"

        }

    }


    return attacks.get(
        attack_type,
        {
            "mitre_id": "Unknown",
            "mitre_name": "Unknown",
            "description": "No information"
        }
    )
