def detect_attack(old_hash, new_hash, file_exists):

    if not file_exists:
        return {
            "attack_type": "File Deletion",
            "severity": "Critical"
        }

    if old_hash != new_hash:
        return {
            "attack_type": "File Tampering",
            "severity": "High"
        }

    return {
        "attack_type": "Secure",
        "severity": "Low"
    }