import os

from hash_utils import generate_hash
from attack_detector import detect_attack

def monitor_file(file_path, old_hash):

    if not os.path.exists(file_path):

        return detect_attack(
            old_hash,
            "",
            False
        )

    new_hash = generate_hash(file_path)

    return detect_attack(
        old_hash,
        new_hash,
        True
    )