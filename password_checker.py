"""
============================================================
 PASSWORD STRENGTH CHECKER
============================================================
Concepts covered: regex, entropy, rule-based scoring
No external libraries required (uses built-in `re` and `math`)
============================================================
"""

import re
import math


# ============================================================
# STEP 1: RULE-BASED CHECKS
# ============================================================
def check_length(password):
    return len(password) >= 8


def check_uppercase(password):
    return bool(re.search(r'[A-Z]', password))


def check_lowercase(password):
    return bool(re.search(r'[a-z]', password))


def check_digit(password):
    return bool(re.search(r'[0-9]', password))


def check_special_char(password):
    return bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))


# ============================================================
# STEP 2: COMMON PASSWORD BLOCKLIST CHECK
# ============================================================
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "123123", "admin", "letmein"
}


def check_common_password(password):
    return password.lower() not in COMMON_PASSWORDS


# ============================================================
# STEP 3: ENTROPY CALCULATION (measures randomness/strength)
# ============================================================
def calculate_entropy(password):
    """
    Entropy = length * log2(character pool size)
    Higher entropy = harder to brute-force.
    """
    pool_size = 0
    if check_lowercase(password):
        pool_size += 26
    if check_uppercase(password):
        pool_size += 26
    if check_digit(password):
        pool_size += 10
    if check_special_char(password):
        pool_size += 32

    if pool_size == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


# ============================================================
# STEP 4: OVERALL SCORING SYSTEM
# ============================================================
def rate_password(password):
    checks = {
        "Length >= 8": check_length(password),
        "Has uppercase": check_uppercase(password),
        "Has lowercase": check_lowercase(password),
        "Has digit": check_digit(password),
        "Has special character": check_special_char(password),
        "Not a common password": check_common_password(password),
    }

    score = sum(checks.values())
    entropy = calculate_entropy(password)

    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MODERATE"
    elif score == 5:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    return checks, score, entropy, strength


# ============================================================
# STEP 5: DISPLAY RESULTS
# ============================================================
def print_report(password):
    checks, score, entropy, strength = rate_password(password)

    print(f"\nPassword: {'*' * len(password)}")
    print("-" * 40)
    for rule, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{rule:<25} {status}")
    print("-" * 40)
    print(f"Score: {score}/6")
    print(f"Entropy: {entropy} bits")
    print(f"Overall Strength: {strength}")


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=== PASSWORD STRENGTH CHECKER ===")
    pwd = input("Enter a password to check: ")
    print_report(pwd)
