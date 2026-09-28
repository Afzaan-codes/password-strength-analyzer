import hashlib
import re
import secrets
import sqlite3
import string


class PasswordAnalyzer:

    def __init__(self, db_name="passwords.db"):
        self.conn = sqlite3.connect(db_name)
        self._init_db()

    def _init_db(self):
        """Initializes database to store hashed passwords securely."""
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT UNIQUE NOT NULL
                )
            """)

    def _hash_password(self, password: str) -> str:
        """Hashes password using SHA-256 for secure storage."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def is_reused(self, password: str) -> bool:
        """Checks if the password has been previously recorded in the database."""
        pw_hash = self._hash_password(password)
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT 1 FROM password_history WHERE password_hash = ?", (pw_hash,)
        )
        return cursor.fetchone() is not None

    def record_password(self, password: str):
        """Saves a hashed password to prevent future reuse."""
        pw_hash = self._hash_password(password)
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO password_history (password_hash) VALUES (?)",
                (pw_hash,),
            )

    def evaluate_strength(self, password: str) -> dict:
        """Evaluates password length, character complexity, patterns, and uniqueness."""
        score = 0
        feedback = []

        # 1. Length Check
        length = len(password)
        if length >= 12:
            score += 2
        elif length >= 8:
            score += 1
            feedback.append("Consider making the password at least 12 characters long.")
        else:
            feedback.append("Password is too short (must be at least 8 characters).")

        # 2. Complexity Checks
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[@$!%*?&#^()_\-+=\[\]{}|;:<>./~`]", password))

        complexity_count = sum([has_lower, has_upper, has_digit, has_special])
        score += complexity_count

        if not has_lower:
            feedback.append("Add lowercase letters.")
        if not has_upper:
            feedback.append("Add uppercase letters.")
        if not has_digit:
            feedback.append("Add numbers.")
        if not has_special:
            feedback.append("Add special characters (e.g., @, #, $, !).")

        # 3. Uniqueness / Repetition Check
        unique_ratio = len(set(password)) / length if length > 0 else 0
        if unique_ratio < 0.6:
            score = max(0, score - 1)
            feedback.append("Avoid too many repeated characters.")

        # Common predictable patterns
        if re.search(
            r"(1234|abcd|password|qwerty|admin)", password, re.IGNORECASE
        ):
            score = max(0, score - 2)
            feedback.append("Avoid common sequences or dictionary words.")

        # 4. Database Reuse Check
        reused = self.is_reused(password)
        if reused:
            feedback.append("This password has already been used previously.")

        # Determine qualitative strength rating
        if score <= 2:
            rating = "Very Weak"
        elif score <= 4:
            rating = "Weak"
        elif score <= 5:
            rating = "Moderate"
        else:
            rating = "Strong"

        return {
            "score": score,
            "max_score": 6,
            "rating": rating,
            "reused": reused,
            "feedback": feedback,
        }

    @staticmethod
    def generate_alternative(length: int = 14) -> str:
        """Generates a cryptographically strong alternative password."""
        chars = (
            string.ascii_lowercase
            + string.ascii_uppercase
            + string.digits
            + "!@#$%^&*()-_=+"
        )
        while True:
            candidate = "".join(secrets.choice(chars) for _ in range(length))
            if (
                any(c.islower() for c in candidate)
                and any(c.isupper() for c in candidate)
                and any(c.isdigit() for c in candidate)
                and any(c in "!@#$%^&*()-_=+" for c in candidate)
            ):
                return candidate


if __name__ == "__main__":
    analyzer = PasswordAnalyzer()

    print("--- Password Strength Analyzer ---")
    user_pw = input("Enter a password to analyze: ").strip()

    result = analyzer.evaluate_strength(user_pw)

    print(f"\nRating: {result['rating']} (Score: {result['score']}/{result['max_score']})")

    if result["feedback"]:
        print("Suggestions / Issues:")
        for item in result["feedback"]:
            print(f" - {item}")

    # Offer alternatives if not strong or if reused
    if result["rating"] != "Strong" or result["reused"]:
        print(f"\nSuggested Strong Alternative: {analyzer.generate_alternative()}")

    # Save to database if acceptable
    if result["score"] >= 4 and not result["reused"]:
        analyzer.record_password(user_pw)
        print("\nPassword securely hashed and saved to history database.")