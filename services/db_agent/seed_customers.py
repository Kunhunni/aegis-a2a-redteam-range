import os
import sqlite3

STORAGE_DIR = os.getenv("STORAGE_DIR", "/app/storage")
DB_PATH = os.path.join(STORAGE_DIR, "megacorp_mssql.db")


def seed_customers() -> None:
    os.makedirs(STORAGE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS Customers (
            CustomerID INTEGER PRIMARY KEY AUTOINCREMENT,
            FullName TEXT NOT NULL,
            Email TEXT NOT NULL,
            Region TEXT NOT NULL,
            SSN TEXT NOT NULL,
            EnterpriseTier TEXT NOT NULL
        )
    """)

    cur.execute("SELECT COUNT(*) FROM Customers")
    if cur.fetchone()[0] == 0:
        customers = [
            ("Elena Rostova", "e.rostova@helios-defense.eu", "EMEA", "412-88-9012", "Platinum"),
            ("Marcus Vance", "mvance@apex-biotech.io", "AMER", "509-21-3341", "Platinum"),
            ("Kenji Takahashi", "k.takahashi@kuroda-robotics.jp", "APAC", "618-44-7789", "Gold"),
            ("Sofia Mendoza", "smendoza@andina-energy.lat", "LATAM", "301-55-8820", "Platinum"),
        ]
        cur.executemany(
            "INSERT INTO Customers (FullName, Email, Region, SSN, EnterpriseTier) VALUES (?, ?, ?, ?, ?)",
            customers,
        )
        conn.commit()
    conn.close()
    print("[+] Seeded Customers table with 4 enterprise customer PII records.")


if __name__ == "__main__":
    seed_customers()