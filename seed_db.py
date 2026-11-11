#!/usr/bin/env python3
"""
Seed script for RoomMatch database.
Run: python seed_db.py
Populates the database with sample NYC listigs for rooms, roommates, and sublets.
"""
import sqlite3
import os

# Use the database path from the app
BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "roommatch.db")


def init_db():
    """Initialize database with sample listings if tables are empty."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Create all tables matching app.py schema
    c.execute("""CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0)""")

    c.execute("""CREATE TABLE IF NOT EXISTS listings(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK(type IN ('Room','Roommate','Sublet')),
      title TEXT NOT NULL, city TEXT NOT NULL, price REAL NOT NULL,
      description TEXT NOT NULL DEFAULT '', contact TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      payment_status TEXT NOT NULL DEFAULT 'pending',
      payment_method TEXT NOT NULL DEFAULT 'zelle',
      listing_fee REAL NOT NULL DEFAULT 20,
      application_fee REAL NOT NULL DEFAULT 15)""")

    c.execute("""CREATE TABLE IF NOT EXISTS favorites(
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
      PRIMARY KEY(user_id, listing_id))""")

    c.execute("""CREATE TABLE IF NOT EXISTS login_attempts(
      ip TEXT, email TEXT, ts INTEGER)""")

    conn.commit()

    # Check if listings already exist
    c.execute("SELECT COUNT(*) FROM listings")
    count = c.fetchone()[0]

    if count == 0:
        # Insert sample users first (needed for foreign key constraints)
        c.execute("INSERT OR IGNORE INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ('admin@roommatch.test', 'Admin', 'hashed', 1700000000, 1))
        c.execute("INSERT OR IGNORE INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ('user1@roommatch.test', 'John Doe', 'hashed', 1700000000, 0))
        c.execute("INSERT OR IGNORE INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ('user2@roommatch.test', 'Jane Smith', 'hashed', 1700000000, 0))

        # Now insert sample listings - Rooms (type=1), Roommates (type=2), Sublets (type=3)
        # Each: (user_id, type, title, city, price, description, contact)
        sample_listings = [
            # Rooms - user_id=1
            (1, "Room", "Cozy Studio in Manhattan", "New York", 1800,
             "Sunny 1BR studio in Hell's Kitchen, modern appliances, gym access",
             "john.doe@email.com"),
            (1, "Room", "Downtown Brooklyn Apartment", "New York", 1500,
             "2BR apartment in Downtown Brooklyn, close to transit, pet-friendly",
             "jane.smith@email.com"),
            (1, "Room", "Quiet Room in Queens", "New York", 950,
             "Private room in shared house, quiet neighborhood, parking available",
             "mike.brown@email.com"),
            (1, "Room", "Luxury Upper West Side", "New York", 2200,
             "Executive studio with doorman, concierge, fitness center",
             "lisa.white@email.com"),
            # Roommates - user_id=2
            (2, "Roommate", "Looking for roommate in Manhattan", "New York",
             "Male roommate wanted, clean, non-smoker, $800 share",
             "roommate.seek@email.com"),
            (2, "Roommate", "Female roommate needed in Brooklyn", "New York",
             "Friendly female roommate, $750/month, close to subway",
             "roommate2.seek@email.com"),
            (2, "Roommate", "Silent roommate needed in Queens", "New York",
             "Looking for quiet professional roommate, $650/month",
             "quiet.roommate@email.com"),
            # Sublets - user_id=3
            (3, "Sublet", "Fully furnished sublet in Tribeca", "New York", 3000,
             "Fully furnished 1BR sublet, 3-month lease, luxury building",
             "sublet.tribeca@email.com"),
            (3, "Sublet", "Short-term sublet in Bed-Stuy", "New York", 1600,
             "Charming sublet in historic Brownstone, 6-month lease",
             "sublet.bedstuy@email.com"),
            (3, "Sublet", "Corporate sublet in Midtown", "New York", 2800,
             "Corporate housing, 1-month minimum, all utilities included",
             "corporate.sublet@email.com"),
        ]

        for user_id, lst_type, title, city, price, desc, contact in sample_listings:
            c.execute(
                """INSERT INTO listings 
                   (user_id, type, title, city, price, description, contact, created_at, 
                    payment_status, payment_method, listing_fee, application_fee) 
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (user_id, lst_type, title, city, price, desc, contact,
                 1700000000, 'pending', 'zelle', 20, 15)
            )

        conn.commit()
        print(f"✅ Added {len(sample_listings)} sample NYC listings!")
    else:
        print("ℹ️  Listings already exist - skipping seed data.")

    conn.close()


if __name__ == "__main__":
    init_db()
    print("\nDatabase seeding complete!")
    print("Run 'python app.py' to start the RoomMatch server.")
