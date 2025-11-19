import sqlite3

conn = sqlite3.connect("users.db")  # replace with your actual DB name
cursor = conn.cursor()

# Add column to existing users table
cursor.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")

conn.commit()
conn.close()

print("✅ Column 'email_verified' added successfully.")
