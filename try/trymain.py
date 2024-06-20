import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('example.db')

# Create a cursor object
cur = conn.cursor()

# Create a table
cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NULL,
    age INTEGER
)
''')

# Insert some data into the table
cur.execute("INSERT INTO users (name, age) VALUES ('Alice', 30)")
cur.execute("INSERT INTO users (name, age) VALUES ('', 25)")
cur.execute("INSERT INTO users (name, age) VALUES ('Charlie', 35)")

# Commit the changes
conn.commit()

# Query the table
cur.execute("SELECT * FROM users")

# Fetch and print each row one by one
row = cur.fetchall()
print(row)
# while row:
#     print(row)  # Each row is a tuple
#     row = cur.fetchone()

# Close the connection
conn.close()
