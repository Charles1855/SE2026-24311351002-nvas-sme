"""
Empty the results database (the tables are kept).

Run from the project root:   python reset_db.py
"""
from database.db import get_connection, init_db

init_db()  # makes sure the tables exist

answer = input("This deletes ALL saved scan results. Type yes to continue: ")
if answer.strip().lower() != "yes":
    print("Cancelled. Nothing was deleted.")
    raise SystemExit

conn = get_connection()
cursor = conn.cursor()
cursor.execute("DELETE FROM vulnerabilities")
cursor.execute("DELETE FROM scans")
cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('scans', 'vulnerabilities')")
conn.commit()
conn.execute("VACUUM")  # shrink the file
conn.close()

print("Database cleared. The next scan starts from an empty database.")