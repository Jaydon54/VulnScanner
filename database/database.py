#database/database.py
#Code for database that stores scan results goes here

import sqlite3                   #built-in module to interact with SQLite databases 
from datetime import datetime    #Optional is useful for working with timestamps 
from typing import List, Tuple, Optional #type hints to clarify function inputs & outputs 



import sqlite3
from typing import List, Tuple

# Database name
DB_NAME = "scanner_results.db"

#----------------------------------------------------------
# Create database connection
#----------------------------------------------------------
def create_connection():
    try:
        conn = sqlite3.connect(DB_NAME)
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

#----------------------------------------------------------
# Create the scan_results table if it doesn't exist
#----------------------------------------------------------
def create_table():
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                state TEXT,
                extra_info TEXT,
                scan_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT
            )
        """)
        conn.commit()
        conn.close()

#----------------------------------------------------------
# Insert a scan result into the database
#----------------------------------------------------------
def insert_result(target: str, port: int, service: str, state: str, extra_info: str, scan_type: str, risk_level: str):
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_results (target, port, service, state, extra_info, scan_type, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target, port, service, state, extra_info, scan_type, risk_level)
        )
        conn.commit()
        conn.close()

#----------------------------------------------------------
# Retrieve all results for a specific target
#----------------------------------------------------------
def get_results_by_target(target: str) -> List[Tuple]:
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scan_results WHERE target = ?",
            (target,)
        )
        rows = cursor.fetchall()
        conn.close()
        return rows
    return []

#----------------------------------------------------------
# Retrieve all results for a specific scan date (YYYY-MM-DD)
#----------------------------------------------------------

def get_results_by_date(start_date: str, end_date: str) -> List[Tuple]: #function for retriving results by date also returning as a tuple
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scan_results
        WHERE DATE(timestamp) BETWEEN DATE(?) AND DATE(?)
        ORDER BY timestamp DESC
    """, (start_date, end_date)) #fetches results from a specific date interval showing the most recent first

    results = cursor.fetchall()
    conn.close()
    return results
