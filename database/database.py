# database/database.py
import sqlite3
from datetime import datetime
from typing import List, Tuple, Optional

# Database Configuration
DB_Name = "scanner_results.db"

# Database Initialization
def init_db() -> None:
    conn = sqlite3.connect(DB_Name)
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
    """)  # Removed extra parenthesis

    conn.commit()
    conn.close()

def insert_result(target, port, service, state, extra_info, scan_type, risk_level):
    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_results 
        (target, port, service, state, extra_info, scan_type, risk_level) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (target, port, service, state, extra_info, scan_type, risk_level))
    conn.commit()
    conn.close()

def get_results_by_target(target: str) -> List[Tuple]:
    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scan_results  
        WHERE target = ?    
        ORDER BY timestamp DESC 
    """, (target,))
    results = cursor.fetchall()
    conn.close()
    return results

def get_results_by_date(start_date: str, end_date: str) -> List[Tuple]:
    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scan_results
        WHERE DATE(timestamp) BETWEEN DATE(?) AND DATE(?)
        ORDER BY timestamp DESC
    """, (start_date, end_date))
    results = cursor.fetchall()
    conn.close()
    return results
