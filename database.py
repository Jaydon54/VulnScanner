#database/database.py
#Code for database that stores scan results goes here

import sqlite3                   #built-in module to interact with SQLite databases 
from datetime import datetime    #Optional is useful for working with timestamps 
from typing import List, Tuple, Optional #type hints to clarify function inputs & outputs 



#--------------------------------
#Database Configuration
#--------------------------------
DB_Name = "scanner_results.db" #name of the SQLite file

#--------------------------------
#Database Initialization
#--------------------------------
def init_db() -> None:
    conn = sqlite3.connect(DB_Name)  #connects to database file and creates one if doesnt exist
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ScanResults (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            port INTEGER NOT NULL,
            service TEXT,
            state TEXT,
            extra_info TEXT,
            scan_type TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
