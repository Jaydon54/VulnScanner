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
def init_db() -> None:  #table for results and their parameters 
    conn = sqlite3.connect(DB_Name)  #connects to database file and creates one if doesnt exist
    cursor = conn.cursor() #control tool for sending SQL commands to database

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
    """)  #SQL commands, where each column will be stored

    conn.commit() #saves changes to database
    conn.close()

def insert_result( #function for inserting results into database
    target: str,
    port: int,
    service: Optional[str],
    state: Optional[str],
    extra_info: Optional[str],
    scan_type: str
) -> None:
    conn = sqlite3.connect(DB_Name) #connects to the SQLite database 
    cursor = conn.cursor() 

    cursor.execute("""
        INSERT INTO ScanResults (target, port, service, state, extra_info, scan_type)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (target, port, service, state, extra_info, scan_type)) #the tuple import will safely insert vales for ?

    conn.commit() 
    conn.close()

def get_results_by_target(target: str) -> List[Tuple]: #function for getting results from target which returns a list of tuples
    conn = sqlite3.connect(DB_Name) #each tuple contains one row from the database
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM ScanResults  
        WHERE target = ?    
        ORDER BY timestamp DESC 
    """, (target,)) #get all columns
                    #filters rows for where target matches
                    #sort results from newest to oldest by descendig
                    #target, is a 1 element tuple whicch is why the comma is used
    results = cursor.fetchall() #retrieves all rows returned by the query and they become a tuple within the list
    conn.close()
    return results  #returns results to where the function was called

def get_results_by_date(start_date: str, end_date: str) -> List[Tuple]: #function for retriving results by date also returning as a tuple
    conn = sqlite3.connect(DB_Name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM ScanResults
        WHERE DATE(timestamp) BETWEEN DATE(?) AND DATE(?)
        ORDER BY timestamp DESC
    """, (start_date, end_date)) #fetches results from a specific date interval showing the most recent first

    results = cursor.fetchall()
    conn.close()
    return results
