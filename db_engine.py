import sqlite3
import datetime
import math
import re
from urllib.parse import urlparse
from fuzzywuzzy import fuzz
import whois

DB_FILE = "sangyan_intelligence.db"

# ---------------------------------------------------------
# Database Initialization & Schema Definition
# ---------------------------------------------------------
def init_db():
    """Initializes local persistent SQLite tables for Registry and Threat Intelligence."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # 1. Official SEBI Registry Cache
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sebi_registry (
        sebi_id TEXT PRIMARY KEY,
        firm_name TEXT NOT NULL,
        category TEXT,
        validity_status TEXT DEFAULT 'ACTIVE',
        official_domain TEXT
    )
    """)

    # 2. Dynamic Threat Intelligence & Blacklist Database (Auto-growing)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_blacklist (
        indicator TEXT PRIMARY KEY, -- URL, Domain, UPI ID, or SEBI ID
        indicator_type TEXT NOT NULL, -- 'DOMAIN', 'URL', 'SEBI_MISUSE', 'UPI'
        threat_score INTEGER NOT NULL,
        reason TEXT NOT NULL,
        first_detected TIMESTAMP,
        last_detected TIMESTAMP,
        hit_count INTEGER DEFAULT 1
    )
    """)

    # Populate sample official SEBI records if database is empty
    cursor.execute("SELECT COUNT(*) FROM sebi_registry")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
        INSERT INTO sebi_registry (sebi_id, firm_name, category, official_domain)
        VALUES (?, ?, ?, ?)
        """, [
            ("INA000001234", "Zerodha Broking Limited", "Investment Adviser", "zerodha.com"),
            ("INH000005678", "Groww Invest Tech Pvt Ltd", "Research Analyst", "groww.in"),
            ("INA200098765", "Angel One Limited", "Investment Adviser", "angelone.in"),
            ("INZ000186937", "ICICI Securities Limited", "Stock Broker", "icicidirect.com")
        ])

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# Threat Intelligence Persistence Engine
# ---------------------------------------------------------
def record_threat_event(indicator: str, indicator_type: str, threat_score: int, reason: str):
    """
    Inserts a newly detected threat into the blacklist DB or increments hit_count if already known.
    This creates the self-learning, growing intelligence loop.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT hit_count FROM threat_blacklist WHERE indicator = ?", (indicator.lower(),))
    row = cursor.fetchone()

    if row:
        # Threat already exists: Increment hit count and update timestamp
        new_count = row[0] + 1
        cursor.execute("""
        UPDATE threat_blacklist 
        SET hit_count = ?, last_detected = ?, threat_score = MAX(threat_score, ?)
        WHERE indicator = ?
        """, (new_count, now, threat_score, indicator.lower()))
    else:
        # New threat discovered: Insert record
        cursor.execute("""
        INSERT INTO threat_blacklist (indicator, indicator_type, threat_score, reason, first_detected, last_detected, hit_count)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (indicator.lower(), indicator_type, threat_score, reason, now, now))

    conn.commit()
    conn.close()


def check_blacklist(indicator: str):
    """Queries local Threat Intelligence DB for sub-millisecond historical hits."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT threat_score, reason, hit_count, first_detected 
    FROM threat_blacklist WHERE indicator = ?
    """, (indicator.lower(),))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "is_blacklisted": True,
            "threat_score": result[0],
            "reason": result[1],
            "hit_count": result[2],
            "first_detected": result[3]
        }
    return {"is_blacklisted": False}
