"""
Database operations for SecurePass
SQLite storage with encrypted credential fields
"""
import sqlite3
import json
from typing import List, Dict, Optional
from datetime import datetime


class DatabaseManager:
    """Manages SQLite database operations"""
    
    def __init__(self, db_path: str = "securepass.db"):
        self.db_path = db_path
        self.conn = None
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        
        # Config table (stores salt, iterations, etc.)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        # Credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                url TEXT,
                notes_encrypted TEXT,
                created_at TEXT NOT NULL,
                modified_at TEXT NOT NULL,
                category TEXT DEFAULT 'General'
            )
        ''')
        
        # Create index for faster searches
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_service 
            ON credentials(service)
        ''')
        
        self.conn.commit()
    
    def save_config(self, key: str, value: str):
        """Save configuration value"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO config (key, value) 
            VALUES (?, ?)
        ''', (key, value))
        self.conn.commit()
    
    def get_config(self, key: str) -> Optional[str]:
        """Retrieve configuration value"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT value FROM config WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row['value'] if row else None
    
    def add_credential(self, service: str, username: str, 
                      password_encrypted: str, url: str = "",
                      notes_encrypted: str = "", category: str = "General") -> int:
        """Add new credential entry"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO credentials 
            (service, username, password_encrypted, url, notes_encrypted, 
             created_at, modified_at, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (service, username, password_encrypted, url, notes_encrypted, 
              now, now, category))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def update_credential(self, cred_id: int, service: str, username: str,
                         password_encrypted: str, url: str = "",
                         notes_encrypted: str = "", category: str = "General"):
        """Update existing credential"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            UPDATE credentials 
            SET service = ?, username = ?, password_encrypted = ?,
                url = ?, notes_encrypted = ?, modified_at = ?, category = ?
            WHERE id = ?
        ''', (service, username, password_encrypted, url, notes_encrypted,
              now, category, cred_id))
        
        self.conn.commit()
    
    def delete_credential(self, cred_id: int):
        """Delete credential by ID"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM credentials WHERE id = ?', (cred_id,))
        self.conn.commit()
    
    def get_credential(self, cred_id: int) -> Optional[Dict]:
        """Get single credential by ID"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM credentials WHERE id = ?', (cred_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_credentials(self, search_term: str = "") -> List[Dict]:
        """
        Get all credentials, optionally filtered by search term
        
        Args:
            search_term: Filter by service, username, or category
        
        Returns:
            List of credential dictionaries
        """
        cursor = self.conn.cursor()
        
        if search_term:
            cursor.execute('''
                SELECT * FROM credentials 
                WHERE service LIKE ? OR username LIKE ? OR category LIKE ?
                ORDER BY service ASC
            ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        else:
            cursor.execute('SELECT * FROM credentials ORDER BY service ASC')
        
        return [dict(row) for row in cursor.fetchall()]
    
    def export_data(self) -> str:
        """Export all credentials as JSON (still encrypted)"""
        credentials = self.get_all_credentials()
        salt = self.get_config('salt')
        iterations = self.get_config('iterations')
        
        export_data = {
            'config': {
                'salt': salt,
                'iterations': iterations
            },
            'credentials': credentials,
            'exported_at': datetime.now().isoformat()
        }
        
        return json.dumps(export_data, indent=2)
    
    def import_data(self, json_data: str) -> int:
        """
        Import credentials from JSON export
        
        Returns:
            Number of credentials imported
        """
        data = json.loads(json_data)
        count = 0
        
        for cred in data.get('credentials', []):
            self.add_credential(
                service=cred['service'],
                username=cred['username'],
                password_encrypted=cred['password_encrypted'],
                url=cred.get('url', ''),
                notes_encrypted=cred.get('notes_encrypted', ''),
                category=cred.get('category', 'General')
            )
            count += 1
        
        self.conn.commit()
        return count
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
