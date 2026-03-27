import mysql.connector

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Varshu@1207",
        database="biometric_db"
    )
