import mysql.connector

conn = mysql.connector.connect(

    host="localhost",

    user="root",

    password="",

    database="fim_system"
)

cursor = conn.cursor(
    dictionary=True,
    buffered=True
)

print("Database Connected")