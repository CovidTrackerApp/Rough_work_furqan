import sys
from user import User
sys.path.insert(1, '/home/furqan/.pyenv/versions/3.8.5/lib/python3.8/site-packages')


import psycopg2

DB_NAME = "test_db"
DB_USER = "ubuntu"
DB_PASS = "ubuntu"
DB_HOST = "ec2-52-74-221-135.ap-southeast-1.compute.amazonaws.com"
DB_PORT = "5432"


try: 
    conn = psycopg2.connect(database=DB_NAME, user = DB_USER, password=DB_PASS, host = DB_HOST, port = DB_PORT)
    print("Database connected successfully")

except: 
    print("Database not connected.")
















