import time
import psycopg2
import os

DATABASE_URL = os.getenv("SUPABASE_DB_URL")

def process_all():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT ttu_core.dispatch_processing()")
    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    while True:
        process_all()
        time.sleep(60)  # correspond au battement de cœur