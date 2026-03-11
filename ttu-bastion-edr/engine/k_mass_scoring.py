import psycopg2
import json
import time
from datetime import datetime, timedelta
class KMassScorer:
def __init__(self, conn_string):
self.conn = psycopg2.connect(conn_string)
def compute_mass_score(self, app_id, payload):
"""Calcule un score de risque à partir du payload et du contexte."""
cur = self.conn.cursor()
cur.execute("SELECT k_factor FROM ttu_core.registry WHERE app_id = %s",
(app_id,))
k = cur.fetchone()[0]
# Logique heuristique : si k est élevé, le système est sous stress → risque accru
risk = k * 0.1
if 'file_hash' in payload:
# Vérification avec une base de signatures (simulée)
risk += 0.5
return min(risk, 1.0)
def quarantine_decision(self, app_id, payload):
score = self.compute_mass_score(app_id, payload)
if score > 0.8:
return True, "Menace détectée (score > 0.8) – mise en quarantaine"
return False, "OK"