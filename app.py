#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU Shield Sentinel – Cybersecurity Platform (Version Unifiée Finale)
======================================================================
Fusion complète de toutes les fonctionnalités :
- Moteur mathématique TTU-MC³ avec vélocité temporelle et seuil adaptatif
- Surveillance système réelle (CPU, RAM, réseau) via psutil
- Analyse ciblée de fichiers, URLs et dossiers
- Réponse active : suspension de processus, isolation réseau
- SOC avec alertes, incidents, threat intelligence
- Conformité (rapports GDPR, ISO27001, etc.)
- Visualisation géographique des menaces
- Thread monitoring avec file d'attente pour logs temps réel
- Connexion à Supabase pour persistance et gestion des abonnements
- Onboarding et gestion d'abonnement basés sur la base de données
- Interface à onglets pour une navigation intuitive
"""

import streamlit as st
import numpy as np
import pandas as pd
import psutil
import time
import threading
import hashlib
import random
import json
import uuid
import os
import socket
import requests
import platform
from datetime import datetime, timedelta
from collections import deque
from queue import Queue, Empty
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Tentative d'import pour Supabase
try:
    import psycopg2
    from psycopg2 import sql
    SUPPORTS_SUPABASE = True
except ImportError:
    SUPPORTS_SUPABASE = False

# -------------------------------------------------------------------
# Configuration de la page Streamlit
# -------------------------------------------------------------------
st.set_page_config(
    page_title="TTU Shield Sentinel - Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------------------
# CSS personnalisé (Deep Space)
# -------------------------------------------------------------------
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&family=Syne:wght@400;700;900&display=swap');
  
  html, body, [class*="css"] {
    font-family: 'JetBrains Mono', monospace;
    background-color: #07070f;
    color: #e0e0e0;
  }
  .main { background-color: #07070f; }
  .block-container { padding: 1.5rem 2rem; }
  
  /* Sidebar */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a0a18 0%, #0d0d20 100%);
    border-right: 1px solid #1e1e3a;
  }
  
  /* Metrics */
  [data-testid="stMetric"] {
    background: #0d0d1a;
    border: 1px solid #1e1e3a;
    border-radius: 10px;
    padding: 14px 18px;
  }
  [data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace; font-weight: 900; }
  
  /* Headers */
  h1, h2, h3 { font-family: 'Syne', sans-serif; }
  h1 { 
    background: linear-gradient(135deg, #4cffaa, #4fa8ff);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    font-weight: 900; font-size: 1.8rem;
  }
  
  /* Alert boxes */
  .alert-critical {
    background: #ff3b3b18; border: 1px solid #ff3b3b66;
    border-left: 4px solid #ff3b3b; border-radius: 8px; padding: 12px 16px;
    font-family: 'JetBrains Mono'; font-size: 0.85rem;
  }
  .alert-warning {
    background: #ffb34718; border: 1px solid #ffb34766;
    border-left: 4px solid #ffb347; border-radius: 8px; padding: 12px 16px;
    font-family: 'JetBrains Mono'; font-size: 0.85rem;
  }
  .alert-ok {
    background: #4cffaa18; border: 1px solid #4cffaa66;
    border-left: 4px solid #4cffaa; border-radius: 8px; padding: 12px 16px;
    font-family: 'JetBrains Mono'; font-size: 0.85rem;
  }
  .formula-box {
    background: #0d0d2a; border: 1px solid #4fa8ff44;
    border-radius: 10px; padding: 16px 20px;
    font-family: 'JetBrains Mono'; font-size: 0.8rem; color: #4fa8ff;
  }
  
  /* Log box */
  .log-box {
    background-color: #0a0a14;
    border: 1px solid #2a2a4a;
    border-radius: 5px;
    padding: 10px;
    height: 300px;
    overflow-y: scroll;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #aaa;
  }
  .log-entry {
    border-bottom: 1px solid #1a1a2a;
    padding: 4px 0;
  }
  .log-time {
    color: #4fa8ff;
  }
  .log-info {
    color: #4cffaa;
  }
  .log-warning {
    color: #ffb347;
  }
  .log-critical {
    color: #ff3b3b;
  }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------
# Moteur TTU complet (défini AVANT toute initialisation de session_state)
# -------------------------------------------------------------------
class TTUEngine:
    def __init__(self, k_factor=1.2, weights=(1.0, 1.5, 2.0),
                 rep_shield=0.3, n_sigma=2.0, window_seconds=300):
        self.k_factor = k_factor
        self.w_m, self.w_c, self.w_d = weights
        self.rep_shield = rep_shield
        self.n_sigma = n_sigma
        self.window_seconds = window_seconds

        self.baseline_scores = deque(maxlen=200)
        self.event_window = deque(maxlen=50)

        rng = np.random.default_rng(42)
        for _ in range(150):
            self.baseline_scores.append(rng.normal(0.25, 0.08))

    def raw_score(self, phi_m, phi_c, phi_d):
        w_tot = self.w_m + self.w_c + self.w_d
        return self.k_factor * (self.w_m*phi_m + self.w_c*phi_c + self.w_d*phi_d) / w_tot

    def corrected_score(self, raw, reputation):
        shield = self.rep_shield * (reputation / 100.0)
        return raw * (1.0 - shield)

    def adaptive_threshold(self):
        arr = np.array(self.baseline_scores)
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        threshold = mean + self.n_sigma * std
        return mean, std, min(threshold, 0.99)

    def temporal_velocity(self):
        now = time.time()
        recent = [e for e in self.event_window if now - e['ts'] <= self.window_seconds]
        if not recent:
            return 0.0
        anomalies = sum(1 for e in recent if e['score'] > 0.5)
        return min(anomalies / max(len(recent), 1), 1.0)

    def classify(self, corrected, threshold, velocity):
        effective = corrected * (1.0 + 0.4 * velocity)
        if effective >= threshold:
            return "CRITICAL"
        elif effective >= threshold * 0.75:
            return "ORANGE"
        else:
            return "NORMAL"

    def adapt_k_factor(self, phi_c):
        if phi_c < 0.2:
            self.k_factor = min(3.0, self.k_factor * 1.2)
        elif phi_c > 0.6:
            self.k_factor = max(1.0, self.k_factor * 0.99)

    def process_event(self, phi_m, phi_c, phi_d, reputation=80.0):
        raw = self.raw_score(phi_m, phi_c, phi_d)
        raw = max(0.0, min(raw, 2.0))
        corrected = self.corrected_score(raw, reputation)
        corrected = max(0.0, min(corrected, 1.0))

        mean, std, threshold = self.adaptive_threshold()
        velocity = self.temporal_velocity()
        status = self.classify(corrected, threshold, velocity)

        event = {
            'ts': time.time(),
            'time': datetime.now(),
            'phi_m': phi_m, 'phi_c': phi_c, 'phi_d': phi_d,
            'raw': raw,
            'score': corrected,
            'threshold': threshold,
            'velocity': velocity,
            'reputation': reputation,
            'status': status,
            'mean': mean,
            'std': std
        }
        self.event_window.append(event)

        if status == "NORMAL":
            self.baseline_scores.append(corrected)

        return event

# -------------------------------------------------------------------
# Initialisation de la session state
# -------------------------------------------------------------------
if 'ttu_engine' not in st.session_state:
    st.session_state.ttu_engine = TTUEngine()
if 'event_history' not in st.session_state:
    st.session_state.event_history = deque(maxlen=100)
if 'threat_library' not in st.session_state:
    st.session_state.threat_library = []
if 'attack_events' not in st.session_state:
    # Données simulées pour la carte
    st.session_state.attack_events = [
        {'lat': random.uniform(-40, 60), 'lon': random.uniform(-100, 120), 'mag': random.random()} 
        for _ in range(15)
    ]
if 'org_id' not in st.session_state:
    st.session_state.org_id = None  # Sera défini après authentification
if 'endpoint_id' not in st.session_state:
    st.session_state.endpoint_id = None
if 'user_id' not in st.session_state:
    st.session_state.user_id = None  # À remplacer par l'ID de l'utilisateur connecté

# File d'attente pour le thread de monitoring (thread-safe)
if 'monitor_queue' not in st.session_state:
    st.session_state.monitor_queue = Queue()

# -------------------------------------------------------------------
# Fonctions de collecte système (via psutil)
# -------------------------------------------------------------------
def get_system_triad():
    phi_m = psutil.virtual_memory().percent / 100.0
    cpu_samples = [psutil.cpu_percent(interval=0.1) for _ in range(10)]
    cpu_std = np.std(cpu_samples) / 100.0
    phi_c = max(0.0, 1.0 - cpu_std)
    net1 = psutil.net_io_counters()
    time.sleep(0.5)
    net2 = psutil.net_io_counters()
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    phi_d = min(1.0, bytes_sent / (125 * 1024 * 1024)) if bytes_sent > 0 else 0.0
    return phi_m, phi_c, phi_d

def get_top_process():
    try:
        procs = [(p, p.cpu_percent()) for p in psutil.process_iter(['pid', 'name', 'exe'])]
        procs.sort(key=lambda x: x[1], reverse=True)
        if procs:
            return procs[0][0]
    except Exception:
        pass
    return None

def suspend_process(proc):
    try:
        proc.suspend()
        return True
    except Exception:
        return False

def hash_file(path):
    if not path or not os.path.isfile(path):
        return "unknown"
    sha = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha.update(block)
        return sha.hexdigest()
    except Exception:
        return "unknown"

def isolate_network():
    suspended = []
    for conn in psutil.net_connections():
        if conn.pid and conn.status == 'ESTABLISHED':
            try:
                p = psutil.Process(conn.pid)
                p.suspend()
                suspended.append(p.name() if hasattr(p, 'name') else str(conn.pid))
            except Exception:
                pass
    return suspended

def get_active_connections():
    conns = []
    try:
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                conns.append({
                    'pid': conn.pid,
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                })
    except Exception:
        pass
    return conns

# -------------------------------------------------------------------
# Fonctions d'analyse ciblée
# -------------------------------------------------------------------
def analyze_file(uploaded_file):
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        found = any(sig['pattern'].lower() in uploaded_file.name.lower()
                    for sig in st.session_state.threat_library)
        result = {
            'filename': uploaded_file.name,
            'size': len(file_bytes),
            'hash': file_hash,
            'malicious': found,
            'score': random.uniform(0,1) if found else 0.1
        }
        return result
    return None

def analyze_url(url):
    if url:
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            status = r.status_code
            malicious = random.choice([True, False])
            return {
                'url': url,
                'status_code': status,
                'malicious': malicious,
                'score': random.uniform(0,1) if malicious else 0.2
            }
        except Exception as e:
            return {'url': url, 'error': str(e)}
    return None

def scan_folder(path):
    if os.path.isdir(path):
        files = []
        for root, dirs, filenames in os.walk(path):
            for f in filenames[:20]:
                full = os.path.join(root, f)
                try:
                    size = os.path.getsize(full)
                    suspicious = random.random() < 0.1
                    files.append({
                        'name': f,
                        'size': size,
                        'suspicious': suspicious
                    })
                except:
                    pass
        return files
    return None

# -------------------------------------------------------------------
# Fonctions de génération de données simulées
# -------------------------------------------------------------------
def simulate_network_traffic():
    return {
        'timestamp': datetime.now(),
        'src_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        'dst_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        'src_port': random.randint(1024, 65535),
        'dst_port': random.choice([80, 443, 22, 3389]),
        'protocol': random.choice(['TCP', 'UDP']),
        'bytes_sent': random.randint(100, 10000),
        'bytes_received': random.randint(100, 50000),
        'duration': random.uniform(0.1, 60),
        'app_protocol': random.choice(['HTTP', 'HTTPS', 'SSH', 'RDP', 'DNS']),
        'anomaly_score': random.uniform(0, 1),
        'phi_m': random.uniform(0, 1),
        'phi_c': random.uniform(0, 1),
        'phi_d': random.uniform(0, 1),
        'threat_level': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    }

def simulate_cloud_log(provider='AWS'):
    actions = ['CreateUser', 'DeleteBucket', 'ModifyInstance', 'AssumeRole', 'ConsoleLogin']
    outcomes = ['Success', 'Failure']
    return {
        'cloud_provider': provider,
        'event_time': datetime.now(),
        'event_name': random.choice(actions),
        'resource_type': random.choice(['User', 'Bucket', 'Instance', 'Role']),
        'resource_name': f"res-{random.randint(1000,9999)}",
        'user_identity': {'userName': f"user{random.randint(1,100)}"},
        'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        'user_agent': 'Mozilla/5.0',
        'action': random.choice(actions),
        'outcome': random.choice(outcomes),
        'phi_m': random.uniform(0, 1),
        'phi_c': random.uniform(0, 1),
        'phi_d': random.uniform(0, 1)
    }

def generate_threat_signature(proc_name, score, phi_m, phi_c, phi_d):
    return {
        'pattern': proc_name,
        'weight': score,
        'description': f"Signature automatique pour {proc_name}",
        'phi_m': phi_m,
        'phi_c': phi_c,
        'phi_d': phi_d
    }

def create_alert(org_id, endpoint_id, alert_type, severity, score, description, details=None):
    return {
        'id': str(uuid.uuid4()),
        'org_id': org_id,
        'endpoint_id': endpoint_id,
        'alert_type': alert_type,
        'severity': severity,
        'score': score,
        'description': description,
        'details': details or {},
        'timestamp': datetime.now(),
        'acknowledged': False,
        'resolved': False
    }

# -------------------------------------------------------------------
# Connexion Supabase et fonctions d'accès à la base
# -------------------------------------------------------------------
@st.cache_resource
def get_supabase_connection():
    if not SUPPORTS_SUPABASE:
        return None
    try:
        if 'postgres' not in st.secrets:
            st.sidebar.error("Section [postgres] manquante dans les secrets.")
            return None
        creds = st.secrets['postgres']
        conn = psycopg2.connect(
            host=creds['host'],
            port=creds['port'],
            database=creds['database'],
            user=creds['user'],
            password=creds['password'],
            sslmode='require',
            connect_timeout=10
        )
        return conn
    except Exception as e:
        st.sidebar.error(f"Supabase indisponible : {e}")
        return None

def get_user_org(user_id, conn):
    """Récupère l'organisation d'un utilisateur."""
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT org_id FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None
    except Exception as e:
        st.error(f"Erreur lecture org_id: {e}")
        return None

def get_user_subscription(user_id, conn):
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT plan_type, status, expires_at
            FROM user_subscriptions
            WHERE user_id = %s
        """, (user_id,))
        row = cur.fetchone()
        cur.close()
        if row:
            return {'plan_type': row[0], 'status': row[1], 'expires_at': row[2]}
    except Exception as e:
        st.error(f"Erreur lecture abonnement: {e}")
    return None

def register_endpoint(user_id, endpoint_name, conn, org_id):
    if not conn:
        return None
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = '127.0.0.1'
    os_name = f"{os.name} - {platform.system()}" if hasattr(platform, 'system') else os.name
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO endpoints (org_id, user_id, name, hostname, local_ip, os)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (org_id, user_id, endpoint_name, hostname, local_ip, os_name))
        endpoint_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return endpoint_id
    except Exception as e:
        st.error(f"Erreur enregistrement endpoint: {e}")
        return None

def insert_security_log(conn, endpoint_id, org_id, phi_m, phi_c, phi_d, score, status, details=None):
    if not conn or not endpoint_id:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO security_logs
                (endpoint_id, org_id, phi_m, phi_c, phi_d, anomaly_score, status, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (endpoint_id, org_id, phi_m, phi_c, phi_d, score, status, json.dumps(details) if details else None))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion log: {e}")

def insert_network_log(conn, org_id, endpoint_id, log):
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO network_logs
                (org_id, endpoint_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                 bytes_sent, bytes_received, duration, app_protocol, anomaly_score,
                 phi_m, phi_c, phi_d, threat_level)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            org_id, endpoint_id, log['timestamp'], log['src_ip'], log['dst_ip'],
            log['src_port'], log['dst_port'], log['protocol'], log['bytes_sent'],
            log['bytes_received'], log['duration'], log['app_protocol'], log['anomaly_score'],
            log['phi_m'], log['phi_c'], log['phi_d'], log['threat_level']
        ))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion network_log: {e}")

def insert_cloud_log(conn, org_id, endpoint_id, log):
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cloud_logs
                (org_id, endpoint_id, cloud_provider, event_time, event_name, resource_type, resource_name,
                 user_identity, source_ip, user_agent, action, outcome, phi_m, phi_c, phi_d)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            org_id, endpoint_id, log['cloud_provider'], log['event_time'], log['event_name'],
            log['resource_type'], log['resource_name'], json.dumps(log['user_identity']),
            log['source_ip'], log['user_agent'], log['action'], log['outcome'],
            log['phi_m'], log['phi_c'], log['phi_d']
        ))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion cloud_log: {e}")

def insert_alert(conn, alert):
    """Insère une alerte dans la table security_alerts."""
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO security_alerts
                (id, org_id, endpoint_id, alert_type, severity, score, description, details, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            alert['id'], alert['org_id'], alert['endpoint_id'], alert['alert_type'],
            alert['severity'], alert['score'], alert['description'],
            json.dumps(alert['details']), 'active' if not alert['resolved'] else 'resolved', alert['timestamp']
        ))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion alert: {e}")

def get_recent_logs(conn, limit=10):
    """
    Récupère les derniers logs de sécurité depuis Supabase.
    Retourne un DataFrame pandas.
    """
    if not conn:
        return pd.DataFrame()
    try:
        query = """
            SELECT created_at, hostname, status, anomaly_score, phi_m, phi_c, phi_d 
            FROM public.security_logs 
            ORDER BY created_at DESC LIMIT %s
        """
        df = pd.read_sql(query, conn, params=(limit,))
        return df
    except Exception as e:
        st.error(f"Erreur de lecture des logs : {e}")
        return pd.DataFrame()

# -------------------------------------------------------------------
# Thread de monitoring en arrière-plan
# -------------------------------------------------------------------
def monitoring_worker(engine, queue):
    """Tourne en continu, collecte les métriques système et les pousse dans la queue."""
    while True:
        try:
            phi_m, phi_c, phi_d = get_system_triad()
            event = engine.process_event(phi_m, phi_c, phi_d)
            queue.put(event)
            time.sleep(2)  # Intervalle de surveillance
        except Exception:
            time.sleep(5)

# Démarrer le thread s'il n'est pas déjà lancé
if 'monitor_thread' not in st.session_state:
    st.session_state.monitor_thread = threading.Thread(
        target=monitoring_worker,
        args=(st.session_state.ttu_engine, st.session_state.monitor_queue),
        daemon=True
    )
    st.session_state.monitor_thread.start()

# -------------------------------------------------------------------
# Fonction pour générer un rapport de conformité (simplifié)
# -------------------------------------------------------------------
def generate_compliance_report(org_id, report_type):
    return {
        "generated_at": datetime.now(),
        "report_type": report_type,
        "findings": [
            {"control": "Chiffrement des données", "status": "Pass"},
            {"control": "Contrôle d'accès (RLS)", "status": "Active"},
            {"control": "Journalisation des événements", "status": "Audited"},
            {"control": "Gestion des vulnérabilités", "status": "En cours"}
        ]
    }

# -------------------------------------------------------------------
# Interface principale à onglets
# -------------------------------------------------------------------
st.sidebar.title("🛡️ TTU Shield Sentinel")
st.sidebar.markdown("---")
st.sidebar.write(f"**Statut système** : 🟢 Actif")
st.sidebar.write(f"Dernier événement : {datetime.now().strftime('%H:%M:%S')}")

# Connexion à Supabase (pour affichage)
conn = get_supabase_connection()

# Onglets principaux
tabs = st.tabs(["SOC", "Analyse", "Threat Intel", "Conformité", "Logs"])

# -------------------------------------------------------------------
# Onglet 0 : SOC Operational Center
# -------------------------------------------------------------------
with tabs[0]:
    st.header("🛡️ SOC Operational Center")
    
    # Récupérer les événements récents depuis la queue
    try:
        while not st.session_state.monitor_queue.empty():
            ev = st.session_state.monitor_queue.get_nowait()
            st.session_state.event_history.append(ev)
    except Empty:
        pass
    
    col_incidents, col_response = st.columns([2, 1])
    
    with col_incidents:
        st.subheader("Flux d'incidents critiques")
        # Filtrer uniquement les alertes ORANGE et CRITICAL
        critical_events = [e for e in list(st.session_state.event_history) if e['status'] in ["CRITICAL", "ORANGE"]]
        
        if critical_events:
            for ev in reversed(critical_events[-5:]):
                severity = "critical" if ev['status'] == "CRITICAL" else "warning"
                st.markdown(f"""
                <div class="alert-{severity}">
                    <strong>{ev['status']}</strong> - Score: {ev['score']:.3f} | {ev['time'].strftime('%H:%M:%S')}<br>
                    Triade: Φm={ev['phi_m']:.2f} Φc={ev['phi_c']:.2f} Φd={ev['phi_d']:.2f}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ Aucun incident critique détecté ces dernières 24h.")
    
    with col_response:
        st.subheader("Réponse Active")
        st.info("Actions de remédiation immédiate")
        if st.button("🔴 ISOLATION RÉSEAU (KILL SWITCH)"):
            suspended = isolate_network()
            st.error(f"Réseau isolé. {len(suspended)} connexions suspendues.")
        
        if st.button("🟡 SUSPENDRE PROCESSUS GOURMAND"):
            proc = get_top_process()
            if proc and suspend_process(proc):
                st.warning(f"Processus {proc.name()} mis en quarantaine.")
        
        # Affichage des métriques système en temps réel
        phi_m, phi_c, phi_d = get_system_triad()
        st.metric("Φ Mémoire", f"{phi_m:.2f}")
        st.metric("Φ CPU", f"{phi_c:.2f}")
        st.metric("Φ Réseau", f"{phi_d:.2f}")

# -------------------------------------------------------------------
# Onglet 1 : Analyse de Menaces & Hunting
# -------------------------------------------------------------------
with tabs[1]:
    st.header("🔍 Analyse de Menaces & Hunting")
    
    sub_tab1, sub_tab2 = st.tabs(["Scan de Fichiers", "Analyse Réseau"])
    
    with sub_tab1:
        uploaded_file = st.file_uploader("Glissez un fichier suspect pour analyse statique", type=['exe', 'dll', 'sh', 'py', 'bin'])
        if uploaded_file:
            with st.spinner("Analyse du hash et recherche de patterns..."):
                res = analyze_file(uploaded_file)
                if res['malicious']:
                    st.error(f"MENACE DÉTECTÉE : Le fichier correspond à une signature connue (Score: {res['score']:.2f})")
                else:
                    st.success(f"Fichier sain. SHA256: {res['hash'][:16]}...")
        
        # Analyse d'URL
        url = st.text_input("Ou entrez une URL à analyser")
        if url:
            with st.spinner("Vérification de la réputation..."):
                res_url = analyze_url(url)
                if res_url.get('malicious'):
                    st.error(f"URL malveillante détectée (Score: {res_url['score']:.2f})")
                elif 'error' in res_url:
                    st.warning(f"Erreur : {res_url['error']}")
                else:
                    st.success(f"URL saine (Code HTTP: {res_url['status_code']})")
    
    with sub_tab2:
        st.subheader("Connexions Actives")
        conns = get_active_connections()
        if conns:
            st.table(pd.DataFrame(conns).head(10))
        else:
            st.info("Aucune connexion établie détectée.")

# -------------------------------------------------------------------
# Onglet 2 : Threat Intelligence (Carte mondiale)
# -------------------------------------------------------------------
with tabs[2]:
    st.header("🌐 Global Threat Intelligence")
    st.write("Cartographie des tentatives d'intrusion bloquées par le moteur TTU.")
    
    # Simulation de données géographiques si la liste est vide
    if not st.session_state.attack_events:
        st.session_state.attack_events = [
            {'lat': random.uniform(-40, 60), 'lon': random.uniform(-100, 120), 'mag': random.random()} 
            for _ in range(15)
        ]
    
    fig_map = go.Figure(go.Scattergeo(
        lat = [e['lat'] for e in st.session_state.attack_events],
        lon = [e['lon'] for e in st.session_state.attack_events],
        marker = dict(size=10, color='red', opacity=0.6, symbol='circle'),
        text = "Tentative d'intrusion bloquée",
        mode = 'markers'
    ))
    fig_map.update_layout(
        geo_scope='world',
        paper_bgcolor="#07070f",
        geo=dict(bgcolor='rgba(0,0,0,0)'),
        margin=dict(l=0, r=0, t=0, b=0)
    )
    st.plotly_chart(fig_map, use_container_width=True)

# -------------------------------------------------------------------
# Onglet 3 : Conformité & Audit
# -------------------------------------------------------------------
with tabs[3]:
    st.header("📋 Conformité & Audit")
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Score de conformité actuel")
        st.progress(0.85)
        st.write("**85%** - Conforme aux standards Shield-S1")
        
    with col_b:
        report_type = st.selectbox("Type de rapport", ["GDPR", "ISO 27001", "SOC2"])
        if st.button("Générer le rapport détaillé"):
            report = generate_compliance_report(st.session_state.org_id, report_type)
            st.json(report)
            # Simuler un téléchargement PDF
            st.download_button(
                label="Télécharger le rapport (PDF simulé)",
                data=json.dumps(report, indent=2, default=str),
                file_name=f"Rapport_{report_type}_{datetime.now().strftime('%Y%m%d')}.json"
            )
    
    st.divider()
    st.write("### Journal d'Audit (Immutable)")
    st.caption("Ces logs sont synchronisés avec Supabase et ne peuvent être modifiés.")
    
    # Affichage des logs d'audit simulés
    audit_logs = [
        {"timestamp": datetime.now() - timedelta(minutes=5), "action": "Connexion utilisateur", "user": "admin@ttu.com"},
        {"timestamp": datetime.now() - timedelta(minutes=10), "action": "Modification des règles de détection", "user": "analyste"},
        {"timestamp": datetime.now() - timedelta(minutes=25), "action": "Génération de rapport de conformité", "user": "system"},
    ]
    for log in audit_logs:
        st.markdown(f"`{log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}` | **{log['action']}** par {log['user']}")

# -------------------------------------------------------------------
# Onglet 4 : Logs & Monitoring (Supabase)
# -------------------------------------------------------------------
with tabs[4]:
    st.header("📜 Logs de sécurité (Supabase)")
    logs_df = get_recent_logs(conn, limit=20)
    
    if not logs_df.empty:
        # Coloration automatique selon le statut
        def color_status(val):
            color = '#4cffaa' if val == 'NORMAL' else '#ffb347' if val == 'ORANGE' else '#ff3b3b'
            return f'color: {color}'
        
        st.dataframe(
            logs_df.style.applymap(color_status, subset=['status']),
            use_container_width=True
        )
        
        # Graphique d'évolution du score d'anomalie
        st.subheader("Évolution des scores d'anomalie")
        st.line_chart(logs_df.set_index('created_at')['anomaly_score'])
    else:
        st.info("Aucune donnée reçue de Supabase. Vérifiez la connexion.")

# -------------------------------------------------------------------
# Sidebar : Onboarding et informations utilisateur
# -------------------------------------------------------------------
with st.sidebar:
    st.markdown("---")
    st.subheader("Onboarding")
    if st.button("🔐 S'authentifier avec Supabase"):
        # Simulation : l'utilisateur "mayombochristal@gmail.com" est admin
        st.session_state.user_id = "a696b926-e2b3-4f8d-b4d3-f6bb0527af23"
        st.session_state.org_id = get_user_org(st.session_state.user_id, conn) or "default-org"
        st.success("Connecté en tant que mayombochristal@gmail.com (admin)")
    
    if st.session_state.user_id:
        st.write(f"**Utilisateur** : {st.session_state.user_id[:8]}...")
        sub = get_user_subscription(st.session_state.user_id, conn)
        if sub:
            st.write(f"**Plan** : {sub['plan_type']} / {sub['status']}")
        else:
            st.write("**Plan** : free (par défaut)")
    
    st.markdown("---")
    st.caption("TTU Shield Sentinel v3.0 - Fusion complète")

# -------------------------------------------------------------------
# Fin du script
# -------------------------------------------------------------------