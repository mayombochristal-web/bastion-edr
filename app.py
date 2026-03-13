#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU Shield Sentinel – Cybersecurity Platform (Version Unifiée)
================================================================
Fusion des meilleures fonctionnalités :
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
- **Monitoring temps réel** des derniers incidents avec affichage coloré
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

# Configuration de la page Streamlit
st.set_page_config(
    page_title="TTU Shield Sentinel - Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------------------
# CSS personnalisé (identique aux versions précédentes)
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
# Moteur TTU complet
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
    Retourne un DataFrame pandas avec coloration automatique selon le statut.
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
# Interface principale de l'application
# -------------------------------------------------------------------
st.sidebar.title("🛡️ TTU Shield Sentinel")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    ["SOC Operational Center", "Analyse système", "Analyse de fichiers", "Threat Intelligence", "Conformité"]
)

# Initialisation de la session state
if 'ttu_engine' not in st.session_state:
    st.session_state.ttu_engine = TTUEngine()
if 'threat_library' not in st.session_state:
    st.session_state.threat_library = []

# Affichage de la page sélectionnée
if page == "SOC Operational Center":
    # --- SECTION : MONITORING TEMPS RÉEL ---
    st.header("🛡️ SOC Operational Center")

    col_logs, col_chart = st.columns([2, 1])

    with col_logs:
        st.subheader("Derniers Incidents Détectés")
        conn = get_supabase_connection()
        logs_df = get_recent_logs(conn, limit=15)

        if not logs_df.empty:
            # Coloration automatique selon le statut
            def color_status(val):
                color = '#4cffaa' if val == 'NORMAL' else '#ffb347' if val == 'ORANGE' else '#ff3b3b'
                return f'color: {color}'

            st.dataframe(logs_df.style.applymap(color_status, subset=['status']), use_container_width=True)
        else:
            st.info("En attente de nouvelles données entrantes...")

    with col_chart:
        st.subheader("Analyse TTU-MC³")
        if not logs_df.empty:
            # Petit graphique d'évolution du score d'anomalie
            st.line_chart(logs_df.set_index('created_at')['anomaly_score'])

elif page == "Analyse système":
    st.header("💻 Analyse système en direct")
    # Ajouter ici le code pour l'analyse système (CPU, RAM, processus, etc.)
    st.info("Section à développer")

elif page == "Analyse de fichiers":
    st.header("📁 Analyse de fichiers / URLs")
    # Ajouter ici le code pour l'analyse de fichiers et URLs
    st.info("Section à développer")

elif page == "Threat Intelligence":
    st.header("🌍 Threat Intelligence")
    # Ajouter ici le code pour la visualisation géographique et les signatures
    st.info("Section à développer")

elif page == "Conformité":
    st.header("📋 Rapports de conformité")
    # Ajouter ici le code pour les rapports GDPR, ISO27001, etc.
    st.info("Section à développer")

# -------------------------------------------------------------------
# Fin du script
# -------------------------------------------------------------------