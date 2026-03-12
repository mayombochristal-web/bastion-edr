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
- Connexion optionnelle à Supabase pour persistance
- Onboarding et gestion d'abonnement simplifiés (démonstration)
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
# CSS personnalisé (fusion des styles précédents)
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
  
  /* Log box (issu de app (23)) */
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
# Moteur TTU complet (avec vélocité temporelle, réputation, seuil adaptatif)
# -------------------------------------------------------------------
class TTUEngine:
    """
    Moteur de calcul du score d'anomalie TTU-MC³.
    Inclut la vélocité temporelle et le bouclier réputation.
    """
    def __init__(self, k_factor=1.2, weights=(1.0, 1.5, 2.0),
                 rep_shield=0.3, n_sigma=2.0, window_seconds=300):
        self.k_factor = k_factor
        self.w_m, self.w_c, self.w_d = weights
        self.rep_shield = rep_shield      # force du bouclier réputation
        self.n_sigma = n_sigma            # nb d'écarts-types pour le seuil
        self.window_seconds = window_seconds

        self.baseline_scores = deque(maxlen=200)
        self.event_window = deque(maxlen=50)   # événements récents

        # Baseline pré-chargée (phase d'apprentissage simulée)
        rng = np.random.default_rng(42)
        for _ in range(150):
            self.baseline_scores.append(rng.normal(0.25, 0.08))

    def raw_score(self, phi_m: float, phi_c: float, phi_d: float) -> float:
        w_tot = self.w_m + self.w_c + self.w_d
        return self.k_factor * (self.w_m*phi_m + self.w_c*phi_c + self.w_d*phi_d) / w_tot

    def corrected_score(self, raw: float, reputation: float) -> float:
        shield = self.rep_shield * (reputation / 100.0)
        return raw * (1.0 - shield)

    def adaptive_threshold(self):
        arr = np.array(self.baseline_scores)
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        threshold = mean + self.n_sigma * std
        return mean, std, min(threshold, 0.99)

    def temporal_velocity(self) -> float:
        now = time.time()
        recent = [e for e in self.event_window if now - e['ts'] <= self.window_seconds]
        if not recent:
            return 0.0
        anomalies = sum(1 for e in recent if e['score'] > 0.5)
        return min(anomalies / max(len(recent), 1), 1.0)

    def classify(self, corrected: float, threshold: float, velocity: float) -> str:
        effective = corrected * (1.0 + 0.4 * velocity)
        if effective >= threshold:
            return "CRITICAL"
        elif effective >= threshold * 0.75:
            return "ORANGE"
        else:
            return "NORMAL"

    def adapt_k_factor(self, phi_c: float):
        """Adaptation du K-factor en fonction de la cohérence (app (21))."""
        if phi_c < 0.2:
            self.k_factor = min(3.0, self.k_factor * 1.2)
        elif phi_c > 0.6:
            self.k_factor = max(1.0, self.k_factor * 0.99)

    def process_event(self, phi_m, phi_c, phi_d, reputation=80.0) -> dict:
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
    """Suspension des processus avec connexions établies (simplifié)."""
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
# Fonctions d'analyse ciblée (app (22))
# -------------------------------------------------------------------
def analyze_file(uploaded_file):
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        # Vérification basique dans la threat library (simulée)
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
            malicious = random.choice([True, False])  # simulé
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
                    suspicious = random.random() < 0.1  # simulé
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
# Fonctions de génération de données simulées (pour démo si besoin)
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
# Connexion Supabase (optionnelle)
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

def register_endpoint(user_id, endpoint_name, conn):
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
            INSERT INTO endpoints (user_id, name, hostname, local_ip, os)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (user_id, endpoint_name, hostname, local_ip, os_name))
        endpoint_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return endpoint_id
    except Exception as e:
        st.error(f"Erreur enregistrement endpoint: {e}")
        return None

def insert_security_log(conn, endpoint_id, phi_m, phi_c, phi_d, score, status, details=None):
    if not conn or not endpoint_id:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO security_logs
                (endpoint_id, phi_m, phi_c, phi_d, anomaly_score, status, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (endpoint_id, phi_m, phi_c, phi_d, score, status, json.dumps(details) if details else None))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion log: {e}")

# -------------------------------------------------------------------
# File d'attente pour logs thread-safe
# -------------------------------------------------------------------
log_queue = Queue()

def add_log(message, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_queue.put({
        'time': timestamp,
        'level': level,
        'message': message
    })

# -------------------------------------------------------------------
# Thread de monitoring
# -------------------------------------------------------------------
def monitoring_loop(engine, stop_event, conn, endpoint_id, log_queue):
    add_log("Démarrage de la surveillance système...", "INFO")
    while not stop_event.is_set():
        try:
            phi_m, phi_c, phi_d = get_system_triad()
            engine.adapt_k_factor(phi_c)
            # Pour la réputation, on peut prendre une valeur par défaut ou depuis l'utilisateur
            reputation = 80  # valeur par défaut
            result = engine.process_event(phi_m, phi_c, phi_d, reputation)

            add_log(f"Φm={phi_m:.2f} Φc={phi_c:.2f} Φd={phi_d:.2f} | Score={result['score']:.3f} ({result['status']})", "INFO")

            if conn and endpoint_id:
                insert_security_log(conn, endpoint_id, phi_m, phi_c, phi_d, result['score'], result['status'])

            if result['status'] == "CRITICAL":
                proc = get_top_process()
                if proc:
                    proc_name = proc.name() if hasattr(proc, 'name') else "inconnu"
                    proc_path = proc.exe() if hasattr(proc, 'exe') else None
                    suspend_process(proc)
                    isolate_network()
                    add_log(f"⚠️ Processus critique suspendu : {proc_name}", "CRITICAL")
                    # Créer une alerte locale
                    alert = create_alert(
                        st.session_state.org_id,
                        endpoint_id,
                        'endpoint_malware',
                        'HIGH',
                        result['score'],
                        f"Processus malveillant suspendu : {proc_name}",
                        {'process': proc_name, 'path': proc_path}
                    )
                    st.session_state.alerts.append(alert)
                    # Ajouter à la threat library
                    sig = generate_threat_signature(proc_name, result['score'], phi_m, phi_c, phi_d)
                    st.session_state.threat_library.append(sig)
                    # Ajouter un point sur la carte
                    lat = random.uniform(-60, 70)
                    lon = random.uniform(-180, 180)
                    st.session_state.attack_events.append({'lat': lat, 'lon': lon})

            # Simuler des logs réseau/cloud de temps en temps
            if random.random() < 0.2:
                net_log = simulate_network_traffic()
                st.session_state.network_logs.append(net_log)
            if random.random() < 0.1:
                cloud_log = simulate_cloud_log()
                st.session_state.cloud_logs.append(cloud_log)

            time.sleep(2)
        except Exception as e:
            add_log(f"Erreur dans la boucle : {e}", "CRITICAL")
            time.sleep(5)

# -------------------------------------------------------------------
# Fonctions de contrôle du thread
# -------------------------------------------------------------------
def start_monitoring(engine, conn, endpoint_id):
    if st.session_state.get('monitoring_active', False):
        return
    st.session_state.monitoring_active = True
    stop_event = threading.Event()
    st.session_state.stop_event = stop_event
    thread = threading.Thread(
        target=monitoring_loop,
        args=(engine, stop_event, conn, endpoint_id, log_queue),
        daemon=True
    )
    thread.start()
    st.session_state.monitor_thread = thread
    add_log("Surveillance activée.", "INFO")

def stop_monitoring():
    if st.session_state.get('monitoring_active', False):
        st.session_state.stop_event.set()
        st.session_state.monitoring_active = False
        st.session_state.monitor_thread = None
        add_log("Surveillance désactivée.", "INFO")

# -------------------------------------------------------------------
# Graphiques (issus des versions précédentes)
# -------------------------------------------------------------------
def plot_gauge(value, color):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        gauge={
            'axis': {'range': [0, 1], 'tickcolor': 'white'},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 0.5], 'color': "#1a1a2e"},
                {'range': [0.5, 0.75], 'color': "#2a1a2e"},
                {'range': [0.75, 1], 'color': "#3a1a2e"}
            ]
        },
        number={'font': {'color': color, 'size': 40}}
    ))
    fig.update_layout(height=250, margin=dict(l=10, r=10, t=10, b=10),
                      paper_bgcolor='#0d0d1a', font={'color': 'white'})
    return fig

def plot_cyber_map(events):
    if not events:
        return go.Figure()
    lats = [e['lat'] for e in events]
    lons = [e['lon'] for e in events]
    fig = go.Figure()
    fig.add_trace(go.Scattergeo(
        lat=lats,
        lon=lons,
        mode='markers',
        marker=dict(size=8, color='red', symbol='circle'),
        name='Menaces'
    ))
    fig.update_layout(
        geo=dict(projection_type='natural earth'),
        height=350,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor='#0d0d1a',
        font=dict(color='#888')
    )
    return fig

# -------------------------------------------------------------------
# Initialisation de la session
# -------------------------------------------------------------------
if 'engine' not in st.session_state:
    st.session_state.engine = TTUEngine(k_factor=1.2, weights=(1.0, 1.5, 2.0), n_sigma=2.0)

if 'endpoint_history' not in st.session_state:
    st.session_state.endpoint_history = []   # Pour compatibilité, mais on utilisera surtout les logs

if 'network_logs' not in st.session_state:
    st.session_state.network_logs = []

if 'cloud_logs' not in st.session_state:
    st.session_state.cloud_logs = []

if 'alerts' not in st.session_state:
    st.session_state.alerts = []

if 'threat_library' not in st.session_state:
    st.session_state.threat_library = []

if 'attack_events' not in st.session_state:
    st.session_state.attack_events = []

if 'conn' not in st.session_state:
    st.session_state.conn = get_supabase_connection()

if 'user_id' not in st.session_state:
    st.session_state.user_id = "a696b926-eb23-4f8d-b4d3-f6bb0527a2f3"  # UUID de test

if 'subscription' not in st.session_state:
    st.session_state.subscription = get_user_subscription(st.session_state.user_id, st.session_state.conn)

if 'onboarding_done' not in st.session_state:
    st.session_state.onboarding_done = False

if 'endpoint_id' not in st.session_state:
    st.session_state.endpoint_id = None

if 'org_id' not in st.session_state:
    st.session_state.org_id = "00000000-0000-0000-0000-000000000001"  # Pour les alertes

if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False

if 'log_messages' not in st.session_state:
    st.session_state.log_messages = []

# -------------------------------------------------------------------
# Interface principale
# -------------------------------------------------------------------
st.title("🛡️ TTU Shield Sentinel – Cybersecurity Platform (Unifiée)")
st.caption("Fusion des versions : moteur mathématique, surveillance réelle, analyse ciblée, réponse active, SOC, conformité.")

# -------------------------------------------------------------------
# Onboarding / Abonnement simplifié
# -------------------------------------------------------------------
if st.session_state.subscription is None and not st.session_state.onboarding_done:
    st.markdown("""
    <div style="text-align: center; padding: 2rem;">
        <h2>Bienvenue sur TTU Shield Sentinel</h2>
        <p>Pour commencer, vous pouvez utiliser un code d'invitation ou passer en mode démo.</p>
    </div>
    """, unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        code = st.text_input("Code d'invitation (optionnel)", placeholder="XXXX-XXXX")
        if st.button("Activer avec code"):
            if code == "DEMO2025":
                st.session_state.subscription = {'plan_type': 'DEMO', 'status': 'active'}
                st.rerun()
            else:
                st.error("Code invalide.")
    with col2:
        if st.button("Continuer en mode démo"):
            st.session_state.subscription = {'plan_type': 'DEMO', 'status': 'active'}
            st.rerun()
    st.stop()

if not st.session_state.onboarding_done and st.session_state.subscription:
    st.markdown("---")
    st.subheader("📋 Configuration initiale")
    endpoint_name = st.text_input("Nom de cet endpoint", placeholder="Mon-PC")
    if st.button("Démarrer la surveillance"):
        if endpoint_name:
            if st.session_state.conn:
                endpoint_id = register_endpoint(st.session_state.user_id, endpoint_name, st.session_state.conn)
                if endpoint_id:
                    st.session_state.endpoint_id = endpoint_id
            else:
                # Mode démo : on génère un faux endpoint_id
                st.session_state.endpoint_id = str(uuid.uuid4())
            st.session_state.onboarding_done = True
            add_log(f"Endpoint '{endpoint_name}' enregistré.", "INFO")
            st.rerun()
        else:
            st.warning("Veuillez saisir un nom.")
    st.stop()

# -------------------------------------------------------------------
# Affichage des logs en temps réel (depuis la queue)
# -------------------------------------------------------------------
while not log_queue.empty():
    try:
        log = log_queue.get_nowait()
        st.session_state.log_messages.append(log)
    except Empty:
        break
if len(st.session_state.log_messages) > 200:
    st.session_state.log_messages = st.session_state.log_messages[-200:]

# -------------------------------------------------------------------
# Sidebar avec infos et contrôles
# -------------------------------------------------------------------
with st.sidebar:
    st.markdown("## ⬡ TTU Shield Sentinel")
    st.markdown("---")
    if st.session_state.monitoring_active:
        if st.button("🛑 DÉSACTIVER LA SURVEILLANCE", use_container_width=True):
            stop_monitoring()
            st.rerun()
    else:
        if st.button("🛡️ ACTIVER LA SURVEILLANCE", use_container_width=True, type="primary"):
            start_monitoring(st.session_state.engine, st.session_state.conn, st.session_state.endpoint_id)
            st.rerun()

    st.markdown("---")
    st.markdown("### 📊 Statut")
    if st.session_state.conn:
        st.success("✅ Supabase connecté")
    else:
        st.warning("⚠️ Supabase non connecté (mode démo)")

    st.markdown(f"**Utilisateur** : {st.session_state.user_id[:8]}...")
    if st.session_state.subscription:
        st.markdown(f"**Abonnement** : `{st.session_state.subscription['plan_type']}`")
    if st.session_state.endpoint_id:
        st.markdown(f"**Endpoint ID** : {st.session_state.endpoint_id[:8]}...")

    st.markdown("---")
    if st.button("🗑 Réinitialiser données locales", use_container_width=True):
        st.session_state.network_logs = []
        st.session_state.cloud_logs = []
        st.session_state.alerts = []
        st.session_state.threat_library = []
        st.session_state.attack_events = []
        st.session_state.log_messages = []
        st.rerun()

    if st.button("Se déconnecter", use_container_width=True):
        st.session_state.subscription = None
        st.session_state.onboarding_done = False
        st.session_state.endpoint_id = None
        stop_monitoring()
        st.rerun()

# -------------------------------------------------------------------
# Onglets principaux
# -------------------------------------------------------------------
tabs = st.tabs(["📊 Dashboard", "🖥️ Endpoint", "🌐 Réseau", "☁️ Cloud", "🧠 Threat Intel", "🚨 SOC", "📋 Conformité", "🌍 Carte", "🔍 Analyse ciblée", "📜 Logs"])

# --- Dashboard ---
with tabs[0]:
    st.subheader("Vue d'ensemble")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Endpoints surveillés", "1 (local)")
    with col2:
        st.metric("Alertes (24h)", len([a for a in st.session_state.alerts if a['timestamp'] > datetime.now()-timedelta(days=1)]))
    with col3:
        st.metric("Menaces bloquées", len(st.session_state.attack_events))
    with col4:
        # Dernier statut (depuis le dernier événement du thread)
        if st.session_state.log_messages:
            last_log = st.session_state.log_messages[-1]
            if "CRITICAL" in last_log['level']:
                status = "CRITICAL"
            elif "WARNING" in last_log['level']:
                status = "ORANGE"
            else:
                status = "NORMAL"
            st.metric("Statut global", status)
        else:
            st.metric("Statut global", "N/A")

    # Graphique des scores depuis security_logs (si connecté) ou depuis logs simulés
    if st.session_state.conn and st.session_state.endpoint_id:
        try:
            cur = st.session_state.conn.cursor()
            cur.execute("""
                SELECT created_at, anomaly_score, status
                FROM security_logs
                WHERE endpoint_id = %s
                ORDER BY created_at DESC
                LIMIT 100
            """, (st.session_state.endpoint_id,))
            rows = cur.fetchall()
            cur.close()
            if rows:
                df = pd.DataFrame(rows, columns=['time', 'score', 'status'])
                df = df.sort_values('time')
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=df['time'], y=df['score'], mode='lines+markers', name='Score'))
                fig.update_layout(height=300, plot_bgcolor='#07070f', paper_bgcolor='#0d0d1a')
                st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.error(f"Erreur lecture historique: {e}")
    else:
        st.info("Aucune donnée historique. Activez la surveillance pour commencer.")

# --- Endpoint (détails) ---
with tabs[1]:
    st.subheader("🖥️ Surveillance Endpoint")
    if st.session_state.monitoring_active:
        # Afficher les dernières métriques via un rafraîchissement manuel
        if st.button("🔄 Rafraîchir les métriques"):
            with st.spinner("Collecte..."):
                phi_m, phi_c, phi_d = get_system_triad()
                st.metric("Mémoire (Φm)", f"{phi_m:.2f}")
                st.metric("Cohérence (Φc)", f"{phi_c:.2f}")
                st.metric("Dissipation (Φd)", f"{phi_d:.2f}")
        # Afficher le dernier événement traité (via le thread)
        # On peut aussi afficher le dernier log
        if st.session_state.log_messages:
            last = st.session_state.log_messages[-1]
            st.info(f"Dernier événement : {last['message']}")
    else:
        st.info("La surveillance est désactivée. Activez-la dans la sidebar.")

# --- Réseau ---
with tabs[2]:
    st.subheader("🌐 Surveillance Réseau")
    if st.session_state.network_logs:
        df_net = pd.DataFrame(st.session_state.network_logs[-50:])
        st.dataframe(df_net[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'threat_level']].tail(20),
                     use_container_width=True, hide_index=True)
        threat_counts = df_net['threat_level'].value_counts()
        fig = go.Figure(data=[go.Bar(x=threat_counts.index, y=threat_counts.values)])
        fig.update_layout(plot_bgcolor='#07070f', paper_bgcolor='#0d0d1a')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Aucun log réseau pour l'instant.")

# --- Cloud ---
with tabs[3]:
    st.subheader("☁️ Surveillance Cloud")
    if st.session_state.cloud_logs:
        df_cloud = pd.DataFrame(st.session_state.cloud_logs[-50:])
        st.dataframe(df_cloud[['event_time', 'cloud_provider', 'event_name', 'resource_type', 'outcome']].tail(20),
                     use_container_width=True, hide_index=True)
    else:
        st.info("Aucun log cloud.")

# --- Threat Intelligence ---
with tabs[4]:
    st.subheader("🧠 Bibliothèque des Menaces")
    if st.session_state.threat_library:
        df_threat = pd.DataFrame(st.session_state.threat_library)
        st.dataframe(df_threat, use_container_width=True)
    else:
        st.info("Aucune signature.")
    if st.button("➕ Ajouter une signature exemple"):
        sig = generate_threat_signature("exemple.exe", 0.9, 0.8, 0.2, 0.9)
        st.session_state.threat_library.append(sig)
        st.rerun()

# --- SOC ---
with tabs[5]:
    st.subheader("🚨 Centre d'Opérations de Sécurité")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Alertes actives", len([a for a in st.session_state.alerts if not a.get('resolved', False)]))
    with col2:
        st.metric("Incidents", len(st.session_state.alerts)//2)  # simulé

    if st.session_state.alerts:
        st.write("**Dernières alertes**")
        df_alert = pd.DataFrame([
            {k: v for k, v in a.items() if k not in ['details', 'org_id', 'endpoint_id']}
            for a in st.session_state.alerts[-10:]
        ])
        st.dataframe(df_alert, use_container_width=True)

    if st.button("➕ Simuler une alerte"):
        alert = create_alert(st.session_state.org_id, st.session_state.endpoint_id,
                             'test', 'MEDIUM', 0.7, "Alerte de test", {})
        st.session_state.alerts.append(alert)
        st.rerun()

# --- Conformité ---
with tabs[6]:
    st.subheader("📋 Conformité et Audits")
    report_types = ['GDPR', 'ISO27001', 'SOC2', 'NIST']
    selected = st.selectbox("Type de rapport", report_types)
    if st.button("Générer un rapport"):
        # Simuler un rapport
        findings = {
            'total_controls': 120,
            'passed': random.randint(100, 119),
            'failed': random.randint(1, 20),
            'critical_findings': random.randint(0, 5)
        }
        st.success(f"Rapport {selected} généré")
        st.json(findings)

# --- Carte mondiale ---
with tabs[7]:
    st.subheader("🌍 Carte mondiale des menaces")
    if st.session_state.attack_events:
        fig_map = plot_cyber_map(st.session_state.attack_events)
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("Aucune menace géolocalisée.")

# --- Analyse ciblée ---
with tabs[8]:
    st.subheader("🔍 Analyse ciblée")
    analysis_type = st.radio("Type d'analyse", ["Fichier", "Dossier", "Site web", "Disque"], horizontal=True)

    if analysis_type == "Fichier":
        uploaded_file = st.file_uploader("Choisissez un fichier", type=None)
        if uploaded_file is not None:
            with st.spinner("Analyse en cours..."):
                result = analyze_file(uploaded_file)
                if result:
                    st.write("### Résultat de l'analyse")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Nom", result['filename'])
                        st.metric("Taille", f"{result['size']} octets")
                    with col2:
                        st.metric("Hash SHA-256", result['hash'][:16]+"...")
                        st.metric("Malveillant", "⚠️ OUI" if result['malicious'] else "✅ NON")
                    if result['malicious']:
                        st.error("Ce fichier correspond à une signature de menace connue.")
                    else:
                        st.success("Aucune menace détectée.")

    elif analysis_type == "Dossier":
        folder_path = st.text_input("Chemin du dossier (ex: C:/Users/... ou /home/...)")
        if st.button("Scanner le dossier") and folder_path:
            with st.spinner("Scan en cours..."):
                files = scan_folder(folder_path)
                if files:
                    df_files = pd.DataFrame(files)
                    st.dataframe(df_files, use_container_width=True)
                    suspicious = sum(1 for f in files if f['suspicious'])
                    st.metric("Fichiers suspects", suspicious)
                else:
                    st.warning("Dossier introuvable ou vide.")

    elif analysis_type == "Site web":
        url = st.text_input("URL du site (ex: https://example.com)")
        if st.button("Analyser le site") and url:
            with st.spinner("Analyse en cours..."):
                result = analyze_url(url)
                if result:
                    st.write("### Résultat")
                    st.json(result)
                    if result.get('malicious'):
                        st.error("Ce site est signalé comme malveillant.")
                    else:
                        st.success("Aucune menace détectée.")

    elif analysis_type == "Disque":
        st.info("Analyse rapide du disque local (simulation)")
        if st.button("Scanner le disque"):
            with st.spinner("Scan en cours..."):
                total_files = random.randint(5000, 20000)
                suspicious = random.randint(0, 50)
                st.metric("Fichiers analysés", total_files)
                st.metric("Menaces potentielles", suspicious)
                if suspicious > 0:
                    st.warning(f"{suspicious} fichiers suspects détectés. Vérifiez les dossiers.")

# --- Logs en temps réel ---
with tabs[9]:
    st.subheader("📜 Journal d'activité en direct")
    log_html = '<div class="log-box">'
    for log in reversed(st.session_state.log_messages[-100:]):
        level_class = "log-info" if log['level']=="INFO" else "log-warning" if log['level']=="WARNING" else "log-critical"
        log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="{level_class}">{log["message"]}</span></div>'
    log_html += '</div>'
    st.markdown(log_html, unsafe_allow_html=True)

# -------------------------------------------------------------------
# Footer
# -------------------------------------------------------------------
st.markdown("---")
st.caption(f"TTU Shield Sentinel – Version Unifiée | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")