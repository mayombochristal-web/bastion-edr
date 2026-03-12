#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU Shield Sentinel – Cybersecurity Platform
Version avec analyse ciblée et données de démonstration
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
import requests
from datetime import datetime, timedelta
from collections import deque
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
# CSS personnalisé (identique)
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
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------
# Moteur TTU avec auto‑adaptation
# -------------------------------------------------------------------
class TTUEngine:
    def __init__(self, k_factor=1.2, weights=(1.0, 1.5, 2.0), n_sigma=2.0):
        self.k_factor = k_factor
        self.w_m, self.w_c, self.w_d = weights
        self.n_sigma = n_sigma
        self.baseline_scores = deque(maxlen=200)
        # Pré‑remplissage aléatoire (phase d'apprentissage)
        rng = np.random.default_rng(42)
        for _ in range(150):
            self.baseline_scores.append(rng.normal(0.25, 0.08))

    def raw_score(self, phi_m, phi_c, phi_d):
        w_tot = self.w_m + self.w_c + self.w_d
        return self.k_factor * (self.w_m*phi_m + self.w_c*phi_c + self.w_d*phi_d) / w_tot

    def adaptive_threshold(self):
        arr = np.array(self.baseline_scores)
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        threshold = mean + self.n_sigma * std
        return mean, std, min(threshold, 0.99)

    def classify(self, score, threshold):
        if score >= threshold:
            return "CRITICAL"
        elif score >= threshold * 0.75:
            return "ORANGE"
        else:
            return "NORMAL"

    def process_event(self, phi_m, phi_c, phi_d):
        raw = self.raw_score(phi_m, phi_c, phi_d)
        raw = max(0.0, min(raw, 2.0))
        score = min(raw, 1.0)
        mean, std, thresh = self.adaptive_threshold()
        status = self.classify(score, thresh)
        if status == "NORMAL":
            self.baseline_scores.append(score)
        return {
            'score': score,
            'threshold': thresh,
            'status': status,
            'mean': mean,
            'std': std
        }

class TTUEngineAuto(TTUEngine):
    def adapt_k_factor(self, phi_c):
        if phi_c < 0.2:
            self.k_factor = min(3.0, self.k_factor * 1.2)
        elif phi_c > 0.6:
            self.k_factor = max(1.0, self.k_factor * 0.99)

# -------------------------------------------------------------------
# Surveillance système avancée (endpoint)
# -------------------------------------------------------------------
def get_system_triad():
    # Mémoire
    phi_m = psutil.virtual_memory().percent / 100.0
    # Cohérence : variation CPU
    cpu_samples = [psutil.cpu_percent(interval=0.1) for _ in range(10)]
    cpu_std = np.std(cpu_samples) / 100.0
    phi_c = max(0.0, 1.0 - cpu_std)
    # Dissipation : débit réseau sortant (normalisé)
    net1 = psutil.net_io_counters()
    time.sleep(0.5)
    net2 = psutil.net_io_counters()
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    phi_d = min(1.0, bytes_sent / (125 * 1024 * 1024))  # 125 Mo/s ≈ 1 Gbps
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
    if not path:
        return "unknown"
    sha = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha.update(block)
        return sha.hexdigest()
    except Exception:
        return "unknown"

# Isolation réseau simplifiée
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

# -------------------------------------------------------------------
# Capteurs réseau simulés (pour démonstration)
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
# Connexion Supabase
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

# -------------------------------------------------------------------
# Session State avec données de démonstration
# -------------------------------------------------------------------
if 'engine' not in st.session_state:
    st.session_state.engine = TTUEngineAuto()

# Initialiser avec des données de démonstration si vide
if 'endpoint_history' not in st.session_state or not st.session_state.endpoint_history:
    st.session_state.endpoint_history = []
    # Générer 20 points de démonstration
    now = datetime.now()
    for i in range(20):
        t = now - timedelta(minutes=20-i)
        score = random.uniform(0.1, 0.8)
        thresh = random.uniform(0.5, 0.7)
        status = "NORMAL" if score < thresh else "ORANGE" if score < thresh*1.2 else "CRITICAL"
        st.session_state.endpoint_history.append({
            'time': t,
            'score': score,
            'threshold': thresh,
            'status': status,
            'phi_m': random.uniform(0.2, 0.8),
            'phi_c': random.uniform(0.2, 0.9),
            'phi_d': random.uniform(0.1, 0.5)
        })

if 'network_logs' not in st.session_state or not st.session_state.network_logs:
    st.session_state.network_logs = [simulate_network_traffic() for _ in range(10)]

if 'cloud_logs' not in st.session_state or not st.session_state.cloud_logs:
    st.session_state.cloud_logs = [simulate_cloud_log() for _ in range(10)]

if 'alerts' not in st.session_state or not st.session_state.alerts:
    st.session_state.alerts = []
    for i in range(5):
        alert = create_alert(
            "org_demo", "endpoint_demo",
            random.choice(['malware', 'phishing', 'anomaly']),
            random.choice(['LOW', 'MEDIUM', 'HIGH']),
            random.uniform(0.5, 0.9),
            f"Alerte de démonstration {i+1}"
        )
        st.session_state.alerts.append(alert)

if 'threat_library' not in st.session_state or not st.session_state.threat_library:
    st.session_state.threat_library = [
        {'pattern': 'malware.exe', 'weight': 0.95, 'description': 'Exemple de signature', 'phi_m': 0.8, 'phi_c': 0.2, 'phi_d': 0.9},
        {'pattern': 'ransomware.dll', 'weight': 0.98, 'description': 'Signature ransomware', 'phi_m': 0.9, 'phi_c': 0.1, 'phi_d': 0.95}
    ]

if 'attack_events' not in st.session_state or not st.session_state.attack_events:
    st.session_state.attack_events = [
        {'lat': random.uniform(-60,70), 'lon': random.uniform(-180,180)} for _ in range(15)
    ]

if 'protection_active' not in st.session_state:
    st.session_state.protection_active = False  # On laisse l'utilisateur activer
if 'monitor_thread' not in st.session_state:
    st.session_state.monitor_thread = None
if 'conn' not in st.session_state:
    st.session_state.conn = get_supabase_connection()
if 'org_id' not in st.session_state:
    st.session_state.org_id = "00000000-0000-0000-0000-000000000001"
if 'endpoint_id' not in st.session_state:
    st.session_state.endpoint_id = "00000000-0000-0000-0000-000000000002"

# -------------------------------------------------------------------
# Boucle de surveillance (thread) – identique à avant
# -------------------------------------------------------------------
def monitoring_loop():
    engine = st.session_state.engine
    while st.session_state.protection_active:
        try:
            phi_m, phi_c, phi_d = get_system_triad()
            engine.adapt_k_factor(phi_c)
            result = engine.process_event(phi_m, phi_c, phi_d)
            st.session_state.endpoint_history.append({
                'time': datetime.now(),
                'score': result['score'],
                'threshold': result['threshold'],
                'status': result['status'],
                'phi_m': phi_m,
                'phi_c': phi_c,
                'phi_d': phi_d
            })

            if random.random() < 0.2:
                net_log = simulate_network_traffic()
                st.session_state.network_logs.append(net_log)
            if random.random() < 0.1:
                cloud_log = simulate_cloud_log()
                st.session_state.cloud_logs.append(cloud_log)

            if result['status'] == "CRITICAL":
                proc = get_top_process()
                if proc:
                    proc_name = proc.name() if hasattr(proc, 'name') else "inconnu"
                    proc_path = proc.exe() if hasattr(proc, 'exe') else None
                    suspend_process(proc)
                    isolate_network()
                    lat = random.uniform(-60, 70)
                    lon = random.uniform(-180, 180)
                    st.session_state.attack_events.append({'lat': lat, 'lon': lon})
                    alert = create_alert(
                        st.session_state.org_id,
                        st.session_state.endpoint_id,
                        'endpoint_malware',
                        'HIGH',
                        result['score'],
                        f"Processus malveillant suspendu : {proc_name}",
                        {'process': proc_name, 'path': proc_path}
                    )
                    st.session_state.alerts.append(alert)
                    sig = generate_threat_signature(proc_name, result['score'],
                                                    phi_m, phi_c, phi_d)
                    st.session_state.threat_library.append(sig)
                    st.session_state.last_alert = f"Menace neutralisée : {proc_name}"

            time.sleep(2)
        except Exception as e:
            print(f"Erreur monitoring: {e}")
            time.sleep(5)

def start_protection():
    if not st.session_state.protection_active:
        st.session_state.protection_active = True
        thread = threading.Thread(target=monitoring_loop, daemon=True)
        thread.start()
        st.session_state.monitor_thread = thread
        st.success("🛡️ Protection activée – surveillance en temps réel.")

def stop_protection():
    st.session_state.protection_active = False
    st.session_state.monitor_thread = None
    st.info("Protection désactivée.")

# -------------------------------------------------------------------
# Fonctions pour l'analyse ciblée
# -------------------------------------------------------------------
def analyze_file(uploaded_file):
    """Analyse un fichier uploadé : calcule le hash et vérifie dans la threat library."""
    if uploaded_file is not None:
        # Lire le contenu pour calculer le hash
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        # Vérifier dans la threat library (simulé)
        found = False
        for sig in st.session_state.threat_library:
            if sig['pattern'].lower() in uploaded_file.name.lower():
                found = True
                break
        # Simuler une analyse YARA (ici juste un check basique)
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
    """Vérifie la réputation d'une URL (simulé avec une requête test)."""
    if url:
        try:
            # On peut faire une simple requête HEAD pour voir si le site répond
            r = requests.head(url, timeout=5, allow_redirects=True)
            status = r.status_code
            # Simuler une vérification de réputation
            malicious = random.choice([True, False])  # à remplacer par API réelle
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
    """Liste les fichiers d'un dossier et signale ceux qui pourraient être suspects."""
    if os.path.isdir(path):
        files = []
        for root, dirs, filenames in os.walk(path):
            for f in filenames[:20]:  # limite pour la démo
                full = os.path.join(root, f)
                try:
                    size = os.path.getsize(full)
                    # Simuler une détection
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
# Graphiques
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
# Sidebar
# -------------------------------------------------------------------
with st.sidebar:
    st.markdown("## ⬡ TTU Shield Sentinel")
    st.markdown("---")
    if st.session_state.protection_active:
        if st.button("🛑 DÉSACTIVER LA PROTECTION", use_container_width=True):
            stop_protection()
            st.rerun()
    else:
        if st.button("🛡️ ACTIVER LA PROTECTION", use_container_width=True, type="primary"):
            start_protection()
            st.rerun()

    st.markdown("---")
    st.markdown("### 📊 Statut")
    if st.session_state.endpoint_history:
        last = st.session_state.endpoint_history[-1]
        st.metric("Dernier score", f"{last['score']:.3f}")
        st.metric("Statut", last['status'])
    else:
        st.metric("Dernier score", "—")
        st.metric("Statut", "—")

    if st.session_state.conn:
        st.success("✅ Supabase connecté")
    else:
        st.warning("⚠️ Supabase non connecté (mode démo)")

    if st.button("🗑 Réinitialiser données locales", use_container_width=True):
        # Remettre les données de démonstration
        st.session_state.endpoint_history = []
        st.session_state.network_logs = []
        st.session_state.cloud_logs = []
        st.session_state.alerts = []
        st.session_state.attack_events = []
        st.session_state.threat_library = []
        st.rerun()

# -------------------------------------------------------------------
# Interface principale – Onglets (ajout de l'onglet Analyse)
# -------------------------------------------------------------------
st.title("🛡️ TTU Shield Sentinel – Cybersecurity Platform")
st.caption("Protection unifiée : Endpoint, Réseau, Cloud, Threat Intelligence, SOC, Conformité, Analyse ciblée")

# Afficher les alertes récentes (toast)
if 'last_alert' in st.session_state and st.session_state.last_alert:
    st.toast(st.session_state.last_alert, icon="🛡️")
    del st.session_state.last_alert

# Indicateur de protection
if st.session_state.protection_active:
    st.markdown('<div class="alert-ok">✅ Protection active – surveillance en temps réel</div>',
                unsafe_allow_html=True)
else:
    st.markdown('<div class="alert-warning">⏸️ Protection désactivée – les données affichées sont des démonstrations. Cliquez sur "ACTIVER" pour une vraie surveillance.</div>',
                unsafe_allow_html=True)

st.markdown("---")

# Création des onglets (ajout de "🔍 Analyse ciblée")
tabs = st.tabs(["📊 Dashboard", "🖥️ Endpoint", "🌐 Réseau", "☁️ Cloud", "🧠 Threat Intel", "🚨 SOC", "📋 Conformité", "🌍 Carte mondiale", "🔍 Analyse ciblée"])

# -------------------------------------------------------------------
# Onglet Dashboard
# -------------------------------------------------------------------
with tabs[0]:
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Endpoints surveillés", "1 (local)")
    with col2:
        st.metric("Alertes (24h)", len([a for a in st.session_state.alerts if a['timestamp'] > datetime.now()-timedelta(days=1)]))
    with col3:
        st.metric("Menaces bloquées", len(st.session_state.attack_events))
    with col4:
        if st.session_state.endpoint_history:
            last_status = st.session_state.endpoint_history[-1]['status']
            st.metric("Statut global", last_status)
        else:
            st.metric("Statut global", "N/A")

    if st.session_state.endpoint_history:
        df = pd.DataFrame(st.session_state.endpoint_history[-50:])
        fig = go.Figure()
        fig.add_trace(go.Scatter(y=df['score'], mode='lines+markers', name='Score'))
        fig.add_trace(go.Scatter(y=df['threshold'], mode='lines', name='Seuil', line=dict(dash='dash')))
        fig.update_layout(height=300, plot_bgcolor='#07070f', paper_bgcolor='#0d0d1a')
        st.plotly_chart(fig, use_container_width=True)

# -------------------------------------------------------------------
# Onglet Endpoint
# -------------------------------------------------------------------
with tabs[1]:
    st.subheader("🖥️ Surveillance Endpoint")
    if st.session_state.endpoint_history:
        last = st.session_state.endpoint_history[-1]
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(plot_gauge(last['score'],
                                        "#4cffaa" if last['status']=="NORMAL" else "#ffb347" if last['status']=="ORANGE" else "#ff3b3b"),
                            use_container_width=True)
        with col2:
            st.metric("Score", f"{last['score']:.3f}")
            st.metric("Seuil", f"{last['threshold']:.3f}")
            st.metric("Φm", f"{last['phi_m']:.2f}")
            st.metric("Φc", f"{last['phi_c']:.2f}")
            st.metric("Φd", f"{last['phi_d']:.2f}")

        # Graphique historique
        df = pd.DataFrame(st.session_state.endpoint_history[-100:])
        df['time'] = pd.to_datetime(df['time'])
        fig = make_subplots(rows=2, cols=1, shared_xaxes=True, row_heights=[0.7, 0.3])
        fig.add_trace(go.Scatter(x=df['time'], y=df['score'], name='Score'), row=1, col=1)
        fig.add_trace(go.Scatter(x=df['time'], y=df['threshold'], name='Seuil', line=dict(dash='dash')), row=1, col=1)
        fig.add_trace(go.Scatter(x=df['time'], y=df['phi_m'], name='Φm'), row=2, col=1)
        fig.add_trace(go.Scatter(x=df['time'], y=df['phi_c'], name='Φc'), row=2, col=1)
        fig.add_trace(go.Scatter(x=df['time'], y=df['phi_d'], name='Φd'), row=2, col=1)
        fig.update_layout(height=500, plot_bgcolor='#07070f', paper_bgcolor='#0d0d1a')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Aucune donnée endpoint.")

# -------------------------------------------------------------------
# Onglet Réseau
# -------------------------------------------------------------------
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
        st.info("Aucun log réseau.")

# -------------------------------------------------------------------
# Onglet Cloud
# -------------------------------------------------------------------
with tabs[3]:
    st.subheader("☁️ Surveillance Cloud")
    if st.session_state.cloud_logs:
        df_cloud = pd.DataFrame(st.session_state.cloud_logs[-50:])
        st.dataframe(df_cloud[['event_time', 'cloud_provider', 'event_name', 'resource_type', 'outcome']].tail(20),
                     use_container_width=True, hide_index=True)
    else:
        st.info("Aucun log cloud.")

# -------------------------------------------------------------------
# Onglet Threat Intelligence
# -------------------------------------------------------------------
with tabs[4]:
    st.subheader("🧠 Bibliothèque des Menaces (Collective)")
    if st.session_state.threat_library:
        df_threat = pd.DataFrame(st.session_state.threat_library)
        st.dataframe(df_threat, use_container_width=True)
    else:
        st.info("Aucune signature.")
    if st.button("➕ Ajouter une signature exemple"):
        sig = generate_threat_signature("exemple.exe", 0.9, 0.8, 0.2, 0.9)
        st.session_state.threat_library.append(sig)
        st.rerun()

# -------------------------------------------------------------------
# Onglet SOC
# -------------------------------------------------------------------
with tabs[5]:
    st.subheader("🚨 Centre d'Opérations de Sécurité (SOC)")
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

# -------------------------------------------------------------------
# Onglet Conformité
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Onglet Carte mondiale
# -------------------------------------------------------------------
with tabs[7]:
    st.subheader("🌍 Carte mondiale des menaces")
    if st.session_state.attack_events:
        fig_map = plot_cyber_map(st.session_state.attack_events)
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("Aucune menace géolocalisée.")

# -------------------------------------------------------------------
# NOUVEL ONGLET : Analyse ciblée
# -------------------------------------------------------------------
with tabs[8]:
    st.subheader("🔍 Analyse ciblée")
    st.markdown("Sélectionnez une cible à analyser : fichier, dossier, disque ou site web.")

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
                # Simuler un scan de disque
                total_files = random.randint(5000, 20000)
                suspicious = random.randint(0, 50)
                st.metric("Fichiers analysés", total_files)
                st.metric("Menaces potentielles", suspicious)
                if suspicious > 0:
                    st.warning(f"{suspicious} fichiers suspects détectés. Vérifiez les dossiers.")

# -------------------------------------------------------------------
# Footer
# -------------------------------------------------------------------
st.markdown("---")
st.caption(f"TTU Shield Sentinel – Cybersecurity Platform | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")