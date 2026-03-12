#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU Shield Sentinel – Version Finale Professionnelle
Avec analyse réelle de l'hôte, threads stables, paywall,
onboarding, logs temps réel, analyse ciblée et historique.
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
# CSS personnalisé
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
  
  /* Style pour la boîte de logs */
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
# Moteur TTU avec auto‑adaptation
# -------------------------------------------------------------------
class TTUEngine:
    def __init__(self, k_factor=1.2, weights=(1.0, 1.5, 2.0), n_sigma=2.0):
        self.k_factor = k_factor
        self.w_m, self.w_c, self.w_d = weights
        self.n_sigma = n_sigma
        self.baseline_scores = deque(maxlen=200)
        # Pré‑remplissage réaliste
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
# Fonctions de collecte de métriques réelles
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
# Scan réel de fichiers (limité)
# -------------------------------------------------------------------
def scan_directory(path, max_files=50, max_depth=3):
    results = []
    if not os.path.isdir(path):
        return results
    try:
        for root, dirs, files in os.walk(path):
            depth = root.replace(path, '').count(os.sep)
            if depth > max_depth:
                dirs[:] = []
                continue
            for f in files:
                if len(results) >= max_files:
                    return results
                full_path = os.path.join(root, f)
                try:
                    file_size = os.path.getsize(full_path)
                    if file_size > 100 * 1024 * 1024:
                        continue
                    file_hash = hash_file(full_path)
                    results.append({
                        'path': full_path,
                        'size': file_size,
                        'hash': file_hash,
                        'suspicious': False
                    })
                except Exception:
                    continue
    except Exception:
        pass
    return results

# -------------------------------------------------------------------
# Analyse de site web (Google Safe Browsing)
# -------------------------------------------------------------------
def check_url_google_safe_browsing(url, api_key):
    if not api_key:
        return None
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "ttu-shield-sentinel",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, params={"key": api_key}, json=payload, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("matches") is not None
    except:
        pass
    return None

def analyze_url(url, google_api_key=None):
    if google_api_key:
        malicious = check_url_google_safe_browsing(url, google_api_key)
        if malicious is not None:
            return {"malicious": malicious, "method": "Google Safe Browsing"}
    # Simulation si pas de clé
    return {"malicious": random.random() < 0.2, "method": "Simulation"}

# -------------------------------------------------------------------
# Connexion Supabase et fonctions de persistance
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

def validate_invite_code(code, user_id, conn):
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, plan_type, is_used
            FROM invitations
            WHERE code = %s AND (expires_at IS NULL OR expires_at > NOW())
        """, (code,))
        row = cur.fetchone()
        if not row:
            return None
        invite_id, plan_type, is_used = row
        if is_used:
            return None
        cur.execute("""
            UPDATE invitations
            SET is_used = TRUE, used_by_user_id = %s
            WHERE id = %s
        """, (user_id, invite_id))
        conn.commit()
        cur.close()
        return plan_type
    except Exception as e:
        st.error(f"Erreur validation code: {e}")
        return None

def create_subscription_from_invite(user_id, plan_type, conn):
    if not conn:
        return False
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO user_subscriptions (user_id, plan_type, status)
            VALUES (%s, %s, 'active')
            ON CONFLICT (user_id) DO UPDATE
            SET plan_type = EXCLUDED.plan_type, status = 'active', updated_at = NOW()
        """, (user_id, plan_type))
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        st.error(f"Erreur création abonnement: {e}")
        return False

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

def insert_threat_signature(conn, pattern, weight, description, phi_m, phi_c, phi_d):
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO threat_library (pattern, weight, description, phi_m, phi_c, phi_d)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (pattern, weight, description, phi_m, phi_c, phi_d))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion threat_library: {e}")

def get_threat_library(conn):
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT pattern, weight, description, phi_m, phi_c, phi_d FROM threat_library ORDER BY weight DESC")
        rows = cur.fetchall()
        cur.close()
        return [{'pattern': r[0], 'weight': r[1], 'description': r[2], 'phi_m': r[3], 'phi_c': r[4], 'phi_d': r[5]} for r in rows]
    except Exception as e:
        st.error(f"Erreur lecture threat_library: {e}")
        return []

# -------------------------------------------------------------------
# Gestion des logs en temps réel (file thread-safe)
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
# Boucle de surveillance (thread)
# -------------------------------------------------------------------
def monitoring_loop(engine, stop_event, conn, endpoint_id):
    add_log("Démarrage de la surveillance système...", "INFO")
    while not stop_event.is_set():
        try:
            phi_m, phi_c, phi_d = get_system_triad()
            engine.adapt_k_factor(phi_c)
            result = engine.process_event(phi_m, phi_c, phi_d)

            add_log(f"Φm={phi_m:.2f} Φc={phi_c:.2f} Φd={phi_d:.2f} | Score={result['score']:.3f} ({result['status']})", "INFO")

            if conn and endpoint_id:
                insert_security_log(conn, endpoint_id, phi_m, phi_c, phi_d, result['score'], result['status'])

            if result['status'] == "CRITICAL":
                proc = get_top_process()
                if proc:
                    proc_name = proc.name() if hasattr(proc, 'name') else "inconnu"
                    proc_path = proc.exe() if hasattr(proc, 'exe') else None
                    suspend_process(proc)
                    add_log(f"⚠️ Processus critique suspendu : {proc_name}", "CRITICAL")
                    # Ajouter à la threat library ?
                    # insert_threat_signature(conn, proc_name, result['score'], "Auto-detected", phi_m, phi_c, phi_d)

            time.sleep(2)
        except Exception as e:
            add_log(f"Erreur dans la boucle : {e}", "CRITICAL")
            time.sleep(5)

# -------------------------------------------------------------------
# Fonctions de démarrage/arrêt du thread
# -------------------------------------------------------------------
def start_monitoring(engine, conn, endpoint_id):
    if st.session_state.get('monitoring_active', False):
        return
    st.session_state.monitoring_active = True
    stop_event = threading.Event()
    st.session_state.stop_event = stop_event
    thread = threading.Thread(
        target=monitoring_loop,
        args=(engine, stop_event, conn, endpoint_id),
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
# Session State – initialisation
# -------------------------------------------------------------------
if 'engine' not in st.session_state:
    st.session_state.engine = TTUEngineAuto()
if 'conn' not in st.session_state:
    st.session_state.conn = get_supabase_connection()
if 'user_id' not in st.session_state:
    # Pour les tests, utiliser un UUID fixe (à remplacer par un vrai utilisateur)
    st.session_state.user_id = "a696b926-eb23-4f8d-b4d3-f6bb0527a2f3"  # UUID de test
if 'subscription' not in st.session_state:
    st.session_state.subscription = get_user_subscription(st.session_state.user_id, st.session_state.conn)
if 'onboarding_done' not in st.session_state:
    st.session_state.onboarding_done = False
if 'endpoint_id' not in st.session_state:
    st.session_state.endpoint_id = None
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False
if 'log_messages' not in st.session_state:
    st.session_state.log_messages = []
if 'google_api_key' not in st.session_state:
    st.session_state.google_api_key = ""  # À remplir dans la sidebar

# -------------------------------------------------------------------
# Interface principale
# -------------------------------------------------------------------
st.title("🛡️ TTU Shield Sentinel – Cybersecurity Platform")
st.caption("Protection unifiée avec analyse réelle de l'hôte")

# -------------------------------------------------------------------
# ÉTAPE 1 : Vérification de l'abonnement
# -------------------------------------------------------------------
if st.session_state.subscription is None:
    # Afficher la landing page
    st.markdown("""
    <div style="text-align: center; padding: 3rem;">
        <h1 style="font-size: 3rem;">🛡️</h1>
        <h2>Bienvenue sur TTU Shield Sentinel</h2>
        <p style="color: #aaa;">La première plateforme de cybersécurité basée sur le modèle mathématique TTU-MC³.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🔐 Déjà membre ?")
        email = st.text_input("Votre email", placeholder="exemple@domaine.com")
        if st.button("Se connecter avec cet email"):
            # Dans un vrai projet, utilisez l'authentification Supabase.
            # Pour la démo, on garde l'UUID fixe.
            st.session_state.user_id = "a696b926-eb23-4f8d-b4d3-f6bb0527a2f3"
            st.session_state.subscription = get_user_subscription(st.session_state.user_id, st.session_state.conn)
            st.rerun()

    with col2:
        st.markdown("### ✨ Nouvel utilisateur")
        code = st.text_input("Code d'invitation", placeholder="XXXX-XXXX")
        if st.button("Activer mon accès"):
            if code:
                plan = validate_invite_code(code, st.session_state.user_id, st.session_state.conn)
                if plan:
                    if create_subscription_from_invite(st.session_state.user_id, plan, st.session_state.conn):
                        st.success(f"Félicitations ! Votre abonnement {plan} est actif.")
                        st.session_state.subscription = get_user_subscription(st.session_state.user_id, st.session_state.conn)
                        st.rerun()
                    else:
                        st.error("Erreur lors de la création de l'abonnement.")
                else:
                    st.error("Code invalide ou déjà utilisé.")
            else:
                st.warning("Veuillez saisir un code.")

    st.stop()

# -------------------------------------------------------------------
# ÉTAPE 2 : Onboarding – nommer l'endpoint
# -------------------------------------------------------------------
if not st.session_state.onboarding_done:
    st.markdown("---")
    st.subheader("📋 Configuration initiale")
    st.markdown("Pour commencer, donnez un nom à cet ordinateur (ex: 'Mon PC', 'Serveur-01').")

    endpoint_name = st.text_input("Nom de l'endpoint", placeholder="Mon-PC")
    if st.button("Démarrer la surveillance"):
        if endpoint_name:
            endpoint_id = register_endpoint(st.session_state.user_id, endpoint_name, st.session_state.conn)
            if endpoint_id:
                st.session_state.endpoint_id = endpoint_id
                st.session_state.onboarding_done = True
                add_log(f"Endpoint '{endpoint_name}' enregistré.", "INFO")
                st.rerun()
            else:
                st.error("Erreur lors de l'enregistrement de l'endpoint.")
        else:
            st.warning("Veuillez saisir un nom.")
    st.stop()

# -------------------------------------------------------------------
# ÉTAPE 3 : Monitoring – interface principale avec onglets
# -------------------------------------------------------------------
st.markdown(f"**Utilisateur** : {st.session_state.user_id[:8]}... | **Abonnement** : `{st.session_state.subscription['plan_type']}` ({st.session_state.subscription['status']})")

# Sidebar pour les contrôles et infos
with st.sidebar:
    st.markdown("## ⬡ TTU Shield Sentinel")
    st.markdown("---")
    st.markdown(f"**Utilisateur** : {st.session_state.user_id[:8]}...")
    st.markdown(f"**Abonnement** : `{st.session_state.subscription['plan_type']}`")
    if st.session_state.endpoint_id:
        st.markdown(f"**Endpoint** : {st.session_state.endpoint_id[:8]}...")

    st.markdown("---")
    # Clé API Google Safe Browsing
    google_api_key = st.text_input("🔑 Clé API Google Safe Browsing", type="password", value=st.session_state.google_api_key,
                                   help="Optionnel pour analyse de sites web")
    if google_api_key != st.session_state.google_api_key:
        st.session_state.google_api_key = google_api_key
        st.rerun()

    st.markdown("---")
    # Contrôle de la surveillance
    if not st.session_state.monitoring_active:
        if st.button("▶️ Démarrer la surveillance", use_container_width=True):
            start_monitoring(st.session_state.engine, st.session_state.conn, st.session_state.endpoint_id)
            st.rerun()
    else:
        if st.button("⏹️ Arrêter", use_container_width=True):
            stop_monitoring()
            st.rerun()

    st.markdown("---")
    if st.button("Se déconnecter (retour à l'accueil)"):
        stop_monitoring()
        st.session_state.subscription = None
        st.session_state.onboarding_done = False
        st.session_state.endpoint_id = None
        st.rerun()

# Récupérer les logs de la file
while not log_queue.empty():
    try:
        log = log_queue.get_nowait()
        st.session_state.log_messages.append(log)
    except Empty:
        break
if len(st.session_state.log_messages) > 200:
    st.session_state.log_messages = st.session_state.log_messages[-200:]

# Création des onglets
tabs = st.tabs(["📊 Dashboard", "🖥️ Endpoint", "🔍 Analyse ciblée", "📋 Historique", "🧠 Threat Library"])

# -------------------------------------------------------------------
# Onglet Dashboard
# -------------------------------------------------------------------
with tabs[0]:
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Statut surveillance", "Active" if st.session_state.monitoring_active else "Inactive")
    with col2:
        st.metric("Dernier score", f"{st.session_state.log_messages[-1]['message'].split('|')[1].strip() if st.session_state.log_messages else 'N/A'}")
    with col3:
        st.metric("Menaces critiques", sum(1 for log in st.session_state.log_messages if log['level']=='CRITICAL'))
    with col4:
        st.metric("Logs", len(st.session_state.log_messages))

    # Zone de logs
    st.markdown("#### Journal d'activité en direct")
    log_html = '<div class="log-box">'
    for log in reversed(st.session_state.log_messages[-50:]):
        level_class = "log-info" if log['level']=="INFO" else "log-warning" if log['level']=="WARNING" else "log-critical"
        log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="{level_class}">{log["message"]}</span></div>'
    log_html += '</div>'
    st.markdown(log_html, unsafe_allow_html=True)

# -------------------------------------------------------------------
# Onglet Endpoint
# -------------------------------------------------------------------
with tabs[1]:
    st.subheader("🖥️ Surveillance détaillée de l'endpoint")
    if st.session_state.monitoring_active:
        if st.button("🔄 Rafraîchir les métriques"):
            with st.spinner("Collecte..."):
                phi_m, phi_c, phi_d = get_system_triad()
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Mémoire (Φm)", f"{phi_m:.2f}")
                with col2:
                    st.metric("Cohérence (Φc)", f"{phi_c:.2f}")
                with col3:
                    st.metric("Dissipation (Φd)", f"{phi_d:.2f}")

        # Afficher les connexions actives
        with st.expander("Connexions réseau actives"):
            conns = get_active_connections()
            if conns:
                st.dataframe(pd.DataFrame(conns), use_container_width=True)
            else:
                st.write("Aucune connexion établie.")
    else:
        st.info("La surveillance n'est pas active. Démarrez-la pour voir les métriques.")

# -------------------------------------------------------------------
# Onglet Analyse ciblée
# -------------------------------------------------------------------
with tabs[2]:
    st.subheader("🔍 Analyse ciblée")
    st.markdown("Sélectionnez une cible à analyser : fichier, dossier ou site web.")

    analysis_type = st.radio("Type d'analyse", ["Fichier", "Dossier", "Site web"], horizontal=True)

    if analysis_type == "Fichier":
        uploaded_file = st.file_uploader("Choisissez un fichier", type=None)
        if uploaded_file is not None:
            with st.spinner("Analyse en cours..."):
                # Sauvegarder temporairement
                temp_path = f"/tmp/{uploaded_file.name}"
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                file_hash = hash_file(temp_path)
                # Vérifier dans la threat library
                threat_lib = get_threat_library(st.session_state.conn)
                malicious = any(sig['pattern'].lower() in uploaded_file.name.lower() for sig in threat_lib)
                os.remove(temp_path)
                st.write("### Résultat")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Nom", uploaded_file.name)
                    st.metric("Taille", f"{uploaded_file.size} octets")
                with col2:
                    st.metric("SHA-256", file_hash[:16]+"...")
                    st.metric("Malveillant", "⚠️ OUI" if malicious else "✅ NON")
                if malicious:
                    st.error("Ce fichier correspond à une signature de menace connue.")
                else:
                    st.success("Aucune menace détectée.")

    elif analysis_type == "Dossier":
        folder_path = st.text_input("Chemin du dossier (ex: C:/Users/... ou /home/...)")
        if st.button("Scanner le dossier (limité à 50 fichiers)") and folder_path:
            with st.spinner("Scan en cours..."):
                files = scan_directory(folder_path, max_files=50, max_depth=3)
                if files:
                    # Vérifier les signatures
                    threat_lib = get_threat_library(st.session_state.conn)
                    for f in files:
                        f['suspicious'] = any(sig['pattern'] in f['path'] for sig in threat_lib)
                    df_files = pd.DataFrame(files)
                    st.dataframe(df_files, use_container_width=True)
                    suspicious = sum(1 for f in files if f['suspicious'])
                    st.metric("Fichiers suspects", suspicious)
                else:
                    st.warning("Dossier introuvable, vide ou accès refusé.")

    elif analysis_type == "Site web":
        url = st.text_input("URL du site (ex: https://example.com)")
        if st.button("Analyser le site") and url:
            with st.spinner("Analyse en cours..."):
                result = analyze_url(url, st.session_state.google_api_key)
                st.write("### Résultat")
                st.json(result)
                if result.get('malicious'):
                    st.error("Ce site est signalé comme malveillant.")
                else:
                    st.success("Aucune menace détectée.")

# -------------------------------------------------------------------
# Onglet Historique (logs depuis Supabase)
# -------------------------------------------------------------------
with tabs[3]:
    st.subheader("📋 Historique des événements (7 derniers jours)")
    if st.session_state.conn and st.session_state.endpoint_id:
        try:
            cur = st.session_state.conn.cursor()
            cur.execute("""
                SELECT created_at, phi_m, phi_c, phi_d, anomaly_score, status
                FROM security_logs
                WHERE endpoint_id = %s AND created_at > NOW() - INTERVAL '7 days'
                ORDER BY created_at DESC
                LIMIT 200
            """, (st.session_state.endpoint_id,))
            rows = cur.fetchall()
            cur.close()
            if rows:
                df = pd.DataFrame(rows, columns=['Timestamp', 'Φm', 'Φc', 'Φd', 'Score', 'Statut'])
                st.dataframe(df, use_container_width=True)

                # Graphique d'évolution
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
                df = df.sort_values('Timestamp')
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=df['Timestamp'], y=df['Score'], mode='lines+markers', name='Score'))
                fig.update_layout(height=300, plot_bgcolor='#07070f', paper_bgcolor='#0d0d1a')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Aucun log trouvé pour cet endpoint.")
        except Exception as e:
            st.error(f"Erreur lecture historique: {e}")
    else:
        st.info("Connectez-vous et enregistrez un endpoint pour voir l'historique.")

# -------------------------------------------------------------------
# Onglet Threat Library
# -------------------------------------------------------------------
with tabs[4]:
    st.subheader("🧠 Bibliothèque des menaces")
    threat_lib = get_threat_library(st.session_state.conn)
    if threat_lib:
        df_threat = pd.DataFrame(threat_lib)
        st.dataframe(df_threat, use_container_width=True)
    else:
        st.info("Aucune signature pour l'instant.")

    if st.button("➕ Ajouter une signature exemple"):
        insert_threat_signature(st.session_state.conn, "exemple.exe", 0.9, "Signature de test", 0.8, 0.2, 0.9)
        st.rerun()

# -------------------------------------------------------------------
# Footer
# -------------------------------------------------------------------
st.markdown("---")
st.caption(f"TTU Shield Sentinel – Version Finale | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")