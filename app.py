#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU Shield Sentinel – Version Professionnelle
Avec paywall, onboarding, monitoring temps réel et logs persistants.
Utilise des données système réelles (psutil) et une file thread-safe.
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
# Moteur TTU avec auto‑adaptation (identique)
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
    """Récupère l'abonnement d'un utilisateur. Retourne None si non trouvé."""
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

def create_subscription_from_invite(user_id, plan_type, conn):
    """Crée un abonnement pour un utilisateur à partir d'un code d'invitation."""
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

def validate_invite_code(code, user_id, conn):
    """Vérifie si un code d'invitation est valide et l'utilise."""
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
        # Marquer comme utilisé
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

def register_endpoint(user_id, endpoint_name, conn):
    """Enregistre un nouvel endpoint pour l'utilisateur."""
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
# Gestion des logs en temps réel (file thread-safe)
# -------------------------------------------------------------------
log_queue = Queue()

def add_log(message, level="INFO"):
    """Ajoute un message dans la file des logs."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_queue.put({
        'time': timestamp,
        'level': level,
        'message': message
    })

# -------------------------------------------------------------------
# Boucle de surveillance réelle (thread) – utilise une file pour les logs
# -------------------------------------------------------------------
def monitoring_loop(engine, stop_event, conn, endpoint_id, log_queue):
    """
    Boucle de surveillance exécutée dans un thread.
    Ajoute des logs dans la file et insère les événements dans Supabase.
    """
    add_log("Démarrage de la surveillance système...", "INFO")
    while not stop_event.is_set():
        try:
            # Collecte des métriques
            phi_m, phi_c, phi_d = get_system_triad()
            engine.adapt_k_factor(phi_c)
            result = engine.process_event(phi_m, phi_c, phi_d)

            # Ajouter un log périodique
            add_log(f"Φm={phi_m:.2f} Φc={phi_c:.2f} Φd={phi_d:.2f} | Score={result['score']:.3f} ({result['status']})", "INFO")

            # Insérer dans Supabase
            if conn and endpoint_id:
                insert_security_log(conn, endpoint_id, phi_m, phi_c, phi_d, result['score'], result['status'])

            # Si anomalie critique
            if result['status'] == "CRITICAL":
                proc = get_top_process()
                if proc:
                    proc_name = proc.name() if hasattr(proc, 'name') else "inconnu"
                    proc_path = proc.exe() if hasattr(proc, 'exe') else None
                    suspend_process(proc)
                    add_log(f"⚠️ Processus critique suspendu : {proc_name}", "CRITICAL")
                    # On pourrait aussi enregistrer dans une table d'alertes

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
# Session State – initialisation
# -------------------------------------------------------------------
if 'engine' not in st.session_state:
    st.session_state.engine = TTUEngineAuto()
if 'conn' not in st.session_state:
    st.session_state.conn = get_supabase_connection()
if 'user_id' not in st.session_state:
    # Pour les tests, on utilise un UUID fixe (à remplacer par un vrai utilisateur)
    # Vous pouvez modifier cette ligne pour utiliser l'email saisi ou un mécanisme d'auth.
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
    st.session_state.log_messages = []  # pour l'affichage, on vide la queue dedans

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
        # Simuler une connexion avec email (pour les tests)
        email = st.text_input("Votre email", placeholder="exemple@domaine.com")
        if st.button("Se connecter avec cet email"):
            # Chercher l'utilisateur dans auth.users par email (simplifié)
            # Dans un vrai projet, utilisez l'authentification Supabase.
            # Ici, on va simplement garder le même UUID fixe pour la démo.
            st.session_state.user_id = "a696b926-eb23-4f8d-b4d3-f6bb0527a2f3"  # à adapter
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

    st.stop()  # Arrête l'exécution ici

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
            # Enregistrer l'endpoint dans Supabase
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
# ÉTAPE 3 : Monitoring – interface principale
# -------------------------------------------------------------------
st.markdown(f"**Utilisateur** : {st.session_state.user_id[:8]}... | **Abonnement** : `{st.session_state.subscription['plan_type']}` ({st.session_state.subscription['status']})")

# Contrôles de surveillance
col1, col2 = st.columns([1, 5])
with col1:
    if not st.session_state.monitoring_active:
        if st.button("▶️ Démarrer la surveillance", use_container_width=True):
            start_monitoring(st.session_state.engine, st.session_state.conn, st.session_state.endpoint_id)
            st.rerun()
    else:
        if st.button("⏹️ Arrêter", use_container_width=True):
            stop_monitoring()
            st.rerun()

# Récupérer les logs de la file et les stocker dans session_state pour affichage
while not log_queue.empty():
    try:
        log = log_queue.get_nowait()
        st.session_state.log_messages.append(log)
    except Empty:
        break
# Limiter le nombre de logs affichés
if len(st.session_state.log_messages) > 200:
    st.session_state.log_messages = st.session_state.log_messages[-200:]

# Afficher les dernières métriques (depuis le dernier log ou via une lecture directe)
# Pour éviter de bloquer, on peut lire les dernières valeurs depuis le moteur ou depuis la file.
# On va simplement afficher les logs et un graphique basé sur les logs Supabase.

st.markdown("---")
st.subheader("📊 Surveillance en temps réel")

# Zone de logs
st.markdown("#### Journal d'activité")
log_html = '<div class="log-box">'
for log in reversed(st.session_state.log_messages[-50:]):
    level_class = "log-info" if log['level']=="INFO" else "log-warning" if log['level']=="WARNING" else "log-critical"
    log_html += f'<div class="log-entry"><span class="log-time">[{log["time"]}]</span> <span class="{level_class}">{log["message"]}</span></div>'
log_html += '</div>'
st.markdown(log_html, unsafe_allow_html=True)

# Graphique des scores récents (depuis Supabase)
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
        else:
            st.info("En attente des premières données...")
    except Exception as e:
        st.error(f"Erreur lecture historique: {e}")

# Afficher les métriques système actuelles (via un appel direct, mais attention au blocage)
if st.button("🔄 Rafraîchir les métriques"):
    with st.spinner("Collecte..."):
        phi_m, phi_c, phi_d = get_system_triad()
        st.metric("Mémoire (Φm)", f"{phi_m:.2f}")
        st.metric("Cohérence (Φc)", f"{phi_c:.2f}")
        st.metric("Dissipation (Φd)", f"{phi_d:.2f}")

# -------------------------------------------------------------------
# Sidebar avec informations utilisateur
# -------------------------------------------------------------------
with st.sidebar:
    st.markdown("## ⬡ TTU Shield Sentinel")
    st.markdown("---")
    st.markdown(f"**Utilisateur** : {st.session_state.user_id[:8]}...")
    st.markdown(f"**Abonnement** : `{st.session_state.subscription['plan_type']}`")
    if st.session_state.endpoint_id:
        st.markdown(f"**Endpoint ID** : {st.session_state.endpoint_id[:8]}...")
    st.markdown("---")
    if st.button("Se déconnecter (retour à l'accueil)"):
        # Simuler une déconnexion en réinitialisant l'abonnement
        st.session_state.subscription = None
        st.session_state.onboarding_done = False
        st.session_state.endpoint_id = None
        stop_monitoring()
        st.rerun()

# -------------------------------------------------------------------
# Footer
# -------------------------------------------------------------------
st.markdown("---")
st.caption(f"TTU Shield Sentinel – Analyse réelle de l'hôte | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")