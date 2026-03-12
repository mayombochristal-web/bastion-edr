#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU Shield Sentinel – Édition EDR
==================================
Surveillance système, détection TTU-MC³, réponse automatique,
carte mondiale des menaces, connexion Supabase.
"""

import streamlit as st
import numpy as np
import pandas as pd
import psutil
import time
import threading
import hashlib
import random
import requests
from datetime import datetime
from collections import deque
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Tentative d'import Supabase (optionnel)
try:
    import psycopg2
    SUPPORTS_SUPABASE = True
except ImportError:
    SUPPORTS_SUPABASE = False

# ─────────────────────────────────────────────
# CONFIGURATION DE LA PAGE
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="TTU Shield Sentinel EDR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
# CSS PERSONNALISÉ (thème sombre)
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
# MOTEUR TTU AVEC AUTO‑ADAPTATION
# ─────────────────────────────────────────────

class TTUEngine:
    """Moteur de base (score, seuil adaptatif)."""
    def __init__(self, k_factor=1.2, weights=(1.0, 1.5, 2.0), n_sigma=2.0):
        self.k_factor = k_factor
        self.w_m, self.w_c, self.w_d = weights
        self.n_sigma = n_sigma
        self.baseline_scores = deque(maxlen=200)   # historique des scores normaux
        # Pré‑remplissage avec une distribution normale (phase d'apprentissage simulée)
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
        score = min(raw, 1.0)   # on ramène à [0,1] pour l'affichage
        mean, std, thresh = self.adaptive_threshold()
        status = self.classify(score, thresh)
        # Ajouter à la baseline seulement si normal (apprentissage supervisé)
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
    """Version auto‑adaptative : K varie selon la cohérence."""
    def __init__(self):
        super().__init__()
        self.k_factor = 1.2

    def adapt_k_factor(self, phi_c):
        # Si la cohérence chute brutalement (attaque probable), on augmente K
        if phi_c < 0.2:
            self.k_factor = min(3.0, self.k_factor * 1.2)
        # Si le système redevient stable, on diminue K progressivement
        elif phi_c > 0.6:
            self.k_factor = max(1.0, self.k_factor * 0.99)


# ─────────────────────────────────────────────
# FONCTIONS DE SURVEILLANCE SYSTÈME
# ─────────────────────────────────────────────

def get_system_triad():
    """
    Calcule les trois flux Φ à partir des métriques système :
    - Φm : mémoire utilisée (ratio)
    - Φc : cohérence = 1 - écart‑type de l'utilisation CPU
    - Φd : dissipation = débit réseau sortant normalisé
    """
    # Mémoire
    phi_m = psutil.virtual_memory().percent / 100.0

    # Cohérence : variation du CPU
    cpu_samples = [psutil.cpu_percent(interval=0.1) for _ in range(10)]
    cpu_std = np.std(cpu_samples) / 100.0
    phi_c = max(0.0, 1.0 - cpu_std)

    # Dissipation : débit sortant (approximatif)
    net1 = psutil.net_io_counters()
    time.sleep(0.5)
    net2 = psutil.net_io_counters()
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    # Normalisation arbitraire (125 Mo/s ≈ 1 Gbps)
    phi_d = min(1.0, bytes_sent / (125 * 1024 * 1024))

    return phi_m, phi_c, phi_d


def get_top_process():
    """Retourne le processus le plus gourmand en CPU (coupable probable)."""
    try:
        # Récupérer tous les processus et trier par CPU %
        procs = [(p, p.cpu_percent()) for p in psutil.process_iter(['pid', 'name', 'exe'])]
        procs.sort(key=lambda x: x[1], reverse=True)
        if procs:
            return procs[0][0]   # le processus avec le plus haut CPU
    except Exception:
        pass
    return None


def suspend_process(proc):
    """Suspend un processus (si possible)."""
    try:
        proc.suspend()
        return True
    except Exception:
        return False


def hash_file(path):
    """Calcule le SHA‑256 d'un fichier."""
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


def isolate_network():
    """
    Isole le réseau en suspendant tous les processus ayant des connexions actives.
    (Simplifié pour la démonstration)
    """
    suspended = []
    for conn in psutil.net_connections():
        if conn.pid and conn.status == 'ESTABLISHED':
            try:
                p = psutil.Process(conn.pid)
                p.suspend()
                suspended.append(p.info['name'] if hasattr(p, 'info') else str(conn.pid))
            except Exception:
                pass
    return suspended


# ─────────────────────────────────────────────
# CARTE MONDIALE DES MENACES
# ─────────────────────────────────────────────

def generate_attack_point():
    """Génère des coordonnées aléatoires pour simuler une attaque."""
    lat = random.uniform(-60, 70)
    lon = random.uniform(-180, 180)
    return lat, lon


def plot_cyber_map(events):
    """Crée une carte mondiale avec les points d'attaque."""
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


# ─────────────────────────────────────────────
# CONNEXION SUPABASE (OPTIONNELLE)
# ─────────────────────────────────────────────

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


def push_to_quarantine(conn, org_id, endpoint_id, payload_hash, payload_path, score, phi_m, phi_c, phi_d):
    """Insère une entrée dans quarantine_vault."""
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO quarantine_vault
                (org_id, endpoint_id, payload_hash, payload, reason, quarantined_at, sync_k, phi_m, phi_c, phi_d)
            VALUES (%s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s)
        """, (org_id, endpoint_id, payload_hash, payload_path, "Détection TTU",
              st.session_state.engine.k_factor, phi_m, phi_c, phi_d))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur insertion quarantine : {e}")


def push_to_blacklist(conn, org_id, ip_address, reason, phi_m, phi_c, phi_d):
    """Ajoute une IP à blacklisted_entities."""
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO blacklisted_entities
                (org_id, ip_address, ban_depth, reason, created_at, phi_m, phi_c, phi_d)
            VALUES (%s, %s, 1, %s, NOW(), %s, %s, %s)
        """, (org_id, ip_address, reason, phi_m, phi_c, phi_d))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur blacklist : {e}")


def push_to_threat_library(conn, pattern, weight, phi_m, phi_c, phi_d):
    """Ajoute une signature à threat_library."""
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO threat_library
                (pattern, weight, description, created_at, phi_m, phi_c, phi_d)
            VALUES (%s, %s, %s, NOW(), %s, %s, %s)
        """, (pattern, weight, "Signature TTU", phi_m, phi_c, phi_d))
        conn.commit()
        cur.close()
    except Exception as e:
        st.error(f"Erreur threat_library : {e}")


# ─────────────────────────────────────────────
# ÉTAT DE SESSION
# ─────────────────────────────────────────────

if 'engine' not in st.session_state:
    st.session_state.engine = TTUEngineAuto()
if 'history' not in st.session_state:
    st.session_state.history = []          # historique des scores
if 'attack_events' not in st.session_state:
    st.session_state.attack_events = []    # pour la carte mondiale
if 'protection_active' not in st.session_state:
    st.session_state.protection_active = False
if 'monitor_thread' not in st.session_state:
    st.session_state.monitor_thread = None
if 'conn' not in st.session_state:
    st.session_state.conn = get_supabase_connection()
if 'org_id' not in st.session_state:
    st.session_state.org_id = "00000000-0000-0000-0000-000000000001"   # À remplacer
if 'endpoint_id' not in st.session_state:
    st.session_state.endpoint_id = "00000000-0000-0000-0000-000000000002"


# ─────────────────────────────────────────────
# BOUCLE DE SURVEILLANCE (THREAD)
# ─────────────────────────────────────────────

def monitoring_loop():
    """Fonction exécutée dans un thread séparé."""
    engine = st.session_state.engine
    while st.session_state.protection_active:
        try:
            phi_m, phi_c, phi_d = get_system_triad()
            engine.adapt_k_factor(phi_c)
            result = engine.process_event(phi_m, phi_c, phi_d)

            # Sauvegarde dans l'historique
            st.session_state.history.append({
                'time': datetime.now(),
                'score': result['score'],
                'threshold': result['threshold'],
                'status': result['status'],
                'phi_m': phi_m,
                'phi_c': phi_c,
                'phi_d': phi_d
            })

            # Si anomalie critique
            if result['status'] == "CRITICAL":
                # 1. Identifier le processus suspect
                proc = get_top_process()
                if proc:
                    proc_name = proc.name() if hasattr(proc, 'name') else "inconnu"
                    proc_path = proc.exe() if hasattr(proc, 'exe') else None
                    # 2. Suspendre le processus
                    suspend_process(proc)
                    # 3. Isoler le réseau (suspendre toutes les connexions)
                    isolated = isolate_network()
                    # 4. Ajouter un point sur la carte mondiale
                    lat, lon = generate_attack_point()
                    st.session_state.attack_events.append({'lat': lat, 'lon': lon})
                    # 5. Envoyer vers Supabase (si connecté)
                    if st.session_state.conn:
                        payload_hash = hash_file(proc_path)
                        push_to_quarantine(st.session_state.conn,
                                           st.session_state.org_id,
                                           st.session_state.endpoint_id,
                                           payload_hash, proc_path,
                                           result['score'],
                                           phi_m, phi_c, phi_d)
                        # On pourrait aussi blacklister l'IP source (non disponible ici)
                        push_to_threat_library(st.session_state.conn,
                                               proc_name,
                                               result['score'],
                                               phi_m, phi_c, phi_d)
                    # 6. Notification utilisateur (via st.toast, mais hors thread)
                    # On utilisera un flag pour afficher plus tard
                    st.session_state.last_alert = f"Menace neutralisée : {proc_name}"

            # Limiter la boucle pour ne pas surcharger le CPU
            time.sleep(2)

        except Exception as e:
            # Éviter de planter le thread
            print(f"Erreur dans monitoring_loop : {e}")
            time.sleep(5)


def start_protection():
    """Démarre le thread de surveillance."""
    if not st.session_state.protection_active:
        st.session_state.protection_active = True
        thread = threading.Thread(target=monitoring_loop, daemon=True)
        thread.start()
        st.session_state.monitor_thread = thread
        st.success("🛡️ Protection activée")


def stop_protection():
    """Arrête la protection."""
    st.session_state.protection_active = False
    # Le thread s'arrêtera à la prochaine itération (daemon)
    st.session_state.monitor_thread = None
    st.info("Protection désactivée")


# ─────────────────────────────────────────────
# INTERFACE SIDEBAR
# ─────────────────────────────────────────────

with st.sidebar:
    st.markdown("## ⬡ TTU Shield Sentinel")
    st.markdown("---")

    # Bouton de contrôle principal
    if st.session_state.protection_active:
        if st.button("🛑 DÉSACTIVER LA PROTECTION", use_container_width=True):
            stop_protection()
            st.rerun()
    else:
        if st.button("🛡️ ACTIVER LA PROTECTION", use_container_width=True, type="primary"):
            start_protection()
            st.rerun()

    st.markdown("---")
    st.markdown("### 📊 Statistiques")
    if st.session_state.history:
        last = st.session_state.history[-1]
        st.metric("Dernier score", f"{last['score']:.3f}")
        st.metric("Statut", last['status'])
    else:
        st.metric("Dernier score", "—")
        st.metric("Statut", "—")

    # Affichage de la connexion Supabase
    if st.session_state.conn:
        st.success("✅ Supabase connecté")
    else:
        st.warning("⚠️ Supabase non connecté")

    # Bouton pour vider l'historique (debug)
    if st.button("🗑 Réinitialiser", use_container_width=True):
        st.session_state.history = []
        st.session_state.attack_events = []
        st.rerun()


# ─────────────────────────────────────────────
# DASHBOARD PRINCIPAL
# ─────────────────────────────────────────────

st.title("🛡️ TTU Shield Sentinel – Édition EDR")
st.caption("Protection autonome par analyse triadique (Mémoire, Cohérence, Dissipation)")

# Gestion des alertes (affichage unique)
if 'last_alert' in st.session_state and st.session_state.last_alert:
    st.toast(st.session_state.last_alert, icon="🛡️")
    del st.session_state.last_alert

# Indicateur de protection en cours
if st.session_state.protection_active:
    st.markdown('<div class="alert-ok">✅ Protection active – surveillance en temps réel</div>',
                unsafe_allow_html=True)
else:
    st.markdown('<div class="alert-warning">⏸️ Protection désactivée – cliquez sur "ACTIVER" dans la sidebar</div>',
                unsafe_allow_html=True)

st.markdown("---")

# ── Ligne supérieure : jauge + métriques
col1, col2 = st.columns([1, 2])

with col1:
    # Jauge de l'état actuel
    if st.session_state.history:
        current_score = st.session_state.history[-1]['score']
        current_status = st.session_state.history[-1]['status']
    else:
        current_score = 0.0
        current_status = "NORMAL"

    # Couleur selon le statut
    gauge_color = "#4cffaa" if current_status == "NORMAL" else "#ffb347" if current_status == "ORANGE" else "#ff3b3b"

    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=current_score,
        number={'font': {'color': gauge_color, 'size': 40}},
        gauge={
            'axis': {'range': [0, 1], 'tickcolor': 'white'},
            'bar': {'color': gauge_color},
            'steps': [
                {'range': [0, 0.5], 'color': "#1a1a2e"},
                {'range': [0.5, 0.75], 'color': "#2a1a2e"},
                {'range': [0.75, 1], 'color': "#3a1a2e"}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 2},
                'thickness': 0.75,
                'value': current_score
            }
        }
    ))
    fig_gauge.update_layout(
        height=250,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor='#0d0d1a',
        font={'color': 'white'}
    )
    st.plotly_chart(fig_gauge, use_container_width=True)

with col2:
    # Métriques rapides
    if st.session_state.history:
        last = st.session_state.history[-1]
        col2a, col2b, col2c = st.columns(3)
        with col2a:
            st.metric("Seuil actuel", f"{last['threshold']:.3f}")
        with col2b:
            st.metric("Φm", f"{last['phi_m']:.2f}")
        with col2c:
            st.metric("Φc", f"{last['phi_c']:.2f}")
        # Deuxième ligne
        col2d, col2e, col2f = st.columns(3)
        with col2d:
            st.metric("Φd", f"{last['phi_d']:.2f}")
        with col2e:
            st.metric("K (auto)", f"{st.session_state.engine.k_factor:.2f}")
        with col2f:
            st.metric("Événements", len(st.session_state.history))
    else:
        st.info("En attente de données...")

st.markdown("---")

# ── Graphique des scores
if len(st.session_state.history) > 1:
    df = pd.DataFrame(st.session_state.history)
    df['time_str'] = df['time'].dt.strftime("%H:%M:%S")

    fig = make_subplots(rows=2, cols=1, shared_xaxes=True,
                        row_heights=[0.7, 0.3],
                        vertical_spacing=0.1)

    # Scores et seuil
    fig.add_trace(go.Scatter(x=df['time_str'], y=df['score'],
                              mode='lines+markers',
                              name='Score anomalie',
                              line=dict(color='#4fa8ff')), row=1, col=1)
    fig.add_trace(go.Scatter(x=df['time_str'], y=df['threshold'],
                              mode='lines',
                              name='Seuil adaptatif',
                              line=dict(color='#ffb347', dash='dash')), row=1, col=1)

    # Zones colorées selon le statut
    for status, color in [('NORMAL', '#4cffaa'), ('ORANGE', '#ffb347'), ('CRITICAL', '#ff3b3b')]:
        mask = df['status'] == status
        if mask.any():
            fig.add_trace(go.Scatter(x=df['time_str'][mask], y=df['score'][mask],
                                      mode='markers',
                                      name=status,
                                      marker=dict(color=color, size=8)), row=1, col=1)

    # Courbes Φ
    fig.add_trace(go.Scatter(x=df['time_str'], y=df['phi_m'],
                              name='Φm', line=dict(color='#4cffaa')), row=2, col=1)
    fig.add_trace(go.Scatter(x=df['time_str'], y=df['phi_c'],
                              name='Φc', line=dict(color='#4fa8ff')), row=2, col=1)
    fig.add_trace(go.Scatter(x=df['time_str'], y=df['phi_d'],
                              name='Φd', line=dict(color='#ff3b3b')), row=2, col=1)

    fig.update_layout(
        height=500,
        plot_bgcolor='#07070f',
        paper_bgcolor='#0d0d1a',
        font=dict(color='#888'),
        legend=dict(orientation='h', yanchor='bottom', y=1.02)
    )
    fig.update_yaxes(title_text="Score / Seuil", row=1, col=1, range=[0,1])
    fig.update_yaxes(title_text="Φ", row=2, col=1, range=[0,1])
    fig.update_xaxes(title_text="Temps", row=2, col=1)

    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("📊 En attente de données de surveillance...")

st.markdown("---")

# ── Carte mondiale des menaces
st.subheader("🌍 Cyber Threat Map – Détections mondiales")
if st.session_state.attack_events:
    fig_map = plot_cyber_map(st.session_state.attack_events)
    st.plotly_chart(fig_map, use_container_width=True)
else:
    st.caption("Aucune menace détectée pour le moment.")

# ── Derniers événements (tableau)
st.subheader("📋 Derniers événements")
if st.session_state.history:
    df_display = pd.DataFrame([
        {
            "Heure": e['time'].strftime("%H:%M:%S"),
            "Score": f"{e['score']:.3f}",
            "Seuil": f"{e['threshold']:.3f}",
            "Statut": e['status'],
            "Φm": f"{e['phi_m']:.2f}",
            "Φc": f"{e['phi_c']:.2f}",
            "Φd": f"{e['phi_d']:.2f}"
        }
        for e in st.session_state.history[-20:]
    ])
    st.dataframe(df_display, use_container_width=True, hide_index=True)
else:
    st.caption("Aucun événement.")

st.markdown("---")
st.caption(f"TTU Shield Sentinel EDR – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")