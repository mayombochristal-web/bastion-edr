"""
TTU-MC³ Shield Sentinel — Moteur Analytique Supra
===================================================
Implémente la logique complète :
  - Score d'anomalie pondéré A_s = K * (w_m·Φm + w_c·Φc + w_d·Φd) / (w_m+w_c+w_d)
  - Seuil adaptatif Baseline + σ (apprentissage 7 jours simulé)
  - Corrélation temporelle & réputation
  - Mécanique Quantum Bounty (ZKP challenge)
  - Tableau de bord Streamlit temps réel
  - Connexion optionnelle à Supabase pour données live
"""

import streamlit as st
import numpy as np
import pandas as pd
import time
import random
import math
from datetime import datetime, timedelta
from collections import deque
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Tentative d'import de psycopg2 pour Supabase (optionnel)
try:
    import psycopg2
    SUPPORTS_SUPABASE = True
except ImportError:
    SUPPORTS_SUPABASE = False

# ─────────────────────────────────────────────
# CONFIGURATION PAGE
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="TTU Shield Sentinel",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
# CSS THÈME
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
# MOTEUR MATHÉMATIQUE TTU
# ─────────────────────────────────────────────

class TTUEngine:
    """
    Moteur de calcul du score d'anomalie TTU-MC³.
    
    Formule centrale :
        A_s = K * (w_m·Φm + w_c·Φc + w_d·Φd) / (w_m + w_c + w_d)
    
    Avec correction réputation :
        A_s_corr = A_s * (1 - rep_shield * reputation_score/100)
    
    Seuil adaptatif :
        T_block = baseline_mean + n_sigma * baseline_std
    """

    def __init__(self, k_factor=1.0, weights=(1.0, 1.0, 1.5),
                 rep_shield=0.3, n_sigma=2.0, window_seconds=300):
        self.k_factor = k_factor
        self.w_m, self.w_c, self.w_d = weights
        self.rep_shield = rep_shield      # force du bouclier réputation [0,1]
        self.n_sigma = n_sigma            # nb d'écarts-types pour le seuil
        self.window_seconds = window_seconds  # fenêtre temporelle corrélation

        # Historique pour baseline (simulation 7j → 200 points)
        self.baseline_scores = deque(maxlen=200)
        self.event_window = deque(maxlen=50)   # événements récents

        # Baseline pré-chargée (phase apprentissage simulée)
        rng = np.random.default_rng(42)
        for _ in range(150):
            self.baseline_scores.append(rng.normal(0.25, 0.08))

    def raw_score(self, phi_m: float, phi_c: float, phi_d: float) -> float:
        """Score brut pondéré avant correction."""
        w_total = self.w_m + self.w_c + self.w_d
        return self.k_factor * (self.w_m * phi_m + self.w_c * phi_c + self.w_d * phi_d) / w_total

    def corrected_score(self, raw: float, reputation: float) -> float:
        """Score après bouclier réputation."""
        shield = self.rep_shield * (reputation / 100.0)
        return raw * (1.0 - shield)

    def adaptive_threshold(self) -> tuple[float, float, float]:
        """Retourne (baseline_mean, baseline_std, threshold)."""
        arr = np.array(self.baseline_scores)
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        threshold = mean + self.n_sigma * std
        return mean, std, min(threshold, 0.99)

    def temporal_velocity(self) -> float:
        """Vitesse d'incrémentation : nb d'anomalies dans la fenêtre / capacité."""
        now = time.time()
        recent = [e for e in self.event_window if now - e['ts'] <= self.window_seconds]
        if not recent:
            return 0.0
        anomalies = sum(1 for e in recent if e['score'] > 0.5)
        return min(anomalies / max(len(recent), 1), 1.0)

    def classify(self, corrected: float, threshold: float, velocity: float) -> str:
        """Classification : NORMAL / ORANGE (ZKP challenge) / CRITICAL (block)."""
        effective = corrected * (1.0 + 0.4 * velocity)
        if effective >= threshold:
            return "CRITICAL"
        elif effective >= threshold * 0.75:
            return "ORANGE"
        else:
            return "NORMAL"

    def process_event(self, phi_m, phi_c, phi_d, reputation=80.0) -> dict:
        """Pipeline complet pour un événement."""
        raw = self.raw_score(phi_m, phi_c, phi_d)
        raw = max(0.0, min(raw, 2.0))  # clamp
        corrected = self.corrected_score(raw, reputation)
        corrected = max(0.0, min(corrected, 1.0))

        mean, std, threshold = self.adaptive_threshold()
        velocity = self.temporal_velocity()

        status = self.classify(corrected, threshold, velocity)

        event = {
            'ts': time.time(),
            'phi_m': phi_m, 'phi_c': phi_c, 'phi_d': phi_d,
            'raw': raw, 'score': corrected,
            'threshold': threshold,
            'velocity': velocity,
            'reputation': reputation,
            'status': status,
            'time': datetime.now(),
            'mean': mean,
            'std': std
        }
        self.event_window.append(event)

        # Ajouter à la baseline seulement les événements normaux (apprentissage supervisé)
        if status == "NORMAL":
            self.baseline_scores.append(corrected)

        return event


# ─────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────
if 'engine' not in st.session_state:
    st.session_state.engine = TTUEngine()
if 'history' not in st.session_state:
    st.session_state.history = []
if 'running' not in st.session_state:
    st.session_state.running = False
if 'zkp_pending' not in st.session_state:
    st.session_state.zkp_pending = False
if 'zkp_challenge' not in st.session_state:
    st.session_state.zkp_challenge = None
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'use_live_data' not in st.session_state:
    st.session_state.use_live_data = False
if 'live_endpoints' not in st.session_state:
    st.session_state.live_endpoints = pd.DataFrame()


# ─────────────────────────────────────────────
# FONCTIONS SUPABASE (optionnel)
# ─────────────────────────────────────────────
import streamlit as st
import psycopg2
from psycopg2 import Error

# Activation du module de base de données
SUPPORTS_SUPABASE = True 

@st.cache_resource
def get_supabase_connection():
    """Établit la connexion avec les paramètres du Session Pooler IPv4."""
    if not SUPPORTS_SUPABASE:
        return None
        
    try:
        # Vérification de la présence de la section [postgres]
        if "postgres" not in st.secrets:
            st.sidebar.error("Configuration [postgres] introuvable dans les Secrets.")
            return None
            
        creds = st.secrets["postgres"]
        
        conn = psycopg2.connect(
            host=creds["host"],
            port=creds["port"],
            database=creds["database"],
            user=creds["user"],
            password=creds["password"],
            sslmode='require',
            connect_timeout=15  # Un peu plus de temps pour le pooler
        )
        return conn
    except Exception as e:
        st.sidebar.error(f"Échec de connexion Supabase : {e}")
        return None

# Initialisation
conn = get_supabase_connection()

if conn:
    st.sidebar.success("✅ Connecté à Supabase (Session Pooler)")
else:
    st.sidebar.warning("⚠️ Connexion à la base de données impossible")
  

# ─────────────────────────────────────────────
# SIDEBAR — CONTRÔLES
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⬡ TTU Shield Sentinel")
    st.markdown("---")

    st.markdown("### ∿ K-Factor")
    k_factor = st.slider("Sensibilité globale", 0.1, 3.0, 1.2, 0.05,
                         help="K élevé → ultra-nerveux. K faible → lisse les anomalies mineures.")
    st.caption(f"K = {k_factor:.2f} · {'🔴 Mode critique' if k_factor > 2.0 else '🟡 Mode équilibré' if k_factor > 1.0 else '🟢 Mode permissif'}")

    st.markdown("### Φ Poids Triadiques")
    w_m = st.slider("w_m (Mémoire)", 0.1, 3.0, 1.0, 0.1)
    w_c = st.slider("w_c (Cohérence)", 0.1, 3.0, 1.5, 0.1,
                    help="Prépondérant pour les serveurs de bases de données")
    w_d = st.slider("w_d (Dissipation)", 0.1, 3.0, 2.0, 0.1,
                    help="Prépondérant pour la détection d'exfiltration")

    st.markdown("### 🛡 Bouclier Réputation")
    rep_shield = st.slider("Force du bouclier", 0.0, 0.8, 0.3, 0.05,
                           help="0 = réputation ignorée, 0.8 = protection maximale")
    reputation = st.slider("Réputation endpoint (%)", 0, 100, 75, 5)

    st.markdown("### ⚙ Seuil Adaptatif")
    n_sigma = st.slider("n·σ (nb d'écarts-types)", 1.0, 4.0, 2.0, 0.25,
                        help="2σ ≈ 97.7% normale. 3σ ≈ 99.9% normale (moins de FP)")

    st.markdown("### ⏱ Fenêtre Temporelle")
    window_sec = st.slider("Fenêtre corrélation (sec)", 30, 600, 180, 30)

    st.markdown("---")

    # Mode live data (si Supabase configuré)
    if SUPPORTS_SUPABASE and st.secrets.get("supabase"):
        st.session_state.use_live_data = st.checkbox("🌐 Utiliser les données live Supabase", value=st.session_state.use_live_data)
        if st.session_state.use_live_data:
            if st.button("🔄 Rafraîchir endpoints"):
                st.session_state.live_endpoints = fetch_live_endpoints()
                st.rerun()
              
    # Mode live data (Utilise la connexion 'conn' établie plus haut)
    if conn:
        st.session_state.use_live_data = st.checkbox("🌐 Utiliser les données live Supabase", value=st.session_state.use_live_data)
        if st.session_state.use_live_data:
            if st.button("🔄 Rafraîchir endpoints"):
                # Assurez-vous que la fonction fetch_live_endpoints() est bien définie
                st.session_state.live_endpoints = fetch_live_endpoints()
                st.rerun()
    else:
        st.session_state.use_live_data = False

    st.markdown("### 💉 Injection de Menace (simulation)")
    inject_type = st.selectbox("Type", ["Trafic Normal", "Anomalie SQL", "RCE", "Brute Force", "Exfiltration"])
    if st.button("⚡ Injecter événement", use_container_width=True):
        scenarios = {
            "Trafic Normal":    (0.32, 0.86, 0.12),
            "Anomalie SQL":     (0.50, 0.28, 0.81),
            "RCE":              (0.91, 0.18, 0.96),
            "Brute Force":      (0.62, 0.38, 0.87),
            "Exfiltration":     (0.38, 0.12, 0.99),
        }
        phi_m, phi_c, phi_d = scenarios[inject_type]
        # Ajouter un peu de bruit
        phi_m = min(1.0, phi_m + random.gauss(0, 0.05))
        phi_c = min(1.0, phi_c + random.gauss(0, 0.05))
        phi_d = min(1.0, phi_d + random.gauss(0, 0.05))
        evt = st.session_state.engine.process_event(phi_m, phi_c, phi_d, reputation)
        st.session_state.history.append(evt)
        if evt['status'] != "NORMAL":
            st.session_state.alerts.insert(0, evt)
        st.rerun()

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶ Sim Auto", use_container_width=True):
            st.session_state.running = not st.session_state.running
    with col2:
        if st.button("🗑 Reset", use_container_width=True):
            st.session_state.history = []
            st.session_state.alerts = []
            st.session_state.zkp_pending = False
            st.session_state.zkp_challenge = None
            st.rerun()


# ─────────────────────────────────────────────
# MISE À JOUR DU MOTEUR
# ─────────────────────────────────────────────
engine = st.session_state.engine
engine.k_factor = k_factor
engine.w_m, engine.w_c, engine.w_d = w_m, w_c, w_d
engine.rep_shield = rep_shield
engine.n_sigma = n_sigma
engine.window_seconds = window_sec


# ─────────────────────────────────────────────
# SIMULATION AUTO
# ─────────────────────────────────────────────
if st.session_state.running and len(st.session_state.history) < 500:
    rng = np.random.default_rng()
    # 85% trafic normal, 15% anomalies
    if rng.random() < 0.15:
        phi_m = rng.uniform(0.5, 1.0)
        phi_c = rng.uniform(0.1, 0.5)
        phi_d = rng.uniform(0.6, 1.0)
    else:
        phi_m = rng.normal(0.35, 0.1)
        phi_c = rng.normal(0.8, 0.08)
        phi_d = rng.normal(0.15, 0.07)

    phi_m = float(np.clip(phi_m, 0.0, 1.0))
    phi_c = float(np.clip(phi_c, 0.0, 1.0))
    phi_d = float(np.clip(phi_d, 0.0, 1.0))

    evt = engine.process_event(phi_m, phi_c, phi_d, float(reputation))
    st.session_state.history.append(evt)
    if evt['status'] != "NORMAL":
        st.session_state.alerts.insert(0, evt)
        if evt['status'] == "ORANGE" and not st.session_state.zkp_pending:
            st.session_state.zkp_pending = True
            # Générer un défi ZKP
            challenge = {
                'code': random.randint(1000, 9999),
                'hash': hex(random.randint(0xABCD0000, 0xABCDFFFF)),
                'expires': datetime.now() + timedelta(seconds=60),
                'event': evt
            }
            st.session_state.zkp_challenge = challenge

    time.sleep(0.3)
    st.rerun()


# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown("# ⬡ TTU · Shield Sentinel")
    st.caption("Moteur Analytique MC³ · Détection / Faux Positifs · Quantum Bounty")
with col_h2:
    mean_b, std_b, thresh = engine.adaptive_threshold()
    st.metric("Seuil Adaptatif", f"{thresh:.3f}", delta=f"{mean_b:.3f} ± {std_b:.3f}")

st.markdown("---")

# ─────────────────────────────────────────────
# FORMULE AFFICHÉE
# ─────────────────────────────────────────────
with st.expander("📐 Formule du Score d'Anomalie TTU (développée)", expanded=False):
    w_total = w_m + w_c + w_d
    st.markdown(f"""
    <div class="formula-box">
    <b>Score Brut :</b><br>
    &nbsp;&nbsp;A_s = K · (w_m·Φm + w_c·Φc + w_d·Φd) / (w_m + w_c + w_d)<br>
    &nbsp;&nbsp;A_s = {k_factor:.2f} · ({w_m:.1f}·Φm + {w_c:.1f}·Φc + {w_d:.1f}·Φd) / {w_total:.1f}<br><br>
    <b>Correction Réputation :</b><br>
    &nbsp;&nbsp;A_corr = A_s · (1 − {rep_shield:.2f} · rep/100)<br>
    &nbsp;&nbsp;Shield actuel : {rep_shield * reputation / 100:.3f} (rep={reputation}%)<br><br>
    <b>Score Effectif (avec vélocité temporelle v) :</b><br>
    &nbsp;&nbsp;A_eff = A_corr · (1 + 0.4·v)<br><br>
    <b>Seuil Adaptatif :</b><br>
    &nbsp;&nbsp;T = μ_baseline + {n_sigma:.1f}·σ = {mean_b:.4f} + {n_sigma:.1f}·{std_b:.4f} = <b>{thresh:.4f}</b><br><br>
    <b>Niveaux :</b><br>
    &nbsp;&nbsp;NORMAL &nbsp;&nbsp;→ A_eff &lt; {thresh*0.75:.4f} (T·75%)<br>
    &nbsp;&nbsp;ORANGE &nbsp;&nbsp;→ A_eff ∈ [{thresh*0.75:.4f}, {thresh:.4f}) → Défi ZKP<br>
    &nbsp;&nbsp;CRITICAL → A_eff ≥ {thresh:.4f} → Blocage immédiat
    </div>
    """, unsafe_allow_html=True)

# ─────────────────────────────────────────────
# KPIS GLOBAUX
# ─────────────────────────────────────────────
hist = st.session_state.history
n_total = len(hist)
n_crit = sum(1 for e in hist if e['status'] == "CRITICAL")
n_orange = sum(1 for e in hist if e['status'] == "ORANGE")
n_normal = sum(1 for e in hist if e['status'] == "NORMAL")
fp_rate = (n_orange / max(n_total, 1)) * 100
detection_rate = (n_crit / max(n_total, 1)) * 100

c1, c2, c3, c4, c5, c6 = st.columns(6)
with c1: st.metric("Événements", n_total)
with c2: st.metric("🔴 Critiques", n_crit, delta=None)
with c3: st.metric("🟡 Orange (ZKP)", n_orange)
with c4: st.metric("🟢 Normaux", n_normal)
with c5: st.metric("Taux Détection", f"{detection_rate:.1f}%")
with c6: st.metric("Taux ZKP/Orange", f"{fp_rate:.1f}%")

st.markdown("---")

# ─────────────────────────────────────────────
# QUANTUM BOUNTY — ZKP CHALLENGE
# ─────────────────────────────────────────────
if st.session_state.zkp_pending and st.session_state.zkp_challenge:
    ch = st.session_state.zkp_challenge
    evt = ch['event']
    remaining = max(0, (ch['expires'] - datetime.now()).seconds)
    st.markdown(f"""
    <div class="alert-warning">
    ⚡ <b>QUANTUM BOUNTY — Défi de Légitimité Requis</b><br>
    Score anomalie : <b>{evt['score']:.4f}</b> (seuil orange : {evt['threshold']*0.75:.4f})<br>
    Hash du défi : <code>{ch['hash']}</code> · Expire dans : <b>{remaining}s</b><br>
    Répondez pour réinitialiser le score et éviter l'escalade.
    </div>
    """, unsafe_allow_html=True)

    zkp_col1, zkp_col2, zkp_col3 = st.columns([2, 1, 1])
    with zkp_col1:
        answer = st.text_input("Code de réponse ZKP :", placeholder=f"Entrez votre token (indice: {ch['code'] // 10}xx)", label_visibility="collapsed")
    with zkp_col2:
        if st.button("✅ Valider Défi", use_container_width=True):
            if answer.strip() == str(ch['code']):
                st.success("✅ Défi réussi — Score réinitialisé. Aucun blocage.")
                st.session_state.zkp_pending = False
                # Ajouter un événement de réinitialisation
                engine.baseline_scores.append(0.1)
                st.rerun()
            else:
                st.error("❌ Réponse incorrecte — Escalade vers CRITICAL")
                st.session_state.zkp_pending = False
                if st.session_state.history:
                    st.session_state.history[-1]['status'] = "CRITICAL"
                st.rerun()
    with zkp_col3:
        if st.button("🚫 Ignorer (escalade)", use_container_width=True):
            st.session_state.zkp_pending = False
            st.rerun()
    st.markdown("---")

# ─────────────────────────────────────────────
# AFFICHAGE DES ENDPOINTS LIVE (si activé)
# ─────────────────────────────────────────────
if st.session_state.use_live_data:
    st.subheader("🌐 Endpoints en direct (Supabase)")
    if st.session_state.live_endpoints.empty:
        if st.button("Charger les endpoints"):
            st.session_state.live_endpoints = fetch_live_endpoints()
    else:
        df = st.session_state.live_endpoints
        for index, row in df.iterrows():
            col_a, col_b, col_c = st.columns([1, 2, 1])
            with col_a:
                st.write(f"**{row['pseudo']}**")
                st.caption(f"{row['os']} | {row['ip_address']}")
            with col_b:
                st.progress(row['phi_m'], text=f"Φm: {int(row['phi_m']*100)}%")
            with col_c:
                status_color = "🟢" if row['protection_status'] == "Actif" else "🔴"
                st.write(f"{status_color} {row['protection_status']}")
        st.caption(f"Dernière mise à jour : {datetime.now().strftime('%H:%M:%S')}")
    st.markdown("---")


# ─────────────────────────────────────────────
# GRAPHIQUES PRINCIPAUX
# ─────────────────────────────────────────────
if len(hist) < 3:
    st.info("⬡ Injectez des événements via la sidebar ou lancez la simulation automatique pour voir les courbes TTU.")
else:
    df = pd.DataFrame(hist)
    df['time_str'] = df['time'].dt.strftime("%H:%M:%S")
    n_display = min(len(df), 120)
    df_plot = df.tail(n_display).reset_index(drop=True)

    # ── FIGURE 1 : Score d'anomalie + seuil adaptatif + statuts
    fig1 = make_subplots(
        rows=2, cols=1,
        row_heights=[0.65, 0.35],
        shared_xaxes=True,
        vertical_spacing=0.06,
        subplot_titles=["Score d'Anomalie Corrigé vs Seuil Adaptatif", "Vecteur Triadique Φ (Φm / Φc / Φd)"]
    )

    # Zones de couleur pour les niveaux
    thresh_val = df_plot['threshold'].iloc[-1]
    fig1.add_hrect(y0=thresh_val, y1=1.1, fillcolor="#ff3b3b", opacity=0.06,
                   line_width=0, row=1, col=1, annotation_text="CRITICAL", annotation_position="right")
    fig1.add_hrect(y0=thresh_val * 0.75, y1=thresh_val, fillcolor="#ffb347", opacity=0.06,
                   line_width=0, row=1, col=1, annotation_text="ORANGE / ZKP", annotation_position="right")
    fig1.add_hrect(y0=0, y1=thresh_val * 0.75, fillcolor="#4cffaa", opacity=0.04,
                   line_width=0, row=1, col=1, annotation_text="NORMAL", annotation_position="right")

    # Seuil adaptatif
    fig1.add_trace(go.Scatter(
        x=df_plot['time_str'], y=df_plot['threshold'],
        name="Seuil T=μ+nσ", line=dict(color="#ffb347", dash="dash", width=1.5),
        opacity=0.9
    ), row=1, col=1)

    # Score par statut (couleurs distinctes)
    for status, color in [("NORMAL", "#4cffaa"), ("ORANGE", "#ffb347"), ("CRITICAL", "#ff3b3b")]:
        mask = df_plot['status'] == status
        sub = df_plot[mask]
        if not sub.empty:
            fig1.add_trace(go.Scatter(
                x=sub['time_str'], y=sub['score'],
                mode='markers', name=status,
                marker=dict(color=color, size=6 if status == "NORMAL" else 10,
                            symbol="circle" if status == "NORMAL" else "diamond",
                            line=dict(color=color, width=1)),
                opacity=0.9
            ), row=1, col=1)

    # Courbe score continue
    fig1.add_trace(go.Scatter(
        x=df_plot['time_str'], y=df_plot['score'],
        name="A_s corrigé", line=dict(color="#4fa8ff", width=1.5),
        fill='tozeroy', fillcolor="rgba(79,168,255,0.05)", opacity=0.7
    ), row=1, col=1)

    # Courbes Φ
    for col_name, color, label in [
        ("phi_m", "#4cffaa", "Φm Mémoire"),
        ("phi_c", "#4fa8ff", "Φc Cohérence"),
        ("phi_d", "#ff3b3b", "Φd Dissipation"),
    ]:
        fig1.add_trace(go.Scatter(
            x=df_plot['time_str'], y=df_plot[col_name],
            name=label, line=dict(color=color, width=1.5),
            opacity=0.85
        ), row=2, col=1)

    fig1.update_layout(
        height=520,
        plot_bgcolor="#07070f", paper_bgcolor="#0d0d1a",
        font=dict(family="JetBrains Mono", color="#888", size=11),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=10, r=80, t=40, b=10),
        hovermode="x unified"
    )

    # Ajustements des axes
    fig1.update_yaxes(title_text="Score / Seuil", row=1, col=1, range=[0, 1.1])
    fig1.update_yaxes(title_text="Φ", row=2, col=1, range=[0, 1.1])
    fig1.update_xaxes(title_text="Temps", row=2, col=1)

    st.plotly_chart(fig1, use_container_width=True)

    # ── FIGURE 2 : Histogramme de distribution des scores
    st.subheader("📊 Distribution des scores d'anomalie")
    fig2 = go.Figure()
    fig2.add_trace(go.Histogram(
        x=df['score'],
        nbinsx=30,
        marker_color="#4fa8ff",
        opacity=0.7,
        name="Scores"
    ))
    # Ligne du seuil actuel
    fig2.add_vline(x=thresh_val, line_dash="dash", line_color="#ffb347", annotation_text=f"Seuil {thresh_val:.3f}")
    fig2.add_vline(x=thresh_val*0.75, line_dash="dot", line_color="#4cffaa", annotation_text="75% seuil")
    fig2.update_layout(
        plot_bgcolor="#07070f", paper_bgcolor="#0d0d1a",
        font=dict(color="#888"),
        xaxis_title="Score d'anomalie",
        yaxis_title="Fréquence",
        bargap=0.05
    )
    st.plotly_chart(fig2, use_container_width=True)

# ─────────────────────────────────────────────
# TABLEAU DES DERNIERS ÉVÉNEMENTS
# ─────────────────────────────────────────────
st.subheader("📋 Derniers événements")
if hist:
    df_display = pd.DataFrame([
        {
            "Heure": e['time'].strftime("%H:%M:%S"),
            "Φm": f"{e['phi_m']:.2f}",
            "Φc": f"{e['phi_c']:.2f}",
            "Φd": f"{e['phi_d']:.2f}",
            "Score": f"{e['score']:.3f}",
            "Seuil": f"{e['threshold']:.3f}",
            "Statut": e['status'],
        }
        for e in hist[-20:]
    ])
    st.dataframe(df_display, use_container_width=True, hide_index=True)
else:
    st.caption("Aucun événement pour l'instant.")

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.markdown("---")
st.caption(f"Architecture Supra-Détaillée | TTU-MC³ Engine | Sync-K: {k_factor:.2f} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
