#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU BASTION EDR - Cockpit Souverain (version compatible ttu_core)
Connexion PostgreSQL avec SQLAlchemy, tables dans le schéma ttu_core.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
import time

# =====================================================
# CONFIGURATION DE LA PAGE (thème sombre)
# =====================================================
st.set_page_config(
    page_title="TTU‑MC³ Bastion EDR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personnalisé
st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #fafafa; }
    .stSidebar { background-color: #1e2128; }
    h1, h2, h3 { color: #00ffaa !important; }
    .stMetric {
        background-color: #1e2128;
        padding: 10px;
        border-radius: 5px;
        border-left: 3px solid #00ffaa;
    }
    .stButton>button {
        background-color: #00ffaa;
        color: #0e1117;
        font-weight: bold;
        border: none;
    }
    .stButton>button:hover { background-color: #00cc88; }
    .stAlert { background-color: #332222; border-left-color: #ff5555; }
</style>
""", unsafe_allow_html=True)

# =====================================================
# CONNEXION À LA BASE
# =====================================================
@st.cache_resource
def init_engine():
    host = st.secrets["DB_HOST"]
    port = st.secrets["DB_PORT"]
    dbname = st.secrets["DB_NAME"]
    user = st.secrets["DB_USER"]
    password = st.secrets["DB_PASSWORD"]
    conn_str = f"postgresql+pg8000://{user}:{password}@{host}:{port}/{dbname}"
    return create_engine(conn_str, pool_pre_ping=True)

engine = init_engine()

# =====================================================
# FONCTIONS D'ACCÈS AUX DONNÉES (avec cache)
# =====================================================
@st.cache_data(ttl=10)
def get_orgs():
    query = """
        SELECT id, name, k_factor, adaptive_threshold, bypass_quota
        FROM ttu_core.organizations
        ORDER BY name
    """
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

@st.cache_data(ttl=10)
def get_endpoints(org_id=None):
    query = """
        SELECT id, org_id, name, ip_address, os, protection_status, last_seen
        FROM ttu_core.endpoints
    """
    params = {}
    if org_id:
        query += " WHERE org_id = :org_id"
        params["org_id"] = org_id
    query += " ORDER BY ip_address"
    with engine.connect() as conn:
        return pd.read_sql(text(query), conn, params=params)

@st.cache_data(ttl=10)
def get_audit_logs(org_id=None, limit=500):
    query = """
        SELECT id, org_id, endpoint_id, timestamp, kmass_score, ml_anomaly_score,
               signature_match, status
        FROM ttu_core.audit_logs_global
    """
    params = {}
    if org_id:
        query += " WHERE org_id = :org_id"
        params["org_id"] = org_id
    query += " ORDER BY timestamp DESC LIMIT :limit"
    params["limit"] = limit
    with engine.connect() as conn:
        return pd.read_sql(text(query), conn, params=params)

@st.cache_data(ttl=30)
def get_quarantine(org_id=None):
    query = """
        SELECT q.id, q.org_id, q.endpoint_id, q.payload_hash, q.reason,
               q.quarantined_at, q.analyzed,
               e.name as endpoint_name, e.ip_address as endpoint_ip
        FROM ttu_core.quarantine_vault q
        LEFT JOIN ttu_core.endpoints e ON q.endpoint_id = e.id
    """
    params = {}
    if org_id:
        query += " WHERE q.org_id = :org_id"
        params["org_id"] = org_id
    query += " ORDER BY q.quarantined_at DESC"
    with engine.connect() as conn:
        return pd.read_sql(text(query), conn, params=params)

@st.cache_data(ttl=60)
def get_subscriptions(org_id=None):
    query = """
        SELECT org_id, plan_name, start_date, end_date, logs_quota
        FROM ttu_core.subscriptions
    """
    params = {}
    if org_id:
        query += " WHERE org_id = :org_id"
        params["org_id"] = org_id
    query += " ORDER BY start_date DESC"
    with engine.connect() as conn:
        return pd.read_sql(text(query), conn, params=params)

@st.cache_data(ttl=60)
def get_logs_per_second(org_id=None, minutes=5):
    query = """
        SELECT
            date_trunc('minute', timestamp) as minute,
            COUNT(*) as logs
        FROM ttu_core.audit_logs_global
        WHERE timestamp > NOW() - INTERVAL ':minutes minutes'
    """
    params = {"minutes": minutes}
    if org_id:
        query += " AND org_id = :org_id"
        params["org_id"] = org_id
    query += " GROUP BY minute ORDER BY minute"
    with engine.connect() as conn:
        df = pd.read_sql(text(query), conn, params=params)
    if not df.empty:
        return df['logs'].sum() / (minutes * 60)
    return 0.0

# =====================================================
# BATTEMENT DE CŒUR
# =====================================================
def run_heartbeat():
    with engine.connect() as conn:
        conn.execute(text("SELECT ttu_core.heartbeat_modulation()"))
        conn.commit()
    st.cache_data.clear()
    st.success("✅ Battement de cœur exécuté – membrane adaptative recalculée.")
    time.sleep(1)
    st.rerun()

# =====================================================
# SIDEBAR
# =====================================================
def sidebar():
    with st.sidebar:
        st.image("https://via.placeholder.com/200x80?text=TTU+BASTION", use_column_width=True)
        st.markdown("## 🧠 Membrane Adaptive")

        orgs = get_orgs()
        org_names = ["Toutes"] + orgs['name'].tolist()
        selected_org_name = st.selectbox("Organisation", org_names)

        if selected_org_name != "Toutes":
            org_id = orgs[orgs['name'] == selected_org_name]['id'].iloc[0]
            st.session_state['org_id'] = org_id
            org_row = orgs[orgs['id'] == org_id].iloc[0]
            st.metric("Courbure k", f"{org_row['k_factor']:.3f}")
            st.metric("Seuil adaptatif", f"{org_row['adaptive_threshold']:.2f}")
        else:
            st.session_state['org_id'] = None
            avg_k = orgs['k_factor'].mean()
            avg_th = orgs['adaptive_threshold'].mean()
            st.metric("Courbure moyenne", f"{avg_k:.3f}")
            st.metric("Seuil moyen", f"{avg_th:.2f}")

        if st.button("💓 Déclencher battement de cœur"):
            run_heartbeat()

        st.markdown("---")
        st.markdown("### Navigation")
        pages = ["🏠 Tableau de bord", "🖥️ Endpoints", "⚠️ Menaces", "🔒 Quarantaine", "📊 Abonnements", "📘 Documentation"]
        choice = st.radio("Aller à", pages, index=0, label_visibility="collapsed")
        return choice

# =====================================================
# PAGES
# =====================================================
def dashboard_page():
    st.title("🛡️ Tableau de bord SOC")
    org_id = st.session_state.get('org_id')

    logs_df = get_audit_logs(org_id, limit=100)
    endpoints_df = get_endpoints(org_id)
    quarantine_df = get_quarantine(org_id)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Endpoints actifs", len(endpoints_df[endpoints_df['protection_status']=='Actif']))
    with col2:
        recent_logs = logs_df[pd.to_datetime(logs_df['timestamp']) > datetime.now() - timedelta(days=1)]
        st.metric("Logs (24h)", len(recent_logs))
    with col3:
        st.metric("En quarantaine", len(quarantine_df))
    with col4:
        avg_k = get_orgs()['k_factor'].mean()
        st.metric("Courbure globale", f"{avg_k:.3f}")

    st.subheader("📈 Courbure k par organisation")
    orgs = get_orgs()
    if not orgs.empty:
        fig = px.bar(orgs, x='name', y='k_factor', title="Facteur de courbure k",
                     color='k_factor', color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("📋 Derniers événements")
    if not logs_df.empty:
        display_logs = logs_df[['timestamp','endpoint_id','status','ml_anomaly_score','signature_match']].head(10)
        st.dataframe(display_logs, use_container_width=True)
    else:
        st.info("Aucun log récent.")

    st.subheader("📊 Scores d'anomalie (temps réel)")
    if not logs_df.empty:
        logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
        logs_df = logs_df.sort_values('timestamp')
        fig2 = px.line(logs_df, x='timestamp', y='ml_anomaly_score', title="Évolution des scores ML")
        st.plotly_chart(fig2, use_container_width=True)

def endpoints_page():
    st.title("🖥️ Endpoints")
    org_id = st.session_state.get('org_id')
    endpoints = get_endpoints(org_id)

    if endpoints.empty:
        st.warning("Aucun endpoint trouvé.")
        return

    status_filter = st.multiselect("Statut", options=endpoints['protection_status'].unique(),
                                   default=endpoints['protection_status'].unique())
    filtered = endpoints[endpoints['protection_status'].isin(status_filter)]
    st.dataframe(filtered, use_container_width=True)

def threats_page():
    st.title("⚠️ Analyse des menaces")
    org_id = st.session_state.get('org_id')
    logs = get_audit_logs(org_id, limit=2000)

    if logs.empty:
        st.warning("Aucune donnée d'audit.")
        return

    fig = px.scatter(logs, x='timestamp', y='ml_anomaly_score', color='status',
                     title="Scores d'anomalie ML", hover_data=['signature_match'])
    st.plotly_chart(fig, use_container_width=True)

    if 'signature_match' in logs.columns:
        sig_counts = logs['signature_match'].value_counts().reset_index()
        sig_counts.columns = ['signature', 'count']
        fig2 = px.bar(sig_counts.head(20), x='signature', y='count', title="Top signatures")
        st.plotly_chart(fig2, use_container_width=True)

def quarantine_page():
    st.title("🔒 Quarantaine")
    org_id = st.session_state.get('org_id')
    qdata = get_quarantine(org_id)

    if qdata.empty:
        st.info("Aucun élément en quarantaine.")
        return

    st.dataframe(qdata[['id','endpoint_ip','payload_hash','reason','quarantined_at','analyzed']],
                 use_container_width=True)

    if st.button("🔬 Analyser les éléments non analysés (simulation)"):
        st.success("Analyse déclenchée !")

def subscriptions_page():
    st.title("📊 Abonnements")
    org_id = st.session_state.get('org_id')
    subs = get_subscriptions(org_id)

    if subs.empty:
        st.info("Aucun abonnement trouvé.")
    else:
        st.dataframe(subs, use_container_width=True)

    if org_id:
        logs_per_sec = get_logs_per_second(org_id, minutes=5)
        st.metric("Logs par seconde (moy. 5 min)", f"{logs_per_sec:.2f}")

        active_subs = subs[subs['end_date'] > datetime.now()] if not subs.empty else pd.DataFrame()
        if not active_subs.empty:
            quota_row = active_subs.iloc[0]
            quota = quota_row['logs_quota']
            if quota:
                used = len(get_audit_logs(org_id, limit=100000))
                remaining = max(0, quota - used)
                st.progress(min(1.0, used/quota), text=f"Utilisation: {used}/{quota}")
                st.metric("Restant", remaining)

def documentation_page():
    st.title("📘 Documentation utilisateur")
    st.markdown("""
    ### Bienvenue dans TTU‑MC³ Bastion EDR

    **Qu'est-ce que la membrane adaptive ?**
    Notre technologie traite la cybersécurité comme un organisme vivant. Au lieu de règles statiques, nous utilisons une **courbure k** qui se contracte ou se relâche en fonction du flux de données (logs par seconde). Cela permet d'absorber les pics de charge et de dissiper les menaces naturellement.

    **Concepts clés :**
    - **Courbure k** : facteur dynamique qui augmente avec la charge. Plus k est élevé, plus le système devient "sensible" et renforce ses contrôles.
    - **Seuil adaptatif** : seuil de détection ajusté automatiquement en fonction de k. Il se resserre quand la charge augmente pour éviter les faux négatifs.
    - **Dissipation** : les événements suspects sont placés dans un vault (quarantaine) en attendant une analyse plus poussée.

    **Fonctionnement du quota :**
    - Chaque organisation bénéficie d'un nombre de logs mensuels selon son abonnement (Essai : 1000 logs, Souverain : illimité).
    - Un trigger vérifie automatiquement le quota avant chaque insertion. Si dépassé, l'insertion est bloquée.
    - L'organisation administrateur (mayombochristal@gmail.com) est exemptée de cette limitation.

    **Battement de cœur** : toutes les minutes, une fonction recalcule la courbure k de chaque organisation active. Vous pouvez également le déclencher manuellement via le bouton dans la barre latérale.

    **Navigation :**
    - Tableau de bord : vue d'ensemble des métriques clés.
    - Endpoints : liste des machines protégées.
    - Menaces : visualisation des scores d'anomalie et signatures.
    - Quarantaine : éléments isolés.
    - Abonnements : gestion des plans.

    Pour toute question, contactez **Mayombo Idiedie Christ Aldo** à mayombochristal@gmail.com.
    """)

# =====================================================
# MAIN
# =====================================================
def main():
    choice = sidebar()

    if choice == "🏠 Tableau de bord":
        dashboard_page()
    elif choice == "🖥️ Endpoints":
        endpoints_page()
    elif choice == "⚠️ Menaces":
        threats_page()
    elif choice == "🔒 Quarantaine":
        quarantine_page()
    elif choice == "📊 Abonnements":
        subscriptions_page()
    elif choice == "📘 Documentation":
        documentation_page()

if __name__ == "__main__":
    main()
