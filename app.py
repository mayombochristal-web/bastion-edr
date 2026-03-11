#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU BASTION EDR - Cockpit adapté à la base de données réelle
Utilise les tables public.* et les colonnes phi_m, phi_c, phi_d.
Connexion PostgreSQL directe via psycopg2.
"""

import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
import json

# =====================================================
# CONFIGURATION DE LA PAGE
# =====================================================
st.set_page_config(
    page_title="TTU‑MC³ Cyber Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================
# CONNEXION À LA BASE (via secrets.toml)
# =====================================================
@st.cache_resource
def init_connection():
    """Retourne une connexion PostgreSQL persistante."""
    try:
        conn = psycopg2.connect(
            host=st.secrets["DB_HOST"],
            port=st.secrets["DB_PORT"],
            dbname=st.secrets["DB_NAME"],
            user=st.secrets["DB_USER"],
            password=st.secrets["DB_PASSWORD"],
            cursor_factory=RealDictCursor
        )
        return conn
    except Exception as e:
        st.error(f"Erreur de connexion à la base : {e}")
        return None

conn = init_connection()

# =====================================================
# FONCTIONS D'ACCÈS AUX DONNÉES (avec cache)
# =====================================================
@st.cache_data(ttl=60)
def get_organizations():
    query = "SELECT id, name, global_reputation_score, phi_m, phi_c, phi_d FROM organizations ORDER BY name;"
    return pd.read_sql(query, conn)

@st.cache_data(ttl=30)
def get_endpoints(org_id=None):
    query = "SELECT id, org_id, ip_address, os, protection_status, last_sync, phi_m, phi_c, phi_d FROM endpoints"
    params = []
    if org_id:
        query += " WHERE org_id = %s"
        params.append(org_id)
    query += " ORDER BY ip_address;"
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=30)
def get_audit_logs(org_id=None, limit=1000):
    query = """
        SELECT id, org_id, endpoint_id, timestamp, payload_extrait, kmass_score,
               signature_match, status, ml_anomaly_score, reputation_score, ip,
               phi_m, phi_c, phi_d
        FROM audit_logs_global
    """
    params = []
    if org_id:
        query += " WHERE org_id = %s"
        params.append(org_id)
    query += " ORDER BY timestamp DESC LIMIT %s;"
    params.append(limit)
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=60)
def get_blacklisted_entities(org_id=None):
    query = "SELECT id, org_id, ip_address, ban_depth, reason, expires_at, phi_m, phi_c, phi_d FROM blacklisted_entities"
    params = []
    if org_id:
        query += " WHERE org_id = %s"
        params.append(org_id)
    query += " ORDER BY created_at DESC;"
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=60)
def get_quarantine_vault(org_id=None):
    query = """
        SELECT q.id, q.org_id, q.endpoint_id, q.payload_hash, q.payload, q.reason,
               q.quarantined_at, q.analyzed, q.phi_m, q.phi_c, q.phi_d,
               e.ip_address as endpoint_ip
        FROM quarantine_vault q
        LEFT JOIN endpoints e ON q.endpoint_id = e.id
    """
    params = []
    if org_id:
        query += " WHERE q.org_id = %s"
        params.append(org_id)
    query += " ORDER BY q.quarantined_at DESC;"
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=120)
def get_triad_metrics(entity_type=None, entity_id=None, hours=24):
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    query = "SELECT id, entity_type, entity_id, phi_m, phi_c, phi_d, recorded_at FROM triad_metrics WHERE recorded_at >= %s"
    params = [since]
    if entity_type:
        query += " AND entity_type = %s"
        params.append(entity_type)
    if entity_id:
        query += " AND entity_id = %s"
        params.append(entity_id)
    query += " ORDER BY recorded_at;"
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=60)
def get_playbooks(org_id=None):
    query = "SELECT id, org_id, name, trigger_condition, actions, enabled, created_at, phi_m, phi_c, phi_d FROM playbooks"
    params = []
    if org_id:
        query += " WHERE org_id = %s"
        params.append(org_id)
    query += " ORDER BY name;"
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=60)
def get_utilisateurs_secure(org_id=None):
    query = """
        SELECT u.id, u.org_id, u.pseudo, u.accreditation_level,
               u.public_encryption_key, u.registered_at, u.phi_m, u.phi_c, u.phi_d
        FROM utilisateurs_secure u
    """
    params = []
    if org_id:
        query += " WHERE u.org_id = %s"
        params.append(org_id)
    query += " ORDER BY u.pseudo;"
    return pd.read_sql(query, conn, params=params)

@st.cache_data(ttl=60)
def get_users():
    query = "SELECT id, email, full_name, company_name, phone, is_active, phi_m, phi_c, phi_d FROM users ORDER BY email;"
    return pd.read_sql(query, conn)

@st.cache_data(ttl=60)
def get_free_trials():
    query = "SELECT id, user_id, scans_used, scans_total, trial_start, trial_end, status FROM free_trials ORDER BY trial_start DESC;"
    return pd.read_sql(query, conn)

# =====================================================
# FONCTIONS DE CALCUL COMPLÉMENTAIRES
# =====================================================
def compute_stress_from_phi(row):
    """Calcule une métrique de stress à partir des composantes triadiques."""
    # Exemple : norme euclidienne (énergie)
    return np.sqrt(row['phi_m']**2 + row['phi_c']**2 + row['phi_d']**2)

def compute_contraction_factor(stress):
    """Simule le facteur de contraction utilisé dans le document original."""
    # basé sur la formule : 1 / (1 + stress/20)
    return 1.0 / (1.0 + stress / 20.0)

# =====================================================
# SIDEBAR
# =====================================================
def sidebar():
    with st.sidebar:
        st.image("https://via.placeholder.com/200x80?text=TTU+BASTION+EDR", use_column_width=True)
        st.markdown("## 🧠 État triadique global")

        orgs = get_organizations()
        if not orgs.empty:
            # Moyenne des phi sur toutes les organisations
            avg_phi_m = orgs['phi_m'].mean()
            avg_phi_c = orgs['phi_c'].mean()
            avg_phi_d = orgs['phi_d'].mean()
            stress = compute_stress_from_phi({'phi_m': avg_phi_m, 'phi_c': avg_phi_c, 'phi_d': avg_phi_d})
        else:
            avg_phi_m = avg_phi_c = avg_phi_d = 0.0
            stress = 0.0

        col1, col2, col3 = st.columns(3)
        col1.metric("Φ_M (Mémoire)", f"{avg_phi_m:.3f}")
        col2.metric("Φ_C (Cohérence)", f"{avg_phi_c:.3f}")
        col3.metric("Φ_D (Dissipation)", f"{avg_phi_d:.3f}")

        contraction = compute_contraction_factor(stress)
        st.metric("Facteur de contraction", f"{contraction:.3f}")
        st.progress(min(1.0, stress/10), text="Stress global")

        st.markdown("---")
        st.markdown("### 🔄 Actions rapides")
        if st.button("🔄 Rafraîchir toutes les données"):
            st.cache_data.clear()
            st.rerun()

        st.markdown("---")
        st.markdown("**TTU BASTION EDR**  \nAdapté à la base réelle  \n© 2026")

# =====================================================
# PAGES
# =====================================================
def home_page():
    st.title("🛡️ Tableau de bord TTU‑MC³")
    st.markdown("Surveillance en temps réel des endpoints, menaces et état triadique.")

    org_id = st.session_state.get("org_id")  # sera défini plus tard si besoin

    # Statistiques rapides
    endpoints = get_endpoints(org_id)
    blacklist = get_blacklisted_entities(org_id)
    quarantine = get_quarantine_vault(org_id)
    logs = get_audit_logs(org_id, limit=100)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Endpoints actifs", len(endpoints[endpoints['protection_status']=='Actif']))
    col2.metric("Entités blacklistées", len(blacklist))
    col3.metric("Éléments en quarantaine", len(quarantine))
    col4.metric("Événements récents", len(logs))

    # Évolution triadique globale (dernières 24h)
    st.subheader("📈 Évolution triadique (moyenne des endpoints)")
    triad = get_triad_metrics(entity_type='endpoint', hours=24)
    if not triad.empty:
        triad['hour'] = pd.to_datetime(triad['recorded_at']).dt.floor('H')
        hourly = triad.groupby('hour')[['phi_m','phi_c','phi_d']].mean().reset_index()
        fig = px.line(hourly, x='hour', y=['phi_m','phi_c','phi_d'],
                      title="Moyenne des composantes triadiques (endpoints)")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Aucune donnée triadique pour les dernières 24h.")

    # Derniers événements d'audit
    st.subheader("📋 Derniers événements")
    if not logs.empty:
        st.dataframe(logs[['timestamp','endpoint_id','status','ml_anomaly_score','signature_match']].head(10),
                     use_container_width=True)

def endpoints_page():
    st.title("🖥️ Gestion des endpoints")
    org_id = st.session_state.get("org_id")
    endpoints = get_endpoints(org_id)

    if endpoints.empty:
        st.warning("Aucun endpoint trouvé.")
        return

    # Filtres
    status_filter = st.multiselect("Statut", options=endpoints['protection_status'].unique(),
                                   default=endpoints['protection_status'].unique())
    filtered = endpoints[endpoints['protection_status'].isin(status_filter)]
    st.dataframe(filtered, use_container_width=True)

    # Détail d'un endpoint
    st.subheader("🔍 Détail triadique")
    selected_id = st.selectbox("Choisir un endpoint", filtered['id'].tolist(),
                                format_func=lambda x: f"{x} - {filtered[filtered['id']==x]['ip_address'].iloc[0]}")
    metrics = get_triad_metrics(entity_type='endpoint', entity_id=selected_id, hours=48)
    if not metrics.empty:
        fig = px.line(metrics, x='recorded_at', y=['phi_m','phi_c','phi_d'],
                      title=f"Évolution triadique de l'endpoint {selected_id}")
        st.plotly_chart(fig, use_container_width=True)
        last = metrics.iloc[-1]
        st.metric("Φ_M actuel", f"{last['phi_m']:.4f}")
        st.metric("Φ_C actuel", f"{last['phi_c']:.4f}")
        st.metric("Φ_D actuel", f"{last['phi_d']:.4f}")

def threats_page():
    st.title("⚠️ Analyse des menaces")
    org_id = st.session_state.get("org_id")
    logs = get_audit_logs(org_id, limit=5000)

    if logs.empty:
        st.warning("Aucune donnée d'audit.")
        return

    fig = px.scatter(logs, x='timestamp', y='ml_anomaly_score', color='status',
                     title="Scores d'anomalie ML")
    st.plotly_chart(fig, use_container_width=True)

    if 'signature_match' in logs.columns:
        sig_counts = logs['signature_match'].value_counts().reset_index()
        sig_counts.columns = ['signature','count']
        fig = px.bar(sig_counts, x='signature', y='count', title="Correspondance des signatures")
        st.plotly_chart(fig, use_container_width=True)

    # Corrélations triadiques
    if {'phi_m','phi_c','phi_d'}.issubset(logs.columns):
        corr = logs[['phi_m','phi_c','phi_d']].corr()
        fig = px.imshow(corr, text_auto=True, color_continuous_scale='RdBu_r',
                        title="Corrélations entre composantes triadiques")
        st.plotly_chart(fig, use_container_width=True)

def quarantine_page():
    st.title("🔒 Quarantaine")
    org_id = st.session_state.get("org_id")
    qdata = get_quarantine_vault(org_id)

    if qdata.empty:
        st.info("Aucun élément en quarantaine.")
        return

    st.dataframe(qdata[['id','endpoint_ip','payload_hash','reason','quarantined_at','analyzed']],
                 use_container_width=True)

    if st.button("🔬 Analyser les éléments non analysés (simulation)"):
        st.success("Analyse déclenchée !")

def playbooks_page():
    st.title("📜 Playbooks de réponse automatique")
    org_id = st.session_state.get("org_id")
    playbooks = get_playbooks(org_id)

    if playbooks.empty:
        st.info("Aucun playbook configuré.")
    else:
        st.dataframe(playbooks[['name','enabled','created_at']], use_container_width=True)

    st.subheader("➕ Ajouter un playbook (simulation)")
    with st.form("new_playbook"):
        name = st.text_input("Nom")
        trigger = st.text_area("Condition (JSON)", value='{"type":"anomaly","threshold":0.8}')
        actions = st.text_area("Actions (JSON)", value='{"action":"quarantine"}')
        enabled = st.checkbox("Actif", True)
        if st.form_submit_button("Créer"):
            st.success("Playbook créé (simulation)")

def attractor_page():
    st.title("🌀 Analyse des attracteurs TTU")
    org_id = st.session_state.get("org_id")
    endpoints = get_endpoints(org_id)

    if endpoints.empty:
        st.warning("Aucun endpoint.")
        return

    selected = st.selectbox("Choisir un endpoint", endpoints['id'].tolist(),
                            format_func=lambda x: f"{x} - {endpoints[endpoints['id']==x]['ip_address'].iloc[0]}")
    metrics = get_triad_metrics(entity_type='endpoint', entity_id=selected, hours=72)

    if metrics.empty:
        st.info("Pas assez de données.")
        return

    # Projection 3D
    fig = go.Figure(data=[go.Scatter3d(
        x=metrics['phi_m'], y=metrics['phi_c'], z=metrics['phi_d'],
        mode='lines+markers',
        marker=dict(size=2, color=metrics.index, colorscale='Viridis'),
        line=dict(color='darkblue', width=1)
    )])
    fig.update_layout(
        title="Trajectoire dans l'espace (Φ_M, Φ_C, Φ_D)",
        scene=dict(xaxis_title="Φ_M", yaxis_title="Φ_C", zaxis_title="Φ_D")
    )
    st.plotly_chart(fig, use_container_width=True)

    # Fonction de Lyapunov (énergie)
    metrics['V'] = metrics['phi_m']**2 + metrics['phi_c']**2 + metrics['phi_d']**2
    fig2 = px.line(metrics, x='recorded_at', y='V', title="Fonction de Lyapunov (énergie)")
    st.plotly_chart(fig2, use_container_width=True)

def config_page():
    st.title("⚙️ Configuration")
    org_id = st.session_state.get("org_id")

    st.subheader("Utilisateurs techniques")
    users_sec = get_utilisateurs_secure(org_id)
    st.dataframe(users_sec[['pseudo','accreditation_level','registered_at']], use_container_width=True)

    st.subheader("Clients")
    clients = get_users()
    st.dataframe(clients[['email','full_name','company_name','is_active']], use_container_width=True)

    st.subheader("Essais gratuits")
    trials = get_free_trials()
    st.dataframe(trials, use_container_width=True)

# =====================================================
# NAVIGATION
# =====================================================
def main():
    # Sélecteur d'organisation dans la sidebar
    orgs = get_organizations()
    org_dict = {row['name']: row['id'] for _, row in orgs.iterrows()}
    org_names = ["Toutes"] + list(org_dict.keys())
    selected_org_name = st.sidebar.selectbox("Organisation", org_names)
    if selected_org_name != "Toutes":
        st.session_state["org_id"] = org_dict[selected_org_name]
    else:
        st.session_state["org_id"] = None

    sidebar()

    menu = ["Accueil", "Endpoints", "Menaces", "Quarantaine", "Playbooks", "Attracteurs", "Configuration"]
    choice = st.sidebar.radio("Navigation", menu)

    if choice == "Accueil":
        home_page()
    elif choice == "Endpoints":
        endpoints_page()
    elif choice == "Menaces":
        threats_page()
    elif choice == "Quarantaine":
        quarantine_page()
    elif choice == "Playbooks":
        playbooks_page()
    elif choice == "Attracteurs":
        attractor_page()
    elif choice == "Configuration":
        config_page()

if __name__ == "__main__":
    if conn is None:
        st.stop()
    main()