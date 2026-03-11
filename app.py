import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from supabase import create_client, Client
import streamlit_option_menu as option_menu
import time
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
# CONNEXION À SUPABASE (via secrets)
# =====================================================
@st.cache_resource
def init_connection():
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["key"]
    return create_client(url, key)

supabase = init_connection()

# =====================================================
# FONCTIONS D'ACCÈS AUX DONNÉES (avec cache)
# =====================================================
@st.cache_data(ttl=60)
def get_organizations():
    response = supabase.table("organizations").select("*").execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=30)
def get_endpoints(org_id=None):
    query = supabase.table("endpoints").select("*")
    if org_id:
        query = query.eq("org_id", org_id)
    response = query.execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=30)
def get_audit_logs(org_id=None, limit=1000):
    query = supabase.table("audit_logs_global").select("*").order("timestamp", desc=True).limit(limit)
    if org_id:
        query = query.eq("org_id", org_id)
    response = query.execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=60)
def get_blacklisted_entities(org_id=None):
    query = supabase.table("blacklisted_entities").select("*")
    if org_id:
        query = query.eq("org_id", org_id)
    response = query.execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=60)
def get_quarantine_vault(org_id=None):
    query = supabase.table("quarantine_vault").select("*")
    if org_id:
        query = query.eq("org_id", org_id)
    response = query.execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=120)
def get_triad_metrics(entity_type=None, entity_id=None, hours=24):
    since = datetime.utcnow() - timedelta(hours=hours)
    query = supabase.table("triad_metrics").select("*").gte("recorded_at", since.isoformat())
    if entity_type:
        query = query.eq("entity_type", entity_type)
    if entity_id:
        query = query.eq("entity_id", str(entity_id))
    response = query.order("recorded_at").execute()
    return pd.DataFrame(response.data)

# =====================================================
# SIDEBAR - SÉLECTION DE L'ORGANISATION
# =====================================================
def sidebar():
    with st.sidebar:
        st.image("https://via.placeholder.com/150x50?text=TTU-MC3+Cyber", use_column_width=True)
        st.markdown("## 🛡️ Tableau de bord")
        orgs = get_organizations()
        org_names = ["Toutes"] + orgs["name"].tolist()
        selected_org = st.selectbox("Organisation", org_names)
        org_id = None
        if selected_org != "Toutes":
            org_id = orgs[orgs["name"] == selected_org]["id"].iloc[0]
        st.session_state["org_id"] = org_id
        st.markdown("---")
        st.markdown("### 🧠 État triadique global")
        if org_id:
            org_data = orgs[orgs["id"] == org_id].iloc[0]
            phi_m = org_data.get("phi_m", 0.0)
            phi_c = org_data.get("phi_c", 0.0)
            phi_d = org_data.get("phi_d", 0.0)
        else:
            # moyenne sur toutes les organisations
            phi_m = orgs["phi_m"].mean() if "phi_m" in orgs.columns else 0
            phi_c = orgs["phi_c"].mean() if "phi_c" in orgs.columns else 0
            phi_d = orgs["phi_d"].mean() if "phi_d" in orgs.columns else 0

        col1, col2, col3 = st.columns(3)
        col1.metric("Φ_M (Mémoire)", f"{phi_m:.3f}")
        col2.metric("Φ_C (Cohérence)", f"{phi_c:.3f}")
        col3.metric("Φ_D (Dissipation)", f"{phi_d:.3f}")

        # Jauge de stabilité (Lyapunov simplifié)
        stability = 1.0 - min(1.0, abs(phi_c) / (abs(phi_m)+0.01))
        st.progress(stability, text="Stabilité")
        st.markdown("---")
        st.markdown("© 2026 USTM - TTU-MC³")

# =====================================================
# PAGE D'ACCUEIL / VUE D'ENSEMBLE
# =====================================================
def home_page():
    st.title("🛡️ Tableau de bord cybersécurité TTU‑MC³")
    st.markdown("Surveillance en temps réel des endpoints, menaces et état triadique.")

    org_id = st.session_state.get("org_id")

    # Statistiques globales
    col1, col2, col3, col4 = st.columns(4)
    endpoints = get_endpoints(org_id)
    blacklist = get_blacklisted_entities(org_id)
    quarantine = get_quarantine_vault(org_id)
    logs = get_audit_logs(org_id, limit=100)

    col1.metric("Endpoints actifs", len(endpoints[endpoints["protection_status"]=="Actif"]))
    col2.metric("Entités blacklistées", len(blacklist))
    col3.metric("Éléments en quarantaine", len(quarantine))
    col4.metric("Événements (24h)", len(logs[logs["timestamp"] > (datetime.utcnow()-timedelta(days=1)).isoformat()]))

    # Graphique de l'évolution triadique des dernières 24h
    st.subheader("📈 Évolution triadique (moyenne des endpoints)")
    triad_df = get_triad_metrics(entity_type="endpoint", hours=24)
    if not triad_df.empty:
        # Agrégation horaire
        triad_df["hour"] = pd.to_datetime(triad_df["recorded_at"]).dt.floor("H")
        hourly = triad_df.groupby("hour")[["phi_m", "phi_c", "phi_d"]].mean().reset_index()
        fig = px.line(hourly, x="hour", y=["phi_m", "phi_c", "phi_d"],
                      labels={"value": "Amplitude", "variable": "Composante"},
                      title="Moyenne des états triadiques")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Aucune donnée triadique disponible pour les dernières 24h.")

    # Derniers événements d'audit
    st.subheader("📋 Derniers événements")
    if not logs.empty:
        display_logs = logs[["timestamp", "endpoint_id", "status", "ml_anomaly_score", "reputation_score"]].head(10)
        st.dataframe(display_logs, use_container_width=True)
    else:
        st.info("Aucun événement récent.")

# =====================================================
# PAGE ENDPOINTS
# =====================================================
def endpoints_page():
    st.title("🖥️ Gestion des endpoints")
    org_id = st.session_state.get("org_id")
    endpoints = get_endpoints(org_id)

    if endpoints.empty:
        st.warning("Aucun endpoint trouvé.")
        return

    # Filtres
    col1, col2 = st.columns(2)
    with col1:
        status_filter = st.multiselect("Statut", options=endpoints["protection_status"].unique(),
                                       default=endpoints["protection_status"].unique())
    with col2:
        search = st.text_input("Recherche par IP ou OS")

    filtered = endpoints[endpoints["protection_status"].isin(status_filter)]
    if search:
        filtered = filtered[filtered["ip_address"].astype(str).str.contains(search, na=False) |
                            filtered["os"].str.contains(search, na=False)]

    st.dataframe(filtered, use_container_width=True)

    # Détail d'un endpoint sélectionné
    st.subheader("🔍 Détail triadique d'un endpoint")
    endpoint_ids = filtered["id"].tolist()
    if endpoint_ids:
        selected_id = st.selectbox("Choisir un endpoint", endpoint_ids, format_func=lambda x: f"{x} - {filtered[filtered['id']==x]['ip_address'].iloc[0]}")
        # Récupérer les métriques triadiques pour cet endpoint
        metrics = get_triad_metrics(entity_type="endpoint", entity_id=selected_id, hours=48)
        if not metrics.empty:
            fig = px.line(metrics, x="recorded_at", y=["phi_m", "phi_c", "phi_d"],
                          title=f"Évolution triadique de l'endpoint {selected_id}")
            st.plotly_chart(fig, use_container_width=True)

            # Calcul de la vitesse de convergence (simulé)
            last = metrics.iloc[-1]
            st.metric("Φ_M actuel", f"{last['phi_m']:.4f}")
            st.metric("Φ_C actuel", f"{last['phi_c']:.4f}")
            st.metric("Φ_D actuel", f"{last['phi_d']:.4f}")
        else:
            st.info("Pas de données triadiques pour cet endpoint.")

# =====================================================
# PAGE ANALYSE DES MENACES
# =====================================================
def threats_page():
    st.title("⚠️ Analyse des menaces")
    org_id = st.session_state.get("org_id")
    logs = get_audit_logs(org_id, limit=5000)

    if logs.empty:
        st.warning("Aucune donnée d'audit.")
        return

    # Scores d'anomalie et de réputation
    fig = px.scatter(logs, x="timestamp", y="ml_anomaly_score", color="status",
                     title="Scores d'anomalie ML au fil du temps",
                     labels={"ml_anomaly_score": "Anomalie"})
    st.plotly_chart(fig, use_container_width=True)

    # Distribution des signatures
    st.subheader("📊 Correspondance des signatures")
    if "signature_match" in logs.columns:
        sig_counts = logs["signature_match"].value_counts().reset_index()
        sig_counts.columns = ["signature", "count"]
        fig = px.bar(sig_counts, x="signature", y="count", title="Occurrences des signatures")
        st.plotly_chart(fig, use_container_width=True)

    # Carte de chaleur des corrélations (si assez de données)
    st.subheader("🔥 Carte de corrélation triadique")
    if "phi_m" in logs.columns and "phi_c" in logs.columns and "phi_d" in logs.columns:
        corr = logs[["phi_m", "phi_c", "phi_d"]].corr()
        fig = px.imshow(corr, text_auto=True, color_continuous_scale="RdBu_r", title="Corrélations entre composantes")
        st.plotly_chart(fig, use_container_width=True)

# =====================================================
# PAGE QUARANTAINE
# =====================================================
def quarantine_page():
    st.title("🔒 Quarantaine")
    org_id = st.session_state.get("org_id")
    qdata = get_quarantine_vault(org_id)

    if qdata.empty:
        st.info("Aucun élément en quarantaine.")
        return

    st.dataframe(qdata[["id", "payload_hash", "reason", "quarantined_at", "analyzed", "phi_m", "phi_c", "phi_d"]], use_container_width=True)

    # Bouton pour analyser (simulation)
    if st.button("🔬 Analyser les éléments non analysés"):
        # Ici on appellerait une fonction d'analyse (ex: via un worker)
        st.success("Analyse déclenchée ! (simulation)")

# =====================================================
# PAGE PLAYBOOKS
# =====================================================
def playbooks_page():
    st.title("📜 Playbooks de réponse automatique")
    org_id = st.session_state.get("org_id")
    response = supabase.table("playbooks").select("*").eq("org_id", org_id).execute()
    playbooks = pd.DataFrame(response.data)

    if playbooks.empty:
        st.info("Aucun playbook configuré.")
    else:
        st.dataframe(playbooks[["name", "enabled", "created_at"]], use_container_width=True)

    st.subheader("➕ Ajouter un playbook")
    with st.form("new_playbook"):
        name = st.text_input("Nom")
        trigger = st.text_area("Condition (JSON)", value='{"type":"anomaly","threshold":0.8}')
        actions = st.text_area("Actions (JSON)", value='{"action":"quarantine"}')
        enabled = st.checkbox("Actif", True)
        submitted = st.form_submit_button("Créer")
        if submitted:
            data = {
                "org_id": org_id,
                "name": name,
                "trigger_condition": json.loads(trigger),
                "actions": json.loads(actions),
                "enabled": enabled
            }
            supabase.table("playbooks").insert(data).execute()
            st.success("Playbook créé !")
            st.cache_data.clear()
            st.rerun()

# =====================================================
# PAGE ANALYSE TRIADIQUE AVANCÉE (ATTRACTEURS)
# =====================================================
def attractor_page():
    st.title("🌀 Analyse des attracteurs TTU")
    st.markdown("Visualisation de l'espace des phases et convergence vers les attracteurs.")

    org_id = st.session_state.get("org_id")
    endpoints = get_endpoints(org_id)

    if endpoints.empty:
        st.warning("Aucun endpoint.")
        return

    # Sélection d'un endpoint
    selected_endpoint = st.selectbox("Choisir un endpoint", endpoints["id"].tolist(),
                                      format_func=lambda x: f"{x} - {endpoints[endpoints['id']==x]['ip_address'].iloc[0]}")
    metrics = get_triad_metrics(entity_type="endpoint", entity_id=selected_endpoint, hours=72)

    if metrics.empty:
        st.info("Pas assez de données pour cet endpoint.")
        return

    # Projection 3D de l'espace des phases
    fig = go.Figure(data=[go.Scatter3d(
        x=metrics["phi_m"],
        y=metrics["phi_c"],
        z=metrics["phi_d"],
        mode='lines+markers',
        marker=dict(size=2, color=metrics.index, colorscale='Viridis'),
        line=dict(color='darkblue', width=1)
    )])
    fig.update_layout(
        title="Trajectoire dans l'espace (Φ_M, Φ_C, Φ_D)",
        scene=dict(
            xaxis_title="Φ_M (Mémoire)",
            yaxis_title="Φ_C (Cohérence)",
            zaxis_title="Φ_D (Dissipation)"
        ),
        width=800,
        height=600
    )
    st.plotly_chart(fig, use_container_width=True)

    # Calcul des exposants de Lyapunov (simplifié)
    st.subheader("📉 Stabilité et attracteur")
    # Simuler une décroissance exponentielle
    if len(metrics) > 10:
        last_values = metrics[["phi_m", "phi_c", "phi_d"]].values[-10:]
        diffs = np.diff(last_values, axis=0)
        norm_diff = np.linalg.norm(diffs, axis=1)
        if np.any(norm_diff > 0):
            lyap = np.mean(np.log(norm_diff[1:] / (norm_diff[:-1]+1e-10)))
            st.metric("Exposant de Lyapunov maximal estimé", f"{lyap:.4f}", delta="négatif = stable" if lyap<0 else "positif = instable")
        else:
            st.info("Pas assez de variation pour estimer Lyapunov.")

    # Fonction de Lyapunov V = (Φ_M²+Φ_C²+Φ_D²)
    metrics["V"] = metrics["phi_m"]**2 + metrics["phi_c"]**2 + metrics["phi_d"]**2
    fig2 = px.line(metrics, x="recorded_at", y="V", title="Fonction de Lyapunov (énergie)")
    st.plotly_chart(fig2, use_container_width=True)

# =====================================================
# PAGE CONFIGURATION (utilisateurs, etc.)
# =====================================================
def config_page():
    st.title("⚙️ Configuration")
    st.markdown("Gestion des utilisateurs et paramètres (simplifié).")

    org_id = st.session_state.get("org_id")
    # Utilisateurs sécurisés
    resp = supabase.table("utilisateurs_secure").select("*").eq("org_id", org_id).execute()
    users = pd.DataFrame(resp.data)
    st.subheader("Utilisateurs techniques")
    st.dataframe(users[["id", "pseudo", "accreditation_level", "registered_at"]], use_container_width=True)

    # Utilisateurs clients
    resp2 = supabase.table("users").select("*").execute()
    clients = pd.DataFrame(resp2.data)
    st.subheader("Clients")
    st.dataframe(clients[["id", "email", "full_name", "company_name", "is_active"]], use_container_width=True)

# =====================================================
# NAVIGATION PRINCIPALE
# =====================================================
def main():
    sidebar()
    with st.sidebar:
        st.markdown("---")
        selected = option_menu.option_menu(
            menu_title=None,
            options=["Accueil", "Endpoints", "Menaces", "Quarantaine", "Playbooks", "Attracteurs", "Configuration"],
            icons=["house", "pc-display", "exclamation-triangle", "shield-lock", "journal-code", "graph-up", "gear"],
            menu_icon="cast",
            default_index=0
        )

    if selected == "Accueil":
        home_page()
    elif selected == "Endpoints":
        endpoints_page()
    elif selected == "Menaces":
        threats_page()
    elif selected == "Quarantaine":
        quarantine_page()
    elif selected == "Playbooks":
        playbooks_page()
    elif selected == "Attracteurs":
        attractor_page()
    elif selected == "Configuration":
        config_page()

if __name__ == "__main__":
    main()
