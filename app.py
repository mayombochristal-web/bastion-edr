import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import create_engine

# =====================================================
# CONFIG
# =====================================================

st.set_page_config(
    page_title="TTU BASTION EDR",
    layout="wide",
    page_icon="🛡️"
)

st.title("🛡️ TTU BASTION EDR")
st.subheader("Cyber-Résilience par Membrane Adaptive")

# =====================================================
# DATABASE ENGINE
# =====================================================

@st.cache_resource
def get_engine():

    db_url = f"""
    postgresql+psycopg2://{st.secrets["DB_USER"]}:{st.secrets["DB_PASSWORD"]}
    @{st.secrets["DB_HOST"]}:{st.secrets["DB_PORT"]}/{st.secrets["DB_NAME"]}
    """

    engine = create_engine(db_url, connect_args={"sslmode": "require"})

    return engine


engine = get_engine()

# =====================================================
# LOAD DATA
# =====================================================

@st.cache_data(ttl=60)
def load_users():

    query = """
    SELECT email, company_name, created_at
    FROM public.users
    ORDER BY created_at DESC
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_endpoints():

    query = """
    SELECT id, ip_address, os, protection_status, last_sync
    FROM public.endpoints
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_audit_logs():

    query = """
    SELECT timestamp, ip, kmass_score, ml_anomaly_score, reputation_score
    FROM public.audit_logs_global
    ORDER BY timestamp DESC
    LIMIT 500
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_quarantine():

    query = """
    SELECT payload_hash, reason, quarantined_at
    FROM public.quarantine_vault
    ORDER BY quarantined_at DESC
    LIMIT 500
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_blacklist():

    query = """
    SELECT ip_address, ban_depth, reason, expires_at
    FROM public.blacklisted_entities
    """

    return pd.read_sql(query, engine)


# =====================================================
# SIDEBAR
# =====================================================

menu = st.sidebar.selectbox(
    "Navigation",
    [
        "SOC Dashboard",
        "Threat Timeline",
        "Quarantine Vault",
        "Blacklisted Entities",
        "Endpoints",
        "Utilisateurs"
    ]
)

# =====================================================
# SOC DASHBOARD
# =====================================================

if menu == "SOC Dashboard":

    st.header("📊 Security Operations Center")

    endpoints = load_endpoints()
    logs = load_audit_logs()
    quarantine = load_quarantine()

    col1, col2, col3 = st.columns(3)

    col1.metric("Endpoints actifs", len(endpoints))
    col2.metric("Logs analysés", len(logs))
    col3.metric("Objets en quarantaine", len(quarantine))

    if not logs.empty:

        fig = px.scatter(
            logs,
            x="kmass_score",
            y="ml_anomaly_score",
            color="reputation_score",
            title="Carte de menace IA"
        )

        st.plotly_chart(fig, use_container_width=True)


# =====================================================
# THREAT TIMELINE
# =====================================================

elif menu == "Threat Timeline":

    st.header("📈 Timeline des menaces")

    logs = load_audit_logs()

    if not logs.empty:

        fig = px.line(
            logs,
            x="timestamp",
            y="ml_anomaly_score",
            title="Anomalies détectées"
        )

        st.plotly_chart(fig, use_container_width=True)

    st.dataframe(logs, use_container_width=True)


# =====================================================
# QUARANTINE
# =====================================================

elif menu == "Quarantine Vault":

    st.header("🧪 Vault de quarantaine")

    quarantine = load_quarantine()

    st.dataframe(quarantine, use_container_width=True)


# =====================================================
# BLACKLIST
# =====================================================

elif menu == "Blacklisted Entities":

    st.header("🚫 Entités bannies")

    blacklist = load_blacklist()

    st.dataframe(blacklist, use_container_width=True)


# =====================================================
# ENDPOINTS
# =====================================================

elif menu == "Endpoints":

    st.header("💻 Terminaux surveillés")

    endpoints = load_endpoints()

    st.dataframe(endpoints, use_container_width=True)

    if not endpoints.empty:

        fig = px.histogram(
            endpoints,
            x="protection_status",
            title="Statut de protection"
        )

        st.plotly_chart(fig, use_container_width=True)


# =====================================================
# USERS
# =====================================================

elif menu == "Utilisateurs":

    st.header("👤 Clients")

    users = load_users()

    st.dataframe(users, use_container_width=True)
