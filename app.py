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

    db_user = st.secrets["DB_USER"]
    db_password = st.secrets["DB_PASSWORD"]
    db_host = st.secrets["DB_HOST"]
    db_port = st.secrets["DB_PORT"]
    db_name = st.secrets["DB_NAME"]

    db_url = f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    engine = create_engine(
        db_url,
        connect_args={"sslmode": "require"},
        pool_pre_ping=True
    )

    return engine


# Création de l'engine (IMPORTANT)
engine = get_engine()

# =====================================================
# TEST CONNEXION
# =====================================================

try:
    test = pd.read_sql("SELECT NOW()", engine)
    st.success("Connexion Supabase OK")
except Exception as e:
    st.error("Erreur connexion base")
    st.write(e)
    st.stop()

# =====================================================
# LOAD DATA
# =====================================================

@st.cache_data(ttl=60)
def load_endpoints():

    query = """
    SELECT id, ip_address, os, protection_status, last_sync
    FROM public.endpoints
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_users():

    query = """
    SELECT email, company_name, created_at
    FROM public.users
    ORDER BY created_at DESC
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_logs():

    query = """
    SELECT timestamp, ip, kmass_score, ml_anomaly_score
    FROM public.audit_logs_global
    ORDER BY timestamp DESC
    LIMIT 500
    """

    return pd.read_sql(query, engine)


# =====================================================
# MENU
# =====================================================

menu = st.sidebar.selectbox(
    "Navigation",
    [
        "SOC Dashboard",
        "Threat Timeline",
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
    logs = load_logs()

    col1, col2 = st.columns(2)

    col1.metric("Endpoints actifs", len(endpoints))
    col2.metric("Logs analysés", len(logs))

    if not logs.empty:

        fig = px.scatter(
            logs,
            x="kmass_score",
            y="ml_anomaly_score",
            title="Analyse anomalies"
        )

        st.plotly_chart(fig, use_container_width=True)


# =====================================================
# TIMELINE
# =====================================================

elif menu == "Threat Timeline":

    st.header("📈 Timeline des menaces")

    logs = load_logs()

    if not logs.empty:

        fig = px.line(
            logs,
            x="timestamp",
            y="ml_anomaly_score"
        )

        st.plotly_chart(fig, use_container_width=True)

    st.dataframe(logs, use_container_width=True)


# =====================================================
# ENDPOINTS
# =====================================================

elif menu == "Endpoints":

    st.header("💻 Terminaux surveillés")

    endpoints = load_endpoints()

    st.dataframe(endpoints, use_container_width=True)


# =====================================================
# USERS
# =====================================================

elif menu == "Utilisateurs":

    st.header("👤 Clients")

    users = load_users()

    st.dataframe(users, use_container_width=True)
