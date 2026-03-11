import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import create_engine, text

# =====================================================
# CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="TTU BASTION EDR - Cockpit Admin",
    layout="wide",
    page_icon="🛡️"
)

# Style visuel
st.markdown("""
<style>
.main {
    background-color:#0e1117;
}

.stMetric {
    background-color:#161b22;
    border-radius:10px;
    padding:15px;
    border:1px solid #30363d;
}
</style>
""", unsafe_allow_html=True)

# =====================================================
# CONNEXION BASE DE DONNÉES
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
        pool_pre_ping=True,
        pool_recycle=3600
    )

    return engine


engine = get_engine()

# =====================================================
# TEST CONNEXION
# =====================================================

try:
    test = pd.read_sql("SELECT NOW()", engine)
except Exception as e:
    st.error("🚨 Impossible de se connecter à la base")
    st.write(e)
    st.stop()

# =====================================================
# CHARGEMENT DONNÉES
# =====================================================

@st.cache_data(ttl=30)
def load_ttu_status():

    query = """
    SELECT app_name, k_factor, adaptive_threshold, is_active
    FROM ttu_core.registry
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=30)
def load_security_data():

    query = """
    SELECT timestamp,
           kmass_score,
           ml_anomaly_score,
           reputation_score,
           status
    FROM public.audit_logs_global
    ORDER BY timestamp DESC
    LIMIT 1000
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_endpoints():

    query = """
    SELECT id,
           os,
           protection_status,
           last_sync
    FROM public.endpoints
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_quarantine():

    query = """
    SELECT payload_hash,
           reason,
           quarantined_at,
           k_factor_sync
    FROM public.quarantine_vault
    ORDER BY quarantined_at DESC
    """

    return pd.read_sql(query, engine)


@st.cache_data(ttl=60)
def load_users():

    query = """
    SELECT email,
           company_name,
           created_at
    FROM public.users
    ORDER BY created_at DESC
    """

    return pd.read_sql(query, engine)


# =====================================================
# UI PRINCIPALE
# =====================================================

st.title("🛡️ TTU BASTION EDR")
st.caption("Cyber-Résilience par Membrane Adaptive")

menu = st.sidebar.selectbox(
    "Navigation",
    [
        "SOC Dashboard",
        "Registre de Courbure",
        "Vault & Quarantaine",
        "Gestion Clients"
    ]
)

# =====================================================
# SOC DASHBOARD
# =====================================================

if menu == "SOC Dashboard":

    st.header("📊 Security Operations Center")

    reg = load_ttu_status()
    logs = load_security_data()
    endpoints = load_endpoints()

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Endpoints", len(endpoints))

    if not reg.empty:
        c2.metric("k Moyen", f"{reg['k_factor'].mean():.4f}")
    else:
        c2.metric("k Moyen", "0")

    if not logs.empty:
        alerts = len(logs[logs["ml_anomaly_score"] > 0.7])
        c3.metric("Alertes IA", alerts)
    else:
        c3.metric("Alertes IA", "0")

    if not reg.empty:
        stability = "SOUVERAINE" if reg["k_factor"].mean() < 1.5 else "CRITIQUE"
        c4.metric("Stabilité", stability)

    st.subheader("🎯 Carte des menaces")

    if not logs.empty:

        fig = px.scatter(
            logs,
            x="kmass_score",
            y="ml_anomaly_score",
            color="reputation_score",
            size="ml_anomaly_score",
            hover_data=["status"],
            template="plotly_dark",
            color_continuous_scale="Viridis"
        )

        st.plotly_chart(fig, use_container_width=True)

# =====================================================
# REGISTRE
# =====================================================

elif menu == "Registre de Courbure":

    st.header("⚙️ Membrane Thermodynamique")

    reg = load_ttu_status()

    col1, col2 = st.columns([1, 2])

    with col1:
        st.dataframe(reg)

    with col2:

        if not reg.empty:

            fig = px.bar(
                reg,
                x="app_name",
                y="k_factor",
                color="k_factor",
                template="plotly_dark",
                title="Pression thermodynamique"
            )

            st.plotly_chart(fig, use_container_width=True)

# =====================================================
# QUARANTAINE
# =====================================================

elif menu == "Vault & Quarantaine":

    st.header("🧪 Objets Dissipés")

    quarantine = load_quarantine()

    st.dataframe(quarantine, use_container_width=True)

# =====================================================
# CLIENTS
# =====================================================

elif menu == "Gestion Clients":

    st.header("👤 Utilisateurs")

    users = load_users()

    st.dataframe(users, use_container_width=True)

# =====================================================
# ACTION ADMIN
# =====================================================

st.sidebar.markdown("---")

if st.sidebar.button("Forcer Synchronisation K"):

    try:

        with engine.connect() as con:

            con.execute(text("SELECT ttu_core.heartbeat_modulation();"))

        st.sidebar.success("Signal envoyé au noyau TTU")

    except Exception as e:

        st.sidebar.error("Erreur synchronisation")
        st.sidebar.write(e)
