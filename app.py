import streamlit as st
import psycopg2
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv
import os

# =====================================================
# CONFIG
# =====================================================

st.set_page_config(
    page_title="TTU BASTION EDR",
    layout="wide",
    page_icon="🛡️"
)

load_dotenv()

# =====================================================
# CONNEXION DATABASE
# =====================================================

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )


# =====================================================
# CHARGEMENT DONNEES
# =====================================================

def load_registry():

    conn = get_connection()

    query = """
    SELECT
        app_name,
        k_factor,
        adaptive_threshold,
        last_heartbeat,
        is_active
    FROM ttu_core.registry
    """

    df = pd.read_sql(query, conn)
    conn.close()

    return df


def load_vault():

    conn = get_connection()

    query = """
    SELECT
        app_id,
        target_table,
        priority,
        ingested_at,
        processed
    FROM ttu_core.dissipation_vault
    ORDER BY ingested_at DESC
    LIMIT 500
    """

    df = pd.read_sql(query, conn)
    conn.close()

    return df


def load_users():

    conn = get_connection()

    query = """
    SELECT
        email,
        company_name,
        created_at
    FROM public.users
    ORDER BY created_at DESC
    """

    df = pd.read_sql(query, conn)
    conn.close()

    return df


# =====================================================
# UI
# =====================================================

st.title("🛡️ TTU BASTION EDR")
st.subheader("Cyber-Résilience par Membrane Adaptive")

menu = st.sidebar.selectbox(
    "Navigation",
    [
        "Dashboard",
        "Flux Vault",
        "Applications",
        "Utilisateurs",
        "Statistiques"
    ]
)

# =====================================================
# DASHBOARD
# =====================================================

if menu == "Dashboard":

    st.header("📊 État global du système")

    registry = load_registry()

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Applications actives",
        registry.shape[0]
    )

    col2.metric(
        "k moyen",
        round(registry["k_factor"].mean(), 2)
    )

    col3.metric(
        "Seuil adaptatif moyen",
        round(registry["adaptive_threshold"].mean(), 2)
    )

    fig = px.bar(
        registry,
        x="app_name",
        y="k_factor",
        title="Courbure k par application"
    )

    st.plotly_chart(fig, use_container_width=True)


# =====================================================
# VAULT
# =====================================================

elif menu == "Flux Vault":

    st.header("📦 Dissipation Vault")

    vault = load_vault()

    st.dataframe(vault, use_container_width=True)

    fig = px.histogram(
        vault,
        x="priority",
        title="Distribution des priorités"
    )

    st.plotly_chart(fig, use_container_width=True)


# =====================================================
# APPLICATIONS
# =====================================================

elif menu == "Applications":

    st.header("⚙️ Registre des applications")

    registry = load_registry()

    st.dataframe(registry, use_container_width=True)


# =====================================================
# UTILISATEURS
# =====================================================

elif menu == "Utilisateurs":

    st.header("👤 Clients")

    users = load_users()

    st.dataframe(users, use_container_width=True)


# =====================================================
# STATISTIQUES
# =====================================================

elif menu == "Statistiques":

    st.header("📈 Analyse système")

    vault = load_vault()

    fig = px.line(
        vault,
        x="ingested_at",
        title="Flux de dissipation"
    )

    st.plotly_chart(fig, use_container_width=True)
