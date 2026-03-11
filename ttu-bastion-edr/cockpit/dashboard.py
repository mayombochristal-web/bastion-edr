import streamlit as st
import psycopg2
import pandas as pd
import plotly.express as px

DATABASE_URL = st.secrets["db_url"]  # ou variable d'environnement

st.set_page_config(page_title="TTU BASTION Cockpit", layout="wide")
st.title("🛡️ TTU BASTION EDR – Monitoring de la Courbure k")

conn = psycopg2.connect(DATABASE_URL)

# Chargement des applications
df_apps = pd.read_sql("""
    SELECT app_name, k_factor, adaptive_threshold, last_heartbeat,
           (SELECT email FROM public.users WHERE id = user_id) as user_email
    FROM ttu_core.registry
    ORDER BY app_name
""", conn)

st.subheader("Applications enregistrées")
st.dataframe(df_apps, use_container_width=True)

# Graphique de courbure
fig = px.line(df_apps, x="app_name", y=["k_factor", "adaptive_threshold"],
              title="Courbure et seuil adaptatif par application")
st.plotly_chart(fig, use_container_width=True)

# Dernières entrées dans les logs d'audit
df_logs = pd.read_sql("""
    SELECT id, payload, sync_k, created_at
    FROM public.audit_logs_global
    ORDER BY created_at DESC
    LIMIT 10
""", conn)

st.subheader("Derniers logs d'audit (avec sync_k)")
st.dataframe(df_logs, use_container_width=True)

# Dernières entrées en quarantaine
df_quar = pd.read_sql("""
    SELECT id, payload, sync_k, created_at
    FROM public.quarantine_vault
    ORDER BY created_at DESC
    LIMIT 10
""", conn)

st.subheader("Derniers éléments en quarantaine")
st.dataframe(df_quar, use_container_width=True)

# Métriques globales
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Applications actives", len(df_apps))
with col2:
    avg_k = df_apps["k_factor"].mean()
    st.metric("Courbure moyenne", f"{avg_k:.2f}")
with col3:
    # Total des scans gratuits restants
    df_trials = pd.read_sql("SELECT SUM(scans_total - scans_used) as remaining FROM public.free_trials WHERE status='active'", conn)
    remaining = df_trials.iloc[0]['remaining'] or 0
    st.metric("Analyses gratuites restantes", int(remaining))

conn.close()