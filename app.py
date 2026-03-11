import streamlit as st
import pandas as pd
import plotly.express as px
from supabase import create_client, Client
import os

# Configuration de la page
st.set_page_config(
    page_title="TTU BASTION EDR - Cockpit de Dissipation",
    page_icon="🛡️",
    layout="wide"
)

# 1. Connexion Supabase (Utilise les Secrets de Streamlit)
@st.cache_resource
def init_connection():
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

try:
    supabase: Client = init_connection()
except Exception as e:
    st.error("Erreur de connexion à Supabase. Vérifiez vos Secrets Streamlit.")
    st.stop()

# 2. Interface de Monitoring
st.title("🛡️ TTU BASTION EDR – Console de Résilience")
st.markdown("---")

# Sidebar - État du Noyau
st.sidebar.header("Statut du Noyau TTU-MC³")
if st.sidebar.button("Forcer le Battement de Cœur (Heartbeat)"):
    try:
        supabase.rpc('heartbeat_modulation').execute()
        st.sidebar.success("Modulation effectuée")
    except Exception as e:
        st.sidebar.error(f"Erreur RPC : {e}")

# 3. Récupération des données du Registre (k-factor)
def get_registry_data():
    res = supabase.table("registry").schema("ttu_core").select("*").execute()
    return pd.DataFrame(res.data)

df_reg = get_registry_data()

if not df_reg.empty:
    # Métriques Clés
    col1, col2, col3 = st.columns(3)
    avg_k = df_reg['k_factor'].mean()
    total_apps = len(df_reg)
    
    col1.metric("Nombre d'Applications", total_apps)
    col2.metric("Facteur de Courbure Moyen (k)", f"{avg_k:.4f}")
    col3.metric("État Global", "STABLE" if avg_k < 2.0 else "CONTRACTION")

    # Graphique de la Courbure k par Application
    st.subheader("Analyse de la Membrane Adaptive (Courbure k)")
    fig = px.bar(df_reg, x='app_name', y='k_factor', 
                 color='k_factor', title="Pression thermodynamique par terminal",
                 color_continuous_scale='Viridis')
    st.plotly_chart(fig, use_container_width=True)

    # Tableau du Registre
    st.subheader("Détails du Registre de Cohérence")
    st.dataframe(df_reg[['app_name', 'app_id', 'k_factor', 'adaptive_threshold', 'last_heartbeat']], 
                 use_container_width=True)

# 4. Simulation d'envoi de Log (Test de liaison)
st.markdown("---")
st.subheader("🚀 Test d'Injection dans le Vault")
with st.expander("Envoyer un événement de sécurité manuel"):
    with st.form("manual_injection"):
        selected_app = st.selectbox("Application", df_reg['app_name'].tolist())
        target_app_id = df_reg[df_reg['app_name'] == selected_app]['app_id'].values[0]
        event_msg = st.text_input("Message d'alerte", "Suspicious process detected")
        priority = st.slider("Priorité", 1, 5, 2)
        submit = st.form_submit_button("Dissiper vers le Vault")

        if submit:
            payload = {
                "app_id": target_app_id,
                "target_table": "audit_logs_global",
                "payload": {"event": event_msg, "source": "Cockpit_Manual"},
                "priority": priority
            }
            res_insert = supabase.table("dissipation_vault").schema("ttu_core").insert(payload).execute()
            if res_insert.data:
                st.success(f"Événement injecté. Le facteur k de {selected_app} va s'ajuster au prochain battement.")

# Pied de page
st.markdown("---")
st.caption("TTU BASTION EDR v2.0 - Souveraineté Numérique - Développeur : GEB")
