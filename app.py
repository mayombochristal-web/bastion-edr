#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TTU BASTION EDR - Cockpit de surveillance (Membrane Adaptive)
Conforme au document TTU BASTION EDR – Cyber‑Résilience par Membrane Adaptive
Utilise une connexion directe PostgreSQL (via psycopg2) aux tables du schéma ttu_core.
"""

import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time

# =====================================================
# CONFIGURATION DE LA PAGE
# =====================================================
st.set_page_config(
    page_title="TTU BASTION EDR - Cockpit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================
# CONNEXION À LA BASE DE DONNÉES (via secrets.toml)
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
# FONCTIONS D'ACCÈS AUX DONNÉES (avec cache temporel)
# =====================================================
@st.cache_data(ttl=10)  # rafraîchissement rapide pour suivre la courbure
def get_registry():
    """Récupère toutes les applications enregistrées dans ttu_core.registry."""
    if conn is None:
        return pd.DataFrame()
    query = """
        SELECT app_id, app_name, k_factor, base_threshold, adaptive_threshold,
               free_scans_remaining, is_active, last_heartbeat
        FROM ttu_core.registry
        ORDER BY app_name;
    """
    df = pd.read_sql(query, conn)
    return df

@st.cache_data(ttl=10)
def get_vault_summary():
    """Récupère un résumé de la file d'attente (dissipation_vault)."""
    if conn is None:
        return pd.DataFrame()
    query = """
        SELECT app_id,
               COUNT(*) FILTER (WHERE processed = FALSE) as pending,
               COUNT(*) FILTER (WHERE processed = TRUE) as processed,
               COUNT(*) as total
        FROM ttu_core.dissipation_vault
        GROUP BY app_id;
    """
    df = pd.read_sql(query, conn)
    return df

@st.cache_data(ttl=30)
def get_pending_vault(limit=100):
    """Récupère les éléments en attente dans le vault."""
    if conn is None:
        return pd.DataFrame()
    query = f"""
        SELECT v.id, r.app_name, v.target_table, v.payload, v.priority,
               v.ingested_at
        FROM ttu_core.dissipation_vault v
        JOIN ttu_core.registry r ON v.app_id = r.app_id
        WHERE v.processed = FALSE
        ORDER BY v.priority DESC, v.ingested_at ASC
        LIMIT {limit};
    """
    df = pd.read_sql(query, conn)
    return df

@st.cache_data(ttl=60)
def get_global_stress():
    """Calcule le stress global (somme des k_factors) pour l'affichage."""
    if conn is None:
        return 0.0
    query = "SELECT COALESCE(SUM(k_factor), 1.0) as stress FROM ttu_core.registry WHERE is_active = TRUE;"
    df = pd.read_sql(query, conn)
    return df.iloc[0]['stress']

# =====================================================
# SIDEBAR - INFORMATIONS GLOBALES
# =====================================================
def sidebar():
    with st.sidebar:
        st.image("https://via.placeholder.com/200x80?text=TTU+BASTION+EDR", use_column_width=True)
        st.markdown("## 🧠 Membrane Adaptive")
        
        # Stress global
        stress = get_global_stress()
        st.metric("Stress global (Σk)", f"{stress:.2f}")
        
        # Facteur de contraction (issu de heartbeat_modulation)
        # On le calcule approximativement : contraction = 1/(1+stress/20)
        contraction = 1.0 / (1.0 + stress / 20.0)
        st.metric("Facteur de contraction", f"{contraction:.3f}")
        
        # Horodatage du dernier battement de cœur
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT MAX(last_heartbeat) FROM ttu_core.registry;")
            last_hb = cur.fetchone()['max']
            cur.close()
            if last_hb:
                st.caption(f"Dernier heartbeat : {last_hb}")
        
        st.markdown("---")
        st.markdown("### 🔄 Actions rapides")
        if st.button("🔄 Rafraîchir toutes les données"):
            st.cache_data.clear()
            st.rerun()
        
        st.markdown("---")
        st.markdown("**TTU BASTION EDR**  \nCyber‑résilience par membrane adaptive  \n© 2026 Mayombo Idiedie Christ Aldo")

# =====================================================
# PAGE PRINCIPALE : TABLEAU DE BORD
# =====================================================
def main_page():
    st.title("🛡️ TTU BASTION EDR - Cockpit de surveillance")
    st.markdown("Visualisation en temps réel de la **courbure k** et de l'état des applications protégées.")
    
    if conn is None:
        st.stop()
    
    registry = get_registry()
    vault_summary = get_vault_summary()
    
    # ========== INDICATEURS CLÉS ==========
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Applications actives", len(registry[registry['is_active']==True]))
    with col2:
        total_pending = vault_summary['pending'].sum() if not vault_summary.empty else 0
        st.metric("Éléments en attente", int(total_pending))
    with col3:
        total_processed = vault_summary['processed'].sum() if not vault_summary.empty else 0
        st.metric("Traités (dernière heure)", int(total_processed))
    with col4:
        avg_k = registry['k_factor'].mean() if not registry.empty else 0
        st.metric("Courbure moyenne", f"{avg_k:.2f}")
    
    # ========== TABLEAU DES APPLICATIONS ==========
    st.subheader("📋 Applications enregistrées")
    if registry.empty:
        st.warning("Aucune application enregistrée dans ttu_core.registry.")
    else:
        # Fusion avec le résumé du vault
        display_df = registry.copy()
        if not vault_summary.empty:
            display_df = display_df.merge(vault_summary, on='app_id', how='left')
            display_df['pending'] = display_df['pending'].fillna(0).astype(int)
            display_df['processed'] = display_df['processed'].fillna(0).astype(int)
        else:
            display_df['pending'] = 0
            display_df['processed'] = 0
        
        # Mise en forme conditionnelle pour free_scans_remaining
        def color_free_scans(val):
            if val <= 0:
                return 'color: red; font-weight: bold'
            elif val <= 1:
                return 'color: orange'
            else:
                return 'color: green'
        
        styled = display_df.style.applymap(color_free_scans, subset=['free_scans_remaining'])
        st.dataframe(
            styled.format({
                'k_factor': '{:.3f}',
                'adaptive_threshold': '{:.2f}',
                'last_heartbeat': lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if pd.notnull(x) else ''
            }),
            use_container_width=True
        )
    
    # ========== GRAPHIQUE DE LA COURBURE ET SEUIL ==========
    st.subheader("📈 Courbure k et seuil adaptatif par application")
    if not registry.empty:
        fig = px.bar(
            registry,
            x='app_name',
            y=['k_factor', 'adaptive_threshold'],
            barmode='group',
            title="Comparaison de la courbure et du seuil",
            labels={'value': 'Valeur', 'app_name': 'Application', 'variable': 'Mesure'}
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Aucune donnée à afficher.")
    
    # ========== VAULT : ÉLÉMENTS EN ATTENTE ==========
    st.subheader("⏳ File d'attente universelle (dissipation_vault) - Éléments en attente")
    pending = get_pending_vault()
    if pending.empty:
        st.success("Aucun élément en attente.")
    else:
        st.dataframe(pending, use_container_width=True)
    
    # ========== ANALYSE SIMPLE DES SCANS GRATUITS ==========
    st.subheader("🆓 Scans gratuits restants")
    if not registry.empty:
        low_scans = registry[registry['free_scans_remaining'] <= 1]
        if not low_scans.empty:
            st.warning(f"⚠️ {len(low_scans)} application(s) n'ont plus ou presque plus de scans gratuits.")
            for _, row in low_scans.iterrows():
                st.write(f"- **{row['app_name']}** : {row['free_scans_remaining']} scan(s) restant")
        else:
            st.info("Toutes les applications disposent d'au moins 2 scans gratuits.")
    
    # ========== PIED DE PAGE ==========
    st.markdown("---")
    st.caption("Mise à jour automatique toutes les 10 secondes (mécanisme de cache). Les données sont actualisées à chaque interaction.")

# =====================================================
# PAGE DE DOCUMENTATION / INTÉGRATION
# =====================================================
def docs_page():
    st.title("📘 Documentation d'intégration")
    st.markdown("""
    ### Intégrer une nouvelle application
    
    1. **Enregistrer l'application** dans la table `ttu_core.registry` :
    ```sql
    INSERT INTO ttu_core.registry (app_name) VALUES ('ma_super_app') RETURNING app_id;
    ```
    
    2. **Créer la fonction de traitement** spécifique à l'application (exemple pour `ma_super_app`) :
    ```sql
    CREATE OR REPLACE FUNCTION process_app_ma_super_app()
    RETURNS void LANGUAGE plpgsql AS $$
    BEGIN
        WITH moved AS (
            DELETE FROM ttu_core.dissipation_vault
            WHERE app_id = (SELECT app_id FROM ttu_core.registry WHERE app_name = 'ma_super_app')
              AND target_table = 'ma_table_finale'
              AND processed = FALSE
            RETURNING payload
        )
        INSERT INTO ma_table_finale (data, sync_k)
        SELECT payload, (SELECT k_factor FROM ttu_core.registry WHERE app_name = 'ma_super_app')
        FROM moved;
    END;
    $$;
    ```
    
    3. **Insérer des données** dans le vault au lieu d'écrire directement dans la table cible :
    ```sql
    INSERT INTO ttu_core.dissipation_vault (app_id, target_table, payload)
    VALUES ('votre-app-id', 'ma_table_finale', '{"data": "valeur"}'::jsonb);
    ```
    
    4. **Surveiller** la courbure et les seuils depuis ce cockpit.
    
    ### Gestion des scans gratuits
    - Chaque application commence avec 3 scans gratuits.
    - Le compteur est décrémenté à chaque mise en quarantaine.
    - Pour souscrire un abonnement, contactez l'administrateur ou utilisez le module de facturation Flutterwave.
    
    ### Worker de traitement
    Le worker (`engine/worker.py`) doit être exécuté en arrière-plan pour traiter les files d'attente toutes les minutes.
    """)
    st.code("""
    # Lancer le worker
    export SUPABASE_DB_URL="postgresql://..."
    python engine/worker.py
    """, language="bash")
    
    st.markdown("---")
    st.markdown("**Contact** : mayombochristal@gmail.com | WhatsApp +241 77 76 54 96")

# =====================================================
# MENU DE NAVIGATION
# =====================================================
def main():
    sidebar()
    
    menu = ["Tableau de bord", "Documentation"]
    choice = st.sidebar.radio("Navigation", menu)
    
    if choice == "Tableau de bord":
        main_page()
    elif choice == "Documentation":
        docs_page()

if __name__ == "__main__":
    main()