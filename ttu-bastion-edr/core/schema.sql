
---

## 2. Noyau PostgreSQL – `core/schema.sql`

```sql
-- =============================================================================
-- SCHÉMA COMPLET TTU BASTION EDR (version 2.0 – avec quotas et abonnements)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE SCHEMA IF NOT EXISTS ttu_core;

-- -----------------------------------------------------------------------------
-- 1. TABLES DE GESTION CLIENTS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    company_name TEXT,
    phone TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS public.free_trials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    scans_used INTEGER DEFAULT 0,
    scans_total INTEGER DEFAULT 3,
    trial_start TIMESTAMPTZ DEFAULT NOW(),
    trial_end TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days'),
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'expired', 'converted'))
);

CREATE TABLE IF NOT EXISTS public.subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    plan_name TEXT NOT NULL,
    price_per_month NUMERIC NOT NULL,
    start_date TIMESTAMPTZ DEFAULT NOW(),
    end_date TIMESTAMPTZ,
    auto_renew BOOLEAN DEFAULT TRUE,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'canceled', 'expired')),
    flutterwave_subscription_id TEXT
);

-- -----------------------------------------------------------------------------
-- 2. REGISTRE DE COHÉRENCE (Φ_C) – étendu avec liens clients
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ttu_core.registry (
    app_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name TEXT UNIQUE NOT NULL,
    k_factor FLOAT DEFAULT 1.0,
    base_threshold FLOAT DEFAULT 5.0,
    adaptive_threshold FLOAT DEFAULT 5.0,
    free_scans_remaining INTEGER DEFAULT 3,          -- obsolète, remplacé par free_trials
    is_active BOOLEAN DEFAULT TRUE,
    last_heartbeat TIMESTAMPTZ DEFAULT NOW(),
    user_id UUID REFERENCES public.users(id),
    subscription_id UUID REFERENCES public.subscriptions(id)
);

-- -----------------------------------------------------------------------------
-- 3. VAULT DE DISSIPATION (Φ_D)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ttu_core.dissipation_vault (
    id BIGSERIAL PRIMARY KEY,
    app_id UUID REFERENCES ttu_core.registry(app_id) ON DELETE CASCADE,
    target_table TEXT NOT NULL,
    payload JSONB NOT NULL,
    priority INTEGER DEFAULT 1,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    k_at_ingestion FLOAT
);

CREATE INDEX IF NOT EXISTS idx_ttu_dissipation_active 
    ON ttu_core.dissipation_vault (app_id, processed) 
    WHERE processed = FALSE;

CREATE INDEX IF NOT EXISTS idx_vault_target_processing
    ON ttu_core.dissipation_vault (target_table, processed)
    WHERE processed = FALSE;

-- -----------------------------------------------------------------------------
-- 4. FONCTION DE MISE À JOUR INSTANTANÉE DE k (TRIGGER)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ttu_core.trigger_k_dynamics()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_queue_size BIGINT;
    v_new_k FLOAT;
BEGIN
    SELECT COUNT(*) INTO v_queue_size
    FROM ttu_core.dissipation_vault
    WHERE app_id = NEW.app_id AND processed = FALSE;

    v_new_k := 1.0 + ( (v_queue_size::FLOAT / 100.0) ^ 2 );

    UPDATE ttu_core.registry 
    SET k_factor = v_new_k,
        last_heartbeat = NOW()
    WHERE app_id = NEW.app_id;

    NEW.k_at_ingestion := v_new_k;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_k_flow ON ttu_core.dissipation_vault;
CREATE TRIGGER trg_k_flow
    BEFORE INSERT ON ttu_core.dissipation_vault
    FOR EACH ROW
    EXECUTE FUNCTION ttu_core.trigger_k_dynamics();

-- -----------------------------------------------------------------------------
-- 5. FONCTIONS DE QUOTA ET TRIGGER DE BLOCAGE
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.check_scan_quota(p_app_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
    v_scans_used INTEGER;
    v_scans_total INTEGER;
    v_subscription_active BOOLEAN;
BEGIN
    SELECT user_id INTO v_user_id FROM ttu_core.registry WHERE app_id = p_app_id;

    SELECT EXISTS (
        SELECT 1 FROM public.subscriptions
        WHERE user_id = v_user_id AND status = 'active'
          AND (end_date IS NULL OR end_date > NOW())
    ) INTO v_subscription_active;

    IF v_subscription_active THEN
        RETURN TRUE;
    END IF;

    SELECT scans_used, scans_total INTO v_scans_used, v_scans_total
    FROM public.free_trials
    WHERE user_id = v_user_id AND status = 'active';

    RETURN COALESCE(v_scans_used < v_scans_total, FALSE);
END;
$$;

CREATE OR REPLACE FUNCTION ttu_core.enforce_quota()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT public.check_scan_quota(NEW.app_id) THEN
        RAISE EXCEPTION 'Quota de scans gratuit épuisé. Veuillez souscrire un abonnement.'
            USING HINT = 'Contactez mayombochristal@gmail.com';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforce_quota ON ttu_core.dissipation_vault;
CREATE TRIGGER trg_enforce_quota
    BEFORE INSERT ON ttu_core.dissipation_vault
    FOR EACH ROW
    EXECUTE FUNCTION ttu_core.enforce_quota();

-- -----------------------------------------------------------------------------
-- 6. FONCTION DE DISPATCH DYNAMIQUE (avec mise à jour du compteur de scans)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ttu_core.dispatch_processing()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    r_app RECORD;
    v_target TEXT;
    v_k_current FLOAT;
    v_sql TEXT;
    v_moved_count INT;
    v_user_id UUID;
BEGIN
    FOR r_app IN SELECT app_id, app_name, k_factor, user_id FROM ttu_core.registry WHERE is_active = TRUE
    LOOP
        v_k_current := r_app.k_factor;
        v_user_id := r_app.user_id;

        FOR v_target IN 
            SELECT DISTINCT target_table 
            FROM ttu_core.dissipation_vault 
            WHERE app_id = r_app.app_id AND processed = FALSE
        LOOP
            v_sql := format('
                WITH moved AS (
                    DELETE FROM ttu_core.dissipation_vault
                    WHERE id IN (
                        SELECT id FROM ttu_core.dissipation_vault
                        WHERE app_id = %L
                          AND target_table = %L
                          AND processed = FALSE
                        ORDER BY priority DESC, ingested_at ASC
                        LIMIT 1000
                    )
                    RETURNING payload
                )
                INSERT INTO %I (payload, sync_k, created_at)
                SELECT payload, %L, NOW() FROM moved;
            ', r_app.app_id, v_target, v_target, v_k_current);

            BEGIN
                EXECUTE v_sql;
                GET DIAGNOSTICS v_moved_count = ROW_COUNT;

                -- Mise à jour du compteur de scans utilisés (uniquement pour les essais)
                IF v_user_id IS NOT NULL AND v_moved_count > 0 THEN
                    UPDATE public.free_trials
                    SET scans_used = scans_used + v_moved_count
                    WHERE user_id = v_user_id AND status = 'active';
                END IF;

                RAISE NOTICE 'App % – Table % : % lignes transférées', r_app.app_name, v_target, v_moved_count;
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'Erreur pour app % table % : %', r_app.app_name, v_target, SQLERRM;
            END;
        END LOOP;
    END LOOP;
END;
$$;

-- -----------------------------------------------------------------------------
-- 7. FONCTION DE BATTEMENT DE CŒUR
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ttu_core.heartbeat_modulation()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_global_stress FLOAT;
    v_contraction_factor FLOAT;
BEGIN
    SELECT COALESCE(SUM(k_factor), 1.0) INTO v_global_stress
    FROM ttu_core.registry WHERE is_active = TRUE;

    v_contraction_factor := 1.0 / (1.0 + (v_global_stress / 20.0));

    UPDATE ttu_core.registry
    SET adaptive_threshold = GREATEST(1.5, base_threshold * v_contraction_factor),
        last_heartbeat = NOW();
END;
$$;

-- -----------------------------------------------------------------------------
-- 8. FONCTION DE PURGE
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ttu_core.purge_processed_flux(p_interval INTERVAL DEFAULT '1 hour')
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM ttu_core.dissipation_vault 
    WHERE processed = TRUE AND processed_at < (NOW() - p_interval);
END;
$$;

-- -----------------------------------------------------------------------------
-- 9. PLANIFICATION DES JOBS (si pg_cron activé)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule('ttu-heartbeat');
        PERFORM cron.unschedule('ttu-processing');
        PERFORM cron.unschedule('ttu-purge');

        PERFORM cron.schedule('ttu-heartbeat', '* * * * *', 'SELECT ttu_core.heartbeat_modulation();');
        PERFORM cron.schedule('ttu-processing', '* * * * *', 'SELECT ttu_core.dispatch_processing();');
        PERFORM cron.schedule('ttu-purge', '0 * * * *', 'SELECT ttu_core.purge_processed_flux(''1 hour'');');
    END IF;
END $$;