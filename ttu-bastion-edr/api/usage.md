# Intégration d’une application cliente à TTU BASTION EDR

## 1. Enregistrement de l’application

Obtenez un `app_id` en vous inscrivant via la page [https://votre-domaine.com/signup](https://votre-domaine.com/signup) ou en appelant directement l’Edge Function `signup`.

## 2. Structure attendue des tables de destination

Vos tables métier (par exemple `audit_logs_global`, `quarantine_vault`) **doivent** comporter les colonnes suivantes pour que le transfert automatique fonctionne :

- `payload` (JSONB) : contient les données à analyser.
- `sync_k` (FLOAT) : reçoit la valeur de la courbure \(k\) au moment du transfert.
- `created_at` (TIMESTAMPTZ) : horodatage de l’insertion (optionnel mais recommandé).

Si vos colonnes ont des noms différents, vous devez adapter la fonction `ttu_core.dispatch_processing()` dans le schéma.

## 3. Envoi des données vers le Vault

Au lieu d’écrire directement dans votre table, insérez les données dans le vault de dissipation :

```sql
INSERT INTO ttu_core.dissipation_vault (app_id, target_table, payload, priority)
VALUES (
    'votre-app-id',
    'nom_de_la_table_finale',   -- ex: 'audit_logs_global'
    '{"cle": "valeur"}'::jsonb,
    1  -- priorité (plus élevé = plus urgent)
);