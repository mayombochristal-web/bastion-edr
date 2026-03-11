import requests
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

class TTUBilling:
    def __init__(self, db_url):
        self.conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
        self.flutterwave_api_key = os.getenv("FLW_SECRET_KEY")
        self.flutterwave_base = "https://api.flutterwave.com/v3"

    def create_subscription(self, user_id, plan):
        """Crée un abonnement et génère un lien de paiement Flutterwave"""
        plans = {
            'bastion': {'price': 500, 'name': 'Pack Bastion'},
            'souverain': {'price': 2500, 'name': 'Pack Souverain'}
        }
        if plan not in plans:
            raise ValueError("Plan invalide")

        # Créer une entrée subscription en attente
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO public.subscriptions (user_id, plan_name, price_per_month, status)
            VALUES (%s, %s, %s, 'pending')
            RETURNING id
        """, (user_id, plan, plans[plan]['price']))
        sub_id = cur.fetchone()['id']
        self.conn.commit()

        # Générer un lien de paiement Flutterwave
        payload = {
            "tx_ref": f"sub-{sub_id}-{int(datetime.now().timestamp())}",
            "amount": str(plans[plan]['price']),
            "currency": "EUR",
            "redirect_url": "https://votre-domaine.com/payment-success",
            "payment_options": "card, mobilemoney",
            "customer": {
                "email": self.get_user_email(user_id),
                "name": self.get_user_name(user_id)
            },
            "customizations": {
                "title": f"TTU BASTION - {plans[plan]['name']}",
                "description": "Abonnement mensuel"
            }
        }
        headers = {"Authorization": f"Bearer {self.flutterwave_api_key}"}
        resp = requests.post(f"{self.flutterwave_base}/payments", json=payload, headers=headers)
        data = resp.json()
        if data['status'] == 'success':
            return data['data']['link']
        else:
            # Annuler la subscription en base
            cur.execute("UPDATE public.subscriptions SET status = 'failed' WHERE id = %s", (sub_id,))
            self.conn.commit()
            raise Exception("Erreur paiement: " + data['message'])

    def handle_webhook(self, payload):
        """Vérifie et active l'abonnement après paiement"""
        # Vérifier la signature (à implémenter selon la doc Flutterwave)
        tx_ref = payload['txRef']
        if tx_ref.startswith('sub-'):
            sub_id = tx_ref.split('-')[1]
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE public.subscriptions
                SET status = 'active', start_date = NOW(), end_date = NOW() + INTERVAL '1 month'
                WHERE id = %s
            """, (sub_id,))
            self.conn.commit()
            self.send_confirmation_email(sub_id)

    def get_user_email(self, user_id):
        cur = self.conn.cursor()
        cur.execute("SELECT email FROM public.users WHERE id = %s", (user_id,))
        return cur.fetchone()['email']

    def get_user_name(self, user_id):
        cur = self.conn.cursor()
        cur.execute("SELECT full_name FROM public.users WHERE id = %s", (user_id,))
        return cur.fetchone()['full_name']

    def send_confirmation_email(self, sub_id):
        # À implémenter avec Resend ou autre service
        pass