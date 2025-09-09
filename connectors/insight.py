import os
import base64
import logging
import arrow
import json
import urllib3
from lib.connector import AssetsConnector
from utils.helper_utils import response_to_object
from typing import Dict, List, Any

# Temporarily disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("connectors/insight")


class Connector(AssetsConnector):
    """
    Insight connector
    """
    MappingName = 'insight'
    Settings = {
        'client_id': {'order': 1, 'example': '', 'default': ""},
        'client_key': {'order': 2, 'example': '', 'default': ""},
        'client_secret': {'order': 3, 'example': '******', 'default': ""},
        'order_creation_date_from': {'order': 4, 'example': 'YYYY-MM-DD', 'default': ""},
        'order_creation_date_to': {'order': 5, 'example': 'YYYY-MM-DD', 'default': arrow.now().format('YYYY-MM-DD')},
        'tracking_data': {'order': 6, 'example': 'X', 'default': ""},
        'insight_url': {'order': 7, 'example': 'https://example.com/GetStatus', 'default': ""}
    }

    def __init__(self, section, settings):
        super(Connector, self).__init__(section, settings)
        
        # Load configuration with environment variable priority (as per PRD requirements)
        # Priority order: Environment Variables > config.ini > defaults
        
        # Insight API URL
        self.get_sales_order_status_api = os.environ.get('INSIGHT_URL') or self.settings.get('insight_url', '')
        if not self.get_sales_order_status_api:
            logger.error("Insight API URL is not set! Please set INSIGHT_URL environment variable or insight_url in config.ini")
            raise ValueError("Insight API URL is not configured!")

        self.access_token = ""
        self.insight_expires_in = 0
        
        # Authentication credentials - prioritize environment variables
        self.client_key = os.environ.get('INSIGHT_CLIENT_KEY') or self.settings.get('client_key', '')
        self.client_secret = os.environ.get('INSIGHT_CLIENT_SECRET') or self.settings.get('client_secret', '')
        self.client_id = os.environ.get('INSIGHT_CLIENT_ID') or self.settings.get('client_id', '')
        self.tracking_data = os.environ.get('INSIGHT_TRACKING_DATA') or self.settings.get('tracking_data', '')

        # Date logic with environment variable priority
        # Priority: Environment Variables > config.ini > yesterday (default)
        order_date_from = os.environ.get('INSIGHT_ORDER_CREATION_DATE_FROM') or self.settings.get('order_creation_date_from', '')
        order_date_to = os.environ.get('INSIGHT_ORDER_CREATION_DATE_TO') or self.settings.get('order_creation_date_to', '')
        
        # If still blank, use yesterday as default
        if not order_date_from:
            order_date_from = arrow.utcnow().shift(days=-1).format('YYYY-MM-DD')
        if not order_date_to:
            order_date_to = arrow.utcnow().shift(days=-1).format('YYYY-MM-DD')
            
        self.order_date_from = order_date_from
        self.order_date_to = order_date_to
        
        logger.info(f"Insight connector initialized with date range: {self.order_date_from} to {self.order_date_to}")

    def get_verification(self):
        """Control SSL verification: env INSIGHT_VERIFY_SSL or VERIFY_SSL overrides; fallback to base setting."""
        env_val = os.getenv('INSIGHT_VERIFY_SSL') or os.getenv('VERIFY_SSL')
        if env_val is not None:
            return str(env_val).lower() in ('1', 'true', 'yes', 'y')
        return super().get_verification()

    def get_headers(self):
        if round(arrow.utcnow().float_timestamp) > self.insight_expires_in:
            self.get_access_token(self.client_key, self.client_secret)
        return {'Accept': 'application/json',
                'Authorization': f'Bearer {self.access_token}'}

    def get_access_token(self, client_key, client_secret):
        # Create the base64 client_id and client_secret token and grab an Access Token
        token = f"{client_key}:{client_secret}"
        base64_token = base64.b64encode(token.encode()).decode()
        token_url = 'https://insight-prod.apigee.net/oauth/client_credential/accesstoken?grant_type=client_credentials'
        basic_auth_headers = {
            'Authorization': f'Basic {base64_token}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        # Use base connector's verification behavior
        json_response = self.post(token_url, data={}, headers=basic_auth_headers, post_as_json=False)
        dict_response = response_to_object(json_response.text)

        self.access_token = dict_response.get('access_token', '')
        # expires in 1hr according to docs
        self.insight_expires_in = round(arrow.utcnow().float_timestamp) + int(dict_response.get('expires_in', 3599))

    @staticmethod
    def generate_dates_range(start: str, end: str, interval: int):
        start = arrow.get(start)
        end = arrow.get(end)

        dates_range = []
        date_from = start
        while date_from <= end:
            date_to = date_from.shift(days=interval)
            if date_to > end:
                date_to = end
            dates_range.append((date_from.format("YYYY-MM-DD"), date_to.format("YYYY-MM-DD")))
            if date_to == end:
                break
            date_from = date_to

        return dates_range

    def get_orders(self):
        # The Insight API allows a maximum range of 180 days, so we need to paginate on the main date range.
        # The Insight API is also very slow, so we chose an interval of 60 days therefore we're sure to get a response.
        dates_range = self.generate_dates_range(self.order_date_from, self.order_date_to, 60)

        for date_from, date_to in dates_range:
            # The call must have a body to return a 200 response
            body_data = {"MT_Status2Request": {
                "StatusRequest": [
                    {
                        "ClientID": self.client_id,
                        "TrackingData": self.tracking_data,
                        "OrderCreationDateFrom": date_from,
                        "OrderCreationDateTo": date_to
                    }
                ]
            }}

            # POST is required (GET with body unsupported)
            response = self.post(self.get_sales_order_status_api, data=body_data)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Request Payload: %s", json.dumps(body_data))
                logger.debug("Response Status Code: %s", response.status_code)
                logger.debug("Response Text: %s", response.text)
            yield response_to_object(response.text)

    @staticmethod
    def attach_order_headers(order_header: List[Dict[str, Any]], final_dict: Dict[str, Any]):
        if order_header:
            final_dict.update({key: value for (key, value) in order_header[0].items()})

    @staticmethod
    def attach_order_tracking(order_tracking_info: List[Dict[str, Any]],
                              serial_number: str,
                              final_dict: Dict[str, Any]):
        for tracking in order_tracking_info:
            if 'SerialNumber' in tracking and str(tracking['SerialNumber']).strip() == serial_number:
                final_dict.update({key: tracking[key] for key in tracking.keys()})

    def attach_order_line_items_and_tracking(self, order_line_items: Dict[str, Any],
                                             order_tracking_info: List[Dict[str, Any]],
                                             base_dict: Dict[str, Any],
                                             ignore_keys: List[str]):

        for order_item in order_line_items.get('OrderLineItems', []):
            item_base = {**base_dict, **{key: value for (key, value) in order_item.items() if key not in ignore_keys}}
            if "Delivery" in order_item:
                for delivery in order_item['Delivery']:
                    delivery_base = {**item_base, **{key: delivery[key] for key in delivery.keys() if key not in ignore_keys}}

                    if "SerialNumbers" in delivery:
                        for serial_number_dict in delivery['SerialNumbers']:
                            raw_sn = serial_number_dict.get('SerialNumber')
                            if raw_sn is None:
                                continue
                            serial_number = str(raw_sn).strip()
                            rec = {**delivery_base, 'SerialNumber': serial_number}

                            self.attach_order_tracking(order_tracking_info, serial_number, rec)
                            if 'BillingInformation' in delivery:
                                if len(delivery['BillingInformation']) == 1:
                                    rec = {**rec, **{key: value for (key, value) in delivery['BillingInformation'][0].items()}}
                                    yield rec
                                else:
                                    logger.warning(
                                        "Billing Information not added to dict as only one is expected per item in Order line item.")

    def create_insight_response_dict(self, response):
        for orders in response.get("StatusOrderResponse", []):
            for order in orders.get('Order', []):
                order_header = order.get('OrderHeader', [])
                order_tracking_info = order.get('Tracking', [])
                ignore_keys = ["Delivery", "SerialNumbers", "BillingInformation"]
                output_dict = {}

                self.attach_order_headers(order_header, output_dict)
                items = self.attach_order_line_items_and_tracking(order, order_tracking_info, output_dict, ignore_keys)
                for result in items:
                    yield result

    def _load_records(self, *a, **kw):
        if not self.client_key or not self.client_secret:
            self.logger.warning("Missing Client Key or Client Secret. Can not run. Exiting.")
            return

        for payload in self.get_orders():
            for ready_order_info in self.create_insight_response_dict(payload):
                yield ready_order_info
