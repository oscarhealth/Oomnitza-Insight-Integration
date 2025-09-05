import os
import sys
import logging
import requests
import datetime
import base64

# --- 1. Configure Logging ---
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s - %(levelname)s - %(message)s',
   stream=sys.stdout,
)

# --- 2. Load and Validate Credentials from Environment Variables ---
logging.info("Loading credentials from environment variables.")

try:
    from dotenv import load_dotenv
    load_dotenv()
    logging.info("Loaded environment variables from .env file.")
except ImportError:
    logging.info("python-dotenv not installed; skipping .env loading.")

def get_env_str(var_name):
    value = os.environ.get(var_name)
    if isinstance(value, bytes):
        value = value.decode()
    elif value is not None and not isinstance(value, str):
        value = str(value)
    return value

OOMNITZA_URL = get_env_str("OOMNITZA_URL")
OOMNITZA_API_TOKEN = get_env_str("OOMNITZA_API_TOKEN")
INSIGHT_CLIENT_ID = get_env_str("INSIGHT_CLIENT_ID")
INSIGHT_CLIENT_KEY = get_env_str("INSIGHT_CLIENT_KEY")
INSIGHT_CLIENT_SECRET = get_env_str("INSIGHT_CLIENT_SECRET")
INSIGHT_URL = get_env_str("INSIGHT_URL")

REQUIRED_VARS = {
   "OOMNITZA_URL": OOMNITZA_URL,
   "OOMNITZA_API_TOKEN": OOMNITZA_API_TOKEN,
   "INSIGHT_CLIENT_ID": INSIGHT_CLIENT_ID,
   "INSIGHT_CLIENT_KEY": INSIGHT_CLIENT_KEY,
   "INSIGHT_CLIENT_SECRET": INSIGHT_CLIENT_SECRET,
   "INSIGHT_URL": INSIGHT_URL,
}

missing_vars = [k for k, v in REQUIRED_VARS.items() if not v]
if missing_vars:
   logging.error(f"Missing required environment variables: {', '.join(missing_vars)}. Exiting.")
   sys.exit(1)

logging.info("All required credentials loaded successfully.")

# --- Set Insight order creation dates to yesterday (only if not already set) ---
date_from_env = os.environ.get('INSIGHT_ORDER_CREATION_DATE_FROM')
date_to_env = os.environ.get('INSIGHT_ORDER_CREATION_DATE_TO')

if not date_from_env or not date_to_env:
    yesterday = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')
    if not date_from_env:
        os.environ['INSIGHT_ORDER_CREATION_DATE_FROM'] = yesterday
    if not date_to_env:
        os.environ['INSIGHT_ORDER_CREATION_DATE_TO'] = yesterday
    logging.info(f"Set default INSIGHT_ORDER_CREATION_DATE_FROM and TO to {yesterday}")
else:
    logging.info(f"Using existing environment variables: FROM={date_from_env}, TO={date_to_env}")

def get_insight_access_token(client_key, client_secret):
    """
    Fetch OAuth access token from Insight API using client_key and client_secret.
    """
    token = f"{client_key}:{client_secret}"
    base64_token = base64.b64encode(token.encode()).decode()
    token_url = 'https://insight-prod.apigee.net/oauth/client_credential/accesstoken?grant_type=client_credentials'
    basic_auth_headers = {
        'Authorization': f'Basic {base64_token}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        # Disable SSL verification for testing
        resp = requests.post(token_url, headers=basic_auth_headers, data={}, verify=False)
        resp.raise_for_status()
        data = resp.json()
        return data.get('access_token', None)
    except Exception as e:
        logging.error(f"Failed to get Insight access token: {e}")
        return None

def get_insight_assets():
    """
    Fetch asset procurement data from the Insight API using Bearer token auth and paginated date ranges.
    """
    logging.info("Starting fetch from Insight API.")
    access_token = get_insight_access_token(INSIGHT_CLIENT_KEY, INSIGHT_CLIENT_SECRET)
    if not access_token:
        logging.error("Could not obtain Insight access token. Exiting.")
        return []
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
    }
    # Date range logic (60-day intervals)
    from datetime import datetime, timedelta
    import json
    date_from = os.environ.get('INSIGHT_ORDER_CREATION_DATE_FROM', '')
    date_to = os.environ.get('INSIGHT_ORDER_CREATION_DATE_TO', '')
    if not date_from or not date_to:
        today = datetime.utcnow().date()
        date_from = (today - timedelta(days=1)).strftime('%Y-%m-%d')
        date_to = date_from
    start = datetime.strptime(date_from, '%Y-%m-%d')
    end = datetime.strptime(date_to, '%Y-%m-%d')
    interval = timedelta(days=60)
    assets = []
    current = start
    while current <= end:
        interval_end = min(current + interval, end)
        payload = {
            "MT_Status2Request": {
                "StatusRequest": [
                    {
                        "ClientID": INSIGHT_CLIENT_ID,
                        "TrackingData": os.environ.get('INSIGHT_TRACKING_DATA', ''),
                        "OrderCreationDateFrom": current.strftime('%Y-%m-%d'),
                        "OrderCreationDateTo": interval_end.strftime('%Y-%m-%d')
                    }
                ]
            }
        }
        print(f"DEBUG: Request Method = POST")
        print(f"DEBUG: Request URL = {INSIGHT_URL}")
        print(f"DEBUG: Request Headers = {json.dumps(headers, indent=2)}")
        print(f"DEBUG: Request Body (Payload) = {json.dumps(payload, indent=2)}")
        try:
            response = requests.post(
                url=INSIGHT_URL,
                json=payload,
                headers=headers,
                timeout=30,
                verify=False  # Disable SSL verification for testing
            )
            print(f"DEBUG: Response Status Code = {response.status_code}")
            print(f"DEBUG: Response Headers = {dict(response.headers)}")
            print(f"DEBUG: Response Text = {response.text}")
            
            if response.status_code != 200:
                logging.error(f"Insight API returned {response.status_code}: {response.text}")
                break
            data = response.json()
            print(f"DEBUG: Parsed JSON Response = {json.dumps(data, indent=2)}")
            
            # Extract assets from the actual Insight API response structure
            page_assets = []
            status_response = data.get('StatusOrderResponse', [])
            
            for status in status_response:
                orders = status.get('Order', [])
                for order in orders:
                    order_header = order.get('OrderHeader', [{}])[0]  # Get first header
                    line_items = order.get('OrderLineItems', [])
                    
                    for item in line_items:
                        # Extract serial number from delivery information if available
                        serial_number = None
                        deliveries = item.get('Delivery', [])
                        for delivery in deliveries:
                            serial_numbers = delivery.get('SerialNumbers', [])
                            if serial_numbers:
                                serial_number = serial_numbers[0].get('SerialNumber', '').strip()
                                break
                        
                        # Only include items that have serial numbers (actual assets)
                        if serial_number:
                            asset_record = {
                                'order': {
                                    'purchaseOrderNumber': order_header.get('CustomerOrderNumber'),
                                    'purchaseDate': order_header.get('OrderCreationDate'),
                                    'insightOrderNumber': order_header.get('InsightOrderNumber'),
                                    'orderStatus': order_header.get('OrderStatus')
                                },
                                'lineItem': {
                                    'serialNumber': serial_number,
                                    'unitPrice': None,  # Price info not readily available in this structure
                                    'quantity': item.get('Quantity'),
                                    'itemStatus': item.get('ItemStatus')
                                },
                                'product': {
                                    'sku': item.get('ManufacturerSKU'),
                                    'description': item.get('MaterialDescription'),
                                    'manufacturer': item.get('Manufacturer'),
                                    'materialNumber': item.get('MaterialNumber')
                                },
                                'trackingInfo': {
                                    'carrier': None,  # Not available in current response
                                    'trackingNumber': None  # Not available in current response
                                }
                            }
                            page_assets.append(asset_record)
            
            assets.extend(page_assets)
            logging.info(f"Fetched {len(page_assets)} assets from {current.strftime('%Y-%m-%d')} to {interval_end.strftime('%Y-%m-%d')}.")
        except Exception as e:
            logging.error(f"Request to Insight API failed: {e}")
            break
        current = interval_end + timedelta(days=1)
    logging.info(f"Total assets fetched from Insight: {len(assets)}.")
    return assets

def transform_insight_to_oomnitza(insight_record):
    """
    Transform a single Insight asset record to the Oomnitza API schema.
    Applies field mapping and data cleansing as per PRD.
    Returns a dict ready for Oomnitza ingestion.
    """
    try:
        order = insight_record.get('order', {})
        line_item = insight_record.get('lineItem', {})
        product = line_item.get('product', {})
        tracking = order.get('trackingInfo', {})
        # Field mapping and transformation
        model = product.get('description', '')
        if model:
            model = model.strip()[:255]
        purchase_date = order.get('purchaseDate')
        if purchase_date:
            # Convert ISO 8601 to YYYY-MM-DD
            purchase_date = purchase_date[:10]
        unit_price = line_item.get('unitPrice')
        if unit_price:
            try:
                unit_price = float(str(unit_price).replace('$', '').replace(',', '').strip())
            except Exception:
                unit_price = None
        return {
            'PO_NUMBER': order.get('purchaseOrderNumber'),
            'SERIAL_NUMBER': line_item.get('serialNumber'),
            'SKU': product.get('sku'),
            'MODEL': model,
            'PURCHASE_DATE': purchase_date,
            'PURCHASE_PRICE': unit_price,
            'SHIPPING_CARRIER': tracking.get('carrier'),
            'TRACKING_NUMBER': tracking.get('trackingNumber'),
        }
    except Exception as e:
        logging.error(f"Error transforming record: {e}")
        return None

def push_to_oomnitza(asset):
    """
    Push a single asset to Oomnitza using SERIAL_NUMBER as the primary key.
    If the asset exists, update it; otherwise, create it.
    Returns True if successful, False otherwise.
    """
    # Try different authentication methods
    headers_bearer = {
        'Authorization': f'Bearer {OOMNITZA_API_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    
    headers_apikey = {
        'Authorization': f'Token {OOMNITZA_API_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    
    headers_basic = {
        'Authorization': f'Basic {OOMNITZA_API_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    
    serial = asset.get('SERIAL_NUMBER')
    if not serial:
        logging.warning("Asset missing SERIAL_NUMBER, skipping.")
        return False
    
    # Try different authentication methods
    auth_methods = [
        ("Bearer", headers_bearer),
        ("Token", headers_apikey), 
        ("Basic", headers_basic)
    ]
    
    for auth_name, headers in auth_methods:
        logging.info(f"Trying {auth_name} authentication for {serial}")
        # 1. Check if asset exists
        search_url = f"{OOMNITZA_URL}/api/assets?serial_number={serial}"
        try:
            resp = requests.get(search_url, headers=headers, timeout=30, verify=False)
            if resp.status_code == 200:
                logging.info(f"{auth_name} authentication successful!")
                results = resp.json().get('assets', [])
                if results:
                    # Update existing asset
                    asset_id = results[0].get('id')
                    if not asset_id:
                        logging.error(f"Oomnitza asset found but missing ID for serial {serial}.")
                        return False
                    update_url = f"{OOMNITZA_URL}/api/assets/{asset_id}"
                    r = requests.patch(update_url, headers=headers, json=asset, timeout=30, verify=False)
                    if r.status_code in (200, 204):
                        logging.info(f"Updated asset {serial} in Oomnitza.")
                        return True
                    else:
                        logging.error(f"Failed to update asset {serial}: {r.status_code} {r.text}")
                        return False
                else:
                    # Create new asset
                    create_url = f"{OOMNITZA_URL}/api/assets"
                    r = requests.post(create_url, headers=headers, json=asset, timeout=30, verify=False)
                    if r.status_code in (200, 201):
                        logging.info(f"Created asset {serial} in Oomnitza.")
                        return True
                    else:
                        logging.error(f"Failed to create asset {serial}: {r.status_code} {r.text}")
                        return False
            elif resp.status_code == 401:
                logging.warning(f"{auth_name} authentication failed: {resp.status_code} {resp.text}")
                continue  # Try next auth method
            else:
                logging.error(f"Oomnitza search failed for {serial} with {auth_name}: {resp.status_code} {resp.text}")
                return False
        except requests.RequestException as e:
            logging.error(f"Oomnitza API error for {serial} with {auth_name}: {e}")
            continue  # Try next auth method
    
    logging.error(f"All authentication methods failed for {serial}")
    return False

def test_env_var_types():
    print("TEST: INSIGHT_CLIENT_KEY type:", type(INSIGHT_CLIENT_KEY), "value:", INSIGHT_CLIENT_KEY)
    print("TEST: INSIGHT_CLIENT_SECRET type:", type(INSIGHT_CLIENT_SECRET), "value:", INSIGHT_CLIENT_SECRET)

if __name__ == "__main__":
    """
    This script is deprecated. Please use the official Oomnitza connector runner:

        python connector.py upload insight

    and configure your Insight integration in connectors/insight.py.

    All custom logic has been removed. See README.md for setup instructions.
    """
    logging.info("Starting Insight to Oomnitza data sync.")
    test_env_var_types()
    raw_assets = get_insight_assets()
    transformed_assets = []
    for record in raw_assets:
        asset = transform_insight_to_oomnitza(record)
        if asset and asset.get('SERIAL_NUMBER'):
            transformed_assets.append(asset)
        else:
            logging.warning("Skipping asset due to transformation error or missing SERIAL_NUMBER.")
    logging.info(f"Pushing {len(transformed_assets)} assets to Oomnitza.")
    success_count = 0
    for asset in transformed_assets:
        if push_to_oomnitza(asset):
            success_count += 1
    logging.info(f"Successfully created/updated {success_count} assets in Oomnitza.")
    if success_count < len(transformed_assets):
        logging.warning(f"Failed to process {len(transformed_assets) - success_count} assets. See error logs for details.")
    logging.info("Data sync finished.")
