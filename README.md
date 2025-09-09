# Oomnitza-Insight Integration

A serverless data connector that automatically syncs asset procurement data from Insight to Oomnitza using GitHub Actions. This integration eliminates manual data entry, reduces errors, and ensures your asset management system stays up-to-date with procurement information.

## Features

- 🚀 **Automated Daily Sync**: Runs automatically every day at 5:00 AM UTC
- 🔄 **Manual Sync**: Trigger on-demand syncs through GitHub Actions UI
- 🔒 **Secure Credential Management**: Uses GitHub Encrypted Secrets
- ☁️ **Serverless Architecture**: No infrastructure to maintain
- 📊 **Smart Data Processing**: Handles pagination and rate limiting
- 🔍 **Comprehensive Logging**: Detailed logs for monitoring and troubleshooting
- ♻️ **Idempotent Operations**: Safe to run multiple times without duplicating data

## Quick Start

### Prerequisites

- GitHub repository with Actions enabled
- Oomnitza instance with API access
- Insight API credentials
- Python 3.11+ (for local development)

### Setup Instructions

#### 1. Fork or Clone This Repository

```bash
# Replace with your repository URL
git clone https://github.com/your-org/your-repo.git
cd your-repo
```

#### 2. Configure GitHub Secrets

Navigate to your repository's **Settings** > **Secrets and variables** > **Actions** and add the following secrets:

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `OOMNITZA_URL` | Your Oomnitza instance URL | `https://yourcompany.oomnitza.com` |
| `OOMNITZA_API_TOKEN` | Oomnitza API token | `<oomnitza_api_token>` |
| `INSIGHT_URL` | Insight API endpoint | `https://insight-prod.apigee.net/GetStatus` |
| `INSIGHT_CLIENT_ID` | Your Insight client ID | `<insight_client_id>` |
| `INSIGHT_CLIENT_KEY` | Insight API key | `<insight_client_key>` |
| `INSIGHT_CLIENT_SECRET` | Insight API secret | `<insight_client_secret>` |

Optional secrets for custom date ranges:
- `INSIGHT_ORDER_CREATION_DATE_FROM` - Start date (YYYY-MM-DD format)
- `INSIGHT_ORDER_CREATION_DATE_TO` - End date (YYYY-MM-DD format)

> Important: Never commit secrets to the repository. Use GitHub Actions secrets only.

#### 3. Enable GitHub Actions

The workflow is already configured in `.github/workflows/oomnitza-sync.yml` and will:
- Run daily at 5:00 AM UTC
- Allow manual triggers from the Actions tab
- Automatically set date ranges to sync yesterday's data

#### 4. Manual Sync

To trigger a manual sync:
1. Go to the **Actions** tab in your repository
2. Click on "Oomnitza-Insight Data Sync" workflow
3. Click "Run workflow" button
4. Select the branch and click "Run workflow"

## Local Development

### Setting Up Your Environment

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` with your credentials:**
   ```bash
   nano .env  # or use your preferred editor
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the connector locally:**
   ```bash
   # Using the main connector framework
   python connector.py upload insight
   
   # Or using the standalone script (for testing)
   python src/connector.py
   ```

### Testing Individual Components

```bash
# Test Insight API connection
python -c "from connectors.insight import Connector; print('Connection test')"

# Run with specific date range
export INSIGHT_ORDER_CREATION_DATE_FROM="2025-07-01"
export INSIGHT_ORDER_CREATION_DATE_TO="2025-07-15"
python connector.py upload insight
```

## Configuration

### Environment Variables

The integration supports configuration through environment variables (prioritized over config.ini):

| Variable | Description | Default |
|----------|-------------|---------|
| `OOMNITZA_URL` | Oomnitza instance URL | Required |
| `OOMNITZA_API_TOKEN` | API authentication token | Required |
| `INSIGHT_URL` | Insight API endpoint | Required |
| `INSIGHT_CLIENT_ID` | Client identifier | Required |
| `INSIGHT_CLIENT_KEY` | API key for authentication | Required |
| `INSIGHT_CLIENT_SECRET` | API secret | Required |
| `INSIGHT_ORDER_CREATION_DATE_FROM` | Start date for sync | Yesterday |
| `INSIGHT_ORDER_CREATION_DATE_TO` | End date for sync | Yesterday |
| `INSIGHT_TRACKING_DATA` | Include tracking information | `True` |

### config.ini File

For local development, you can also use the `config.ini` file:

```ini
[oomnitza]
enable = True
url = https://yourinstance.oomnitza.com
api_token = <oomnitza_api_token>

[insight]
enable = True
client_id = <insight_client_id>
client_key = <insight_client_key>
client_secret = <insight_client_secret>
insight_url = https://insight-prod.apigee.net/GetStatus
order_creation_date_from = 2025-07-18
order_creation_date_to = 2025-07-21
tracking_data = True
```

## Data Mapping

The integration maps Insight fields to Oomnitza as follows:

| Insight Field | Oomnitza Field | Transformation |
|---------------|----------------|----------------|
| `order.purchaseOrderNumber` | `PO_NUMBER` | Direct copy |
| `lineItem.serialNumber` | `SERIAL_NUMBER` | Primary key for matching |
| `lineItem.product.sku` | `SKU` | Direct copy |
| `lineItem.product.description` | `MODEL` | Truncated to 255 chars |
| `order.purchaseDate` | `PURCHASE_DATE` | Converted to YYYY-MM-DD |
| `lineItem.unitPrice` | `PURCHASE_PRICE` | Converted to float |
| `order.trackingInfo.carrier` | `SHIPPING_CARRIER` | Direct copy |
| `order.trackingInfo.trackingNumber` | `TRACKING_NUMBER` | Direct copy |

## Monitoring & Troubleshooting

### Viewing Logs

1. Navigate to the **Actions** tab in your repository
2. Click on a specific workflow run
3. Click on the `sync-data` job
4. Expand the "Run Oomnitza-Insight Sync" step to see detailed logs

### Common Issues

**Issue: Missing credentials error**
- Solution: Ensure all required GitHub Secrets are configured correctly

**Issue: API rate limiting**
- Solution: The connector automatically handles pagination with 60-day intervals

**Issue: Duplicate assets**
- Solution: The integration uses SERIAL_NUMBER as primary key and performs upsert operations

**Issue: Date range too large**
- Solution: Insight API limits to 180 days; the connector automatically splits into smaller chunks

### Log Examples

Successful sync:
```
2025-07-20 05:00:01 - INFO - Starting Insight to Oomnitza data sync
2025-07-20 05:00:02 - INFO - Successfully authenticated with Insight API
2025-07-20 05:00:05 - INFO - Fetched 42 new asset records from Insight
2025-07-20 05:00:08 - INFO - Successfully created/updated 42 assets in Oomnitza
2025-07-20 05:00:09 - INFO - Data sync finished successfully
```

## Security Best Practices

1. **Credential Rotation**: Rotate API tokens regularly
2. **Access Control**: Limit repository access to authorized personnel
3. **Audit Logs**: Regularly review GitHub Actions logs
4. **Secret Management**: Never commit credentials to the repository
5. **Branch Protection**: Enable branch protection rules for main branch

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   GitHub Actions│────▶│  Python Connector│────▶│   Insight API   │
│   (Scheduler)   │     │   (connector.py) │     │  (Procurement)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │                          
                               ▼                          
                        ┌──────────────────┐              
                        │   Oomnitza API   │              
                        │ (Asset Management)│              
                        └──────────────────┘              
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For issues or questions:
- Check the Issues section of your repository
- Review the logs in GitHub Actions
- Contact your IT administrator

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on the [Oomnitza Connector Framework](https://github.com/Oomnitza/oomnitza-connector)
- Automated with GitHub Actions
- Powered by Python 3.12+
