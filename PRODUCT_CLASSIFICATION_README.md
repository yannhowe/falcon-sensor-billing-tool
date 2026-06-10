# Falcon Sensor Product Classification

This tool now classifies sensor usage into four CrowdStrike product types for accurate billing and licensing:

## Product Types

### FCSC - Falcon Cloud Security Complete
**Container Hosts**: Kubernetes worker nodes, Docker hosts, ECS cluster EC2 instances
- Platform: K8S
- Tags containing: kubernetes, k8s, worker, node, aks, eks, gke, openshift, rancher, docker
- Hostname patterns: `*-worker-*`, `*-node-*`, `aks-*`, `gke-*`, AWS EKS patterns

### FMC - Falcon Managed Cloud  
**Fargate & Sidecars**: ECS Fargate, Kubernetes Fargate, sidecar containers, image-integrated sensors
- Tags containing: fargate, sidecar, ecs-task, pod-injection
- Hostname patterns: `fargate-*`, `ecs-*-fargate-*`, `*-sidecar-*`

### FCS - Falcon Cloud Security
**Cloud VMs**: AWS EC2, Azure VMs, GCP Compute instances (non-container hosts)
- Streamlined licensing for cloud workloads
- Tags containing: aws, ec2, azure, gcp, cloud, vm, compute, instance
- Hostname patterns: AWS instance IDs (`i-*`), IP patterns (`ip-10-0-1-55`), cloud domains

### EPP - Endpoint Protection Platform
**Traditional Endpoints**: Laptops, workstations, on-premise servers, mobile devices
- Windows workstations
- Mac laptops
- Android/iOS mobile devices  
- ChromeOS devices
- On-premise servers (though these could be classified as FCS in hybrid environments)

## Current Classification Results

Based on your data (479 total hosts):

| Product | 28-Day Avg | Unique Hosts | Description |
|---------|------------|--------------|-------------|
| **FCSC** | 88.0 | 88 | Container hosts (K8s nodes, Docker) |
| **FMC**  | 0.0  | 0  | Fargate/sidecars |
| **FCS**  | 77.0 | 77 | Cloud VMs |
| **EPP**  | 314.0 | 314 | Traditional endpoints |
| **Total** | **479.0** | **479** | |

## Files Created

1. **`classify_products.py`** - Classification logic module
   - `classify_sensor()` - Main classification function
   - `classify_sensor_from_row()` - Helper for database rows

2. **`add_product_classification.py`** - Database migration script
   - Adds `product_type` column to tables
   - Classifies all existing hosts
   - Updates sensor logs

3. **Web Dashboard Updates**:
   - `/api/product_breakdown` - Get 28-day averages by product type
   - `/api/product_trend` - Get hourly trend breakdown by product
   - New UI section with product type cards and trend chart

## Usage

### 1. Classify Existing Data
```bash
python3 add_product_classification.py
```

### 2. View in Dashboard
```bash
python3 web_dashboard.py
# Visit http://localhost:5000
```

The dashboard now shows:
- Product type breakdown cards (FCSC, FMC, FCS, EPP)
- 28-day rolling average per product
- Stacked area chart showing trend over time

### 3. Re-classify After New Data Collection
```bash
python3 add_product_classification.py
```

## Classification Logic Flow

```
┌─────────────────┐
│  Check Platform │
│   (K8S = FCSC)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Check Tags for:│
│  - Kubernetes   │  ───→ FCSC
│  - Docker       │
│  - Fargate      │  ───→ FMC
│  - Sidecar      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Check Hostname: │
│  - AWS patterns │  ───→ FCS
│  - Azure patterns│
│  - GCP patterns  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Default: EPP   │
│  (Traditional   │
│   Endpoints)    │
└─────────────────┘
```

## Customizing Classification

Edit `classify_products.py` to adjust the classification logic:

```python
# Add custom patterns
k8s_indicators = [
    'kubernetes', 'k8s', 'worker', 'node',
    'your-custom-tag'  # <-- Add here
]

# Add custom hostname patterns
custom_patterns = [
    r'your-pattern-.*',
]
```

Then re-run classification:
```bash
python3 add_product_classification.py
```

## API Examples

### Get Product Breakdown
```bash
curl "http://localhost:5000/api/product_breakdown?days=28"
```

Returns:
```json
{
  "products": [
    {
      "product_type": "FCSC",
      "unique_sensors": 88,
      "avg_28day": 88.0,
      "hours_active": 672
    },
    ...
  ],
  "total_avg_28day": 479.0
}
```

### Get Product Trend
```bash
curl "http://localhost:5000/api/product_trend?days=7"
```

Returns hourly breakdown:
```json
[
  {
    "timestamp": "2026-04-14 12:00:00",
    "FCSC": 88,
    "FMC": 0,
    "FCS": 77,
    "EPP": 314
  },
  ...
]
```

## Benefits

1. **Accurate Billing**: Know exactly how many hosts fall under each product tier
2. **License Optimization**: Identify opportunities to switch licensing models (e.g., EPP → FCS for cloud workloads)
3. **Hybrid Environment Clarity**: See breakdown of on-premise vs cloud vs container workloads
4. **Prevent Double-Counting**: FCS uses hourly average instead of unique-per-day (avoids inflation)

## Licensing Best Practices

- **Cloud workloads**: Use FCS instead of EPP to avoid inflated counts from auto-scaling
- **Container hosts**: Always use FCSC for K8s worker nodes and Docker hosts
- **Fargate**: Use FMC for serverless containers
- **Hybrid migrations**: As workloads move to cloud, shift from EPP to FCS licensing

