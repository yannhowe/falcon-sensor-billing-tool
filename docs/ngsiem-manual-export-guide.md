# NGSIEM Manual Export Guide
## Gojek Billing Analysis — Host Inventory & Cloud Classification

All queries are tested and confirmed working. Follow the step-by-step instructions below to export each dataset from the Falcon UI, then drop the CSV files into the project folder for analysis.

---

## How to Navigate to NG-SIEM

1. Log into **[falcon.crowdstrike.com](https://falcon.crowdstrike.com)**
2. In the left nav, go to **Next-Gen SIEM** → **Log Management** → **Advanced Event Search**
3. You should see a LogScale query editor with a time picker in the top right

---

## Before You Start

- **Time picker:** Set to **Last 7 days** before running each query (top right of the query editor)
- **Run query:** Click the blue **Search** / **Run** button
- **Export:** Once results load, click the **Download** icon (↓) above the results table → select **CSV**
- **File naming:** Save each export with the filename shown below so the analysis script can find them

---

## Export 1: Unique Hosts Per Hour

**Filename:** `q1_hosts_per_hour.csv`

**What it's for:** Billing calculation — unique sensors active per clock hour over 7 days.

```
#event_simpleName=AgentOnline OR #event_simpleName=ProcessRollup2 OR #event_simpleName=UserLogon
| hour_key := formatTime("%Y-%m-%dT%H:00:00Z", field=@timestamp, timezone="UTC")
| groupBy([hour_key, aid], function=count(), limit=max)
| sort(field=hour_key, order=asc)
```

**Columns:** `hour_key`, `aid`, `_count`

Each row = one sensor active in that hour. Count distinct `aid` per `hour_key` → hourly unique sensor count. Sum ÷ hours = 28-day rolling average.

**Sample:**
```
hour_key,aid,_count
2026-05-13T21:00:00Z,006ac5711c3145d3...,309
2026-05-13T21:00:00Z,0a41105696fa4c0c...,647
```

---

## Export 2: Host Metadata Snapshot

**Filename:** `q2_host_metadata.csv`

**What it's for:** One row per unique sensor — hostname, IPs, platform, hardware manufacturer. `SystemManufacturer` is the primary cloud signal.

```
#event_simpleName=AgentOnline
| groupBy([aid], function=[
    selectLast([
      ComputerName,
      aip,
      LocalAddressIP4,
      ConfigBuild,
      event_platform,
      MachineDomain,
      SystemManufacturer,
      SystemProductName,
      BiosVersion
    ]),
    max(@timestamp, as=last_seen_epoch)
  ], limit=max)
| last_seen := formatTime("%Y-%m-%dT%H:%M:%SZ", field=last_seen_epoch)
| drop([last_seen_epoch])
| sort(field=last_seen, order=desc)
```

**Columns:** `aid`, `ComputerName`, `aip`, `LocalAddressIP4`, `ConfigBuild`, `event_platform`, `MachineDomain`, `SystemManufacturer`, `SystemProductName`, `BiosVersion`, `last_seen`

**`SystemManufacturer` cloud reference:**
| Value | Cloud |
|-------|-------|
| `Amazon EC2` | AWS EC2 |
| `Xen` | AWS or Azure (older instance type) |
| `Microsoft Corporation` | Azure (especially with `aks-` hostname) |
| `Google` | GCP |
| `Alibaba Cloud ECS` | **Alibaba Cloud** |
| `VMware, Inc.` | VMware on-prem or VMware Cloud |
| `Dell Inc.` / `HP` / `Lenovo` | Physical hardware / laptop |
| `QEMU` | KVM / on-prem virtualisation |
| empty | Mobile device or unknown |

**Sample:**
```
aid,ComputerName,aip,LocalAddressIP4,event_platform,SystemManufacturer,last_seen
08cea86f...,ip-172-31-31-108.ec2.internal,54.173.99.60,,Lin,Amazon EC2,2026-05-14T03:22:57
7c0b12d3...,aks-agentpool-35640463-vmss00000D,172.210.97.252,10.224.0.10,Lin,Microsoft Corporation,2026-05-14T01:03:39
98789468...,DANNYH-WIN11-LT,173.72.161.6,192.168.38.52,Win,Dell Inc.,2026-05-13T22:54:39
```

---

## Export 3: IMDS Traffic — Cloud Provider Detection

**Filename:** `q3_imds_traffic.csv`

**What it's for:** Cloud hosts call the IMDS (Instance Metadata Service) to get instance info. **Alibaba Cloud ECS uses `100.100.100.200`** — distinct from the `169.254.169.254` used by AWS/Azure/GCP.

```
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4 = "169.254.169.254" OR RemoteAddressIP4 = "100.100.100.200" OR RemoteAddressIP4 = "169.254.42.42"
| groupBy([aid, RemoteAddressIP4], function=[
    count(as=connection_count),
    selectLast([ComputerName, LocalAddressIP4])
  ], limit=max)
| sort(field=connection_count, order=desc)
```

**Columns:** `aid`, `RemoteAddressIP4`, `connection_count`, `ComputerName`, `LocalAddressIP4`

**IMDS IP reference:**
| IP | Cloud |
|----|-------|
| `169.254.169.254` | AWS, Azure, GCP, Oracle (use Export 4 to distinguish) |
| `100.100.100.200` | **Alibaba Cloud ECS** |
| `169.254.42.42` | Scaleway |

**Sample:**
```
aid,RemoteAddressIP4,connection_count,ComputerName,LocalAddressIP4
551cda52...,169.254.169.254,1686,ip-172-31-0-47.us-east-2.compute.internal,
9e22a031...,169.254.169.254,1661,aks-nodepool1-85827039-vmss000002,10.224.0.11
```

---

## Export 4: Cloud Agent Process Fingerprint

**Filename:** `q4_imds_processes.csv`

**What it's for:** Identifies which cloud management agent is making IMDS calls — distinguishes AWS vs Azure vs GCP for hosts that all share the `169.254.169.254` IMDS IP.

```
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4 = "169.254.169.254"
| groupBy([aid, ContextBaseFileName], function=[
    count(as=connection_count),
    selectLast([ComputerName])
  ], limit=max)
| sort(field=connection_count, order=desc)
```

**Columns:** `aid`, `ContextBaseFileName`, `connection_count`, `ComputerName`

**Process → Cloud mapping (confirmed from live data):**
| Process | Cloud |
|---------|-------|
| `amazon-ssm-agent`, `ssm-document-worker`, `aws` | AWS |
| `azure-cloud-node-manager`, `waagent`, `mdsd` | Azure |
| `gce_workload_cert_refresh`, `google_cloud_ops_agent` | GCP |
| `aliyun-service`, `aliyun_assist_service` | Alibaba Cloud |
| `curl`, `python3.x` | Generic — check hostname/manufacturer |

**Sample:**
```
aid,ContextBaseFileName,connection_count,ComputerName
551cda52...,curl,1679,ip-172-31-0-47.us-east-2.compute.internal
...,amazon-ssm-agent,165,...
...,azure-cloud-node-manager,42,...
...,gce_workload_cert_refresh,36,...
```

---

## Export 5: Installed Cloud Management Agents

**Filename:** `q5_installed_apps.csv`

**What it's for:** Cloud VMs come pre-installed with cloud management agents. This is a strong secondary signal — especially for Alibaba, which installs `Alibaba Cloud Assist` or `AliyunService`. Works even if IMDS traffic wasn't captured.

```
#event_simpleName=InstalledApplication
| AppName = /alibaba|aliyun|amazon|aws|azure|google|tencent|tencentcloud/i
| groupBy([aid, AppName, AppVendor, AppVersion], function=[
    count(as=event_count),
    selectLast([ComputerName, event_platform])
  ], limit=max)
| sort(field=AppName, order=asc)
```

**Columns:** `aid`, `AppName`, `AppVendor`, `AppVersion`, `event_count`, `ComputerName`, `event_platform`

**Known cloud management agents:**
| AppName pattern | Cloud |
|-----------------|-------|
| `Alibaba Cloud Assist`, `AliyunService`, `aliyun_assist_service` | **Alibaba Cloud** |
| `Amazon SSM Agent`, `AWS CLI`, `Amazon CloudWatch Agent` | AWS |
| `Microsoft Azure Arc`, `Azure Monitor Agent`, `waagent` | Azure |
| `Google Cloud Ops Agent`, `Google Cloud SDK` | GCP |
| `Tencent Cloud Monitor`, `tat_agent` | Tencent Cloud |

> **Note:** This catches hosts that don't generate IMDS network events (e.g. hosts where network telemetry is reduced). Good complement to Export 3.

---

## Export 6: User Logon Domain (AD vs Cloud)

**Filename:** `q6_logon_domain.csv`

**What it's for:** AD-joined machines log on to a Windows domain. Cloud VMs typically show `WORKGROUP`, a local hostname, or a cloud-specific domain (e.g. `EC2AMAZ-*`). Helps separate on-prem domain-joined machines from cloud instances with no AD membership.

```
#event_simpleName=UserLogon
| groupBy([aid], function=[
    selectLast([ComputerName, UserName, LogonDomain, LogonServer, LogonType,
                UserIsAdmin, LocalAddressIP4, aip, event_platform]),
    max(@timestamp, as=last_seen_epoch)
  ], limit=max)
| last_seen := formatTime("%Y-%m-%dT%H:%M:%SZ", field=last_seen_epoch)
| drop([last_seen_epoch])
| sort(field=LogonDomain, order=asc)
```

**Columns:** `aid`, `ComputerName`, `UserName`, `LogonDomain`, `LogonServer`, `LogonType`, `UserIsAdmin`, `LocalAddressIP4`, `aip`, `event_platform`, `last_seen`

**How to read `LogonDomain`:**
| Value | Likely environment |
|-------|--------------------|
| Corporate AD domain (e.g. `GOJEK`, `CORP`) | On-premise / domain-joined |
| `WORKGROUP` | Cloud VM or standalone machine |
| Matches hostname (e.g. `EC2AMAZ-CUR91L9`) | Cloud VM, local account only |
| `Window Manager`, `Font Driver Host`, `VIRTUAL USERS` | Windows internal service accounts — ignore |

**Sample:**
```
aid,ComputerName,UserName,LogonDomain,LogonType
3018c822...,WHUP-EAGLE-ADMN,tgenerator,WORKSHOP,4
9d56ae57...,SE-DJS-WDCIKVM,UMFD-0,Font Driver Host,2
08cea86f...,ip-172-31-31-108.ec2.internal,ec2-user,ip-172-31-31-108,3
```

---

## Where to Drop the Files

Place all CSV files in:

```
projects/falcon-sensor-billing-tool/gojek-export/
```

Exact filenames:
```
gojek-export/
├── q1_hosts_per_hour.csv
├── q2_host_metadata.csv
├── q3_imds_traffic.csv
├── q4_imds_processes.csv
├── q5_installed_apps.csv
└── q6_logon_domain.csv
```

Once the files are there, the analysis will join all datasets on `aid`, classify each host by cloud provider, and output a corrected billing breakdown.

---

## Signal Priority for Cloud Classification

| Priority | Signal | Source | Field |
|----------|--------|--------|-------|
| 1 | IMDS IP `100.100.100.200` | Q3 | `RemoteAddressIP4` — definitive Alibaba |
| 2 | `AppName` contains `alibaba` or `aliyun` | Q5 | `AppName` |
| 3 | `SystemManufacturer = "Alibaba Cloud ECS"` | Q2 | `SystemManufacturer` |
| 4 | Process `aliyun-service` / `aliyun_assist_service` | Q4 | `ContextBaseFileName` |
| 5 | `SystemManufacturer = "Amazon EC2"` | Q2 | `SystemManufacturer` |
| 6 | Process `amazon-ssm-agent` or `AppName` contains `Amazon SSM` | Q4 / Q5 | |
| 7 | Hostname pattern `ip-*.ec2.internal` or `i-[0-9a-f]+` | Q2 | `ComputerName` |
| 8 | `SystemManufacturer = "Microsoft Corporation"` + `aks-` hostname | Q2 | |
| 9 | Process `azure-cloud-node-manager` | Q4 | |
| 10 | `LogonDomain = "WORKGROUP"` or matches hostname | Q6 | Suggests cloud, not confirmed |
| 11 (lowest) | No signals | — | Assume On-Premise / Unknown |
