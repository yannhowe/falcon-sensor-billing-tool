"""Product and cloud provider classification for Falcon sensors.

Product types: FCSC (container hosts), FMC (managed containers),
               FCS (cloud VMs), EPP (traditional endpoints)

Cloud providers: AWS, Azure, GCP, Oracle, Alibaba, On-Premise, End-User-Device
"""
import json
import re


def classify_sensor(hostname, platform_name, tags, groups=None):
    """Classify a sensor based on its attributes.

    Args:
        hostname: Host hostname
        platform_name: Platform (K8S, Linux, Windows, etc.)
        tags: JSON string of tags list (or None)
        groups: JSON string of groups list (optional)

    Returns:
        str: Product classification (FCSC, FMC, FCS, EPP)
    """
    # Parse tags
    try:
        tags_list = json.loads(tags) if tags else []
    except Exception:
        tags_list = []

    # Parse groups
    try:
        groups_list = json.loads(groups) if groups else []
    except Exception:
        groups_list = []

    # Convert to lowercase for matching
    tags_lower = [t.lower() for t in tags_list]
    hostname_lower = hostname.lower() if hostname else ""

    # ===== FCSC: Container Hosts =====
    # Kubernetes worker nodes, Docker hosts, ECS cluster EC2 hosts

    # K8S platform is definitely FCSC
    if platform_name == "K8S":
        return "FCSC"

    # Check for Kubernetes-related tags
    k8s_indicators = [
        'kubernetes', 'k8s', 'worker', 'node', 'aks', 'eks', 'gke',
        'openshift', 'rancher', 'kube', 'cluster'
    ]
    for tag in tags_lower:
        if any(indicator in tag for indicator in k8s_indicators):
            return "FCSC"

    # Check for Docker-related tags
    docker_indicators = ['docker', 'container-host', 'containerd']
    for tag in tags_lower:
        if any(indicator in tag for indicator in docker_indicators):
            return "FCSC"

    # Check hostname patterns for Kubernetes
    k8s_hostname_patterns = [
        r'.*-worker.*', r'.*-node.*', r'.*worker.*', r'.*node-\d+.*',
        r'ip-\d+-\d+-\d+-\d+\..*\.compute\..*',  # AWS EKS pattern
        r'aks-.*', r'gke-.*'  # AKS/GKE patterns
    ]
    for pattern in k8s_hostname_patterns:
        if re.match(pattern, hostname_lower):
            return "FCSC"

    # ===== FMC: Fargate, Sidecars, Image-integrated =====

    # Check for Fargate indicators in tags
    fargate_indicators = ['fargate', 'sidecar', 'ecs-task', 'pod-injection']
    for tag in tags_lower:
        if any(indicator in tag for indicator in fargate_indicators):
            return "FMC"

    # Check hostname for Fargate patterns
    fargate_patterns = [
        r'fargate.*', r'ecs-.*-fargate.*', r'.*-sidecar-.*'
    ]
    for pattern in fargate_patterns:
        if re.match(pattern, hostname_lower):
            return "FMC"

    # ===== FCS: Cloud VMs =====
    # AWS EC2, Azure VMs, GCP Compute (that aren't container hosts)

    cloud_vm_indicators = [
        'aws', 'ec2', 'azure', 'gcp', 'cloud', 'vm', 'compute',
        'instance', 'i-0', 'i-1', 'i-2', 'i-3', 'i-4', 'i-5', 'i-6', 'i-7', 'i-8', 'i-9'
    ]

    # Check tags for cloud indicators
    for tag in tags_lower:
        if any(indicator in tag for indicator in cloud_vm_indicators):
            return "FCS"

    # Check hostname patterns for cloud VMs
    cloud_hostname_patterns = [
        r'ip-\d+-\d+-\d+-\d+',  # AWS private IP format
        r'i-[0-9a-f]+',  # AWS instance ID
        r'.*\.compute\.amazonaws\.com',  # AWS compute
        r'.*\.azure\.com',  # Azure
        r'.*\.gcp\..*',  # GCP
    ]
    for pattern in cloud_hostname_patterns:
        if re.search(pattern, hostname_lower):
            return "FCS"

    # Linux/Windows servers in cloud could be FCS if they have cloud-like names
    if platform_name in ['Linux', 'Windows']:
        if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', hostname_lower):
            return "FCS"

    # ===== EPP: Traditional Endpoints =====
    # Everything else: laptops, workstations, on-premise servers

    return "EPP"


def classify_sensor_from_row(row):
    """Classify a sensor from a database row.

    Args:
        row: SQLite row object with hostname, platform_name, tags, groups

    Returns:
        str: Product classification
    """
    try:
        hostname = row['hostname'] if 'hostname' in row.keys() else None
        platform_name = row['platform_name'] if 'platform_name' in row.keys() else None
        tags_json = row['tags'] if 'tags' in row.keys() else None
        groups_json = row['groups'] if 'groups' in row.keys() else None
    except (KeyError, TypeError):
        hostname = None
        platform_name = None
        tags_json = None
        groups_json = None

    return classify_sensor(
        hostname=hostname,
        platform_name=platform_name,
        tags=tags_json,
        groups=groups_json,
    )


def is_cloud_vm(manufacturer=None, cloud_provider=None, tags=None, product_type_desc=None) -> bool:
    """Determine if a host is FCS-billable (VM/server) vs EPP (user endpoint).

    Goal: Maximize FCS classification. Any VM or server (cloud or on-prem)
    should be FCS. Only physical workstations, laptops, and mobile devices
    should be EPP.

    Classification priority:
    1. Manufacturer is a hypervisor → FCS (VM, including VDI)
    2. cloud_provider field (IMDS) → FCS (cloud VM)
    3. Manufacturer is a cloud vendor → FCS
    4. product_type_desc is Server/Domain Controller → FCS (bare-metal server)
    5. sensor_tags with cloud/vm keywords → FCS
    6. Everything else → EPP (physical workstation, laptop, mobile)

    Args:
        manufacturer: system_manufacturer from Hosts API (DMI string)
        cloud_provider: cloud_provider from Hosts API (IMDS auto-detected)
        tags: JSON string or list of sensor tags
        product_type_desc: product_type_desc from Hosts API (Server, Workstation, etc.)

    Returns:
        bool: True if FCS-eligible, False if EPP
    """
    # --- 1. Manufacturer is a hypervisor → FCS (any VM, including VDI) ---
    if manufacturer:
        mfr_lower = manufacturer.strip().lower()

        hypervisor_patterns = [
            'vmware',
            'innotek',        # VirtualBox
            'bochs',          # KVM/QEMU
            'qemu',
            'red hat',        # KVM on-prem
            'xen',            # Citrix/AWS Xen
            'parallels',
            'nutanix',        # AHV hypervisor
        ]
        for pattern in hypervisor_patterns:
            if pattern in mfr_lower:
                return True

        # "Microsoft Corporation" as manufacturer = Hyper-V VM
        # (not to be confused with physical Surface devices which report
        # "Microsoft Corporation" but have product_type_desc=Workstation
        # and no hypervisor traits — handled below)
        if 'microsoft corporatio' in mfr_lower:
            # Microsoft Corporation as manufacturer almost always means Hyper-V/Azure VM
            # Physical Surface devices are rare in enterprise server fleets
            return True

    # --- 2. cloud_provider field (IMDS auto-detected) ---
    if cloud_provider:
        cp_lower = cloud_provider.strip().lower()
        cloud_cp_values = {
            'aws', 'azure', 'gcp', 'oci', 'oracle',
            'alibaba', 'huawei', 'tencent', 'volcengine',
        }
        if cp_lower in cloud_cp_values:
            return True

    # --- 3. Manufacturer is a cloud vendor ---
    if manufacturer:
        mfr_lower = manufacturer.strip().lower()
        cloud_mfr_patterns = [
            'amazon ec2',
            'amazon',
            'google',
            'alibaba cloud',
            'alibaba',
            'aliyun',
            'oracle cloud',
            'huawei cloud',
            'tencent cloud',
        ]
        for pattern in cloud_mfr_patterns:
            if pattern in mfr_lower:
                return True

    # --- 4. product_type_desc indicates server role → FCS (bare-metal server) ---
    if product_type_desc:
        ptd_lower = product_type_desc.strip().lower()
        if ptd_lower in ('server', 'domain controller'):
            return True

    # --- 5. Fallback: sensor_tags ---
    try:
        if isinstance(tags, str):
            tags_list = json.loads(tags) if tags else []
        elif isinstance(tags, list):
            tags_list = tags
        else:
            tags_list = []
    except Exception:
        tags_list = []

    cloud_tag_keywords = [
        'aws', 'ec2', 'azure', 'gcp', 'google cloud',
        'alibaba', 'aliyun', 'oracle cloud', 'oci',
        'huawei cloud', 'tencent cloud', 'volcengine',
        'cloud', 'vm', 'vdi',
    ]
    tags_lower = [str(t).lower() for t in tags_list]
    for tag in tags_lower:
        if any(kw in tag for kw in cloud_tag_keywords):
            return True

    # --- 6. Default: EPP (physical workstation, laptop, mobile) ---
    return False


def classify_cloud_provider(hostname, platform_name, tags):
    """Classify cloud provider based on hostname patterns, platform, and tags.

    Args:
        hostname: Host hostname
        platform_name: Platform (Linux, Windows, Mac, Android, iOS, etc.)
        tags: JSON string of tags list (or None)

    Returns:
        str: Cloud provider classification — one of:
             AWS, Azure, GCP, Oracle, Alibaba, On-Premise, End-User-Device
    """
    # Parse tags
    try:
        tags_list = json.loads(tags) if tags else []
    except Exception:
        tags_list = []

    tags_lower = [t.lower() for t in tags_list]
    hostname_lower = hostname.lower() if hostname else ""

    # ===== End-User Devices =====
    if platform_name in ['Android', 'iOS', 'ChromeOS', 'Mac']:
        return 'End-User-Device'

    if platform_name == 'Windows':
        # Classic desktop/laptop hostname patterns (no IP-style naming)
        if not re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', hostname_lower):
            return 'End-User-Device'

    # ===== Tag-based cloud detection =====
    tag_provider_map = [
        (['aws', 'ec2', 'eks'], 'AWS'),
        (['azure', 'aks'], 'Azure'),
        (['gcp', 'gke', 'google'], 'GCP'),
        (['oracle', 'oci'], 'Oracle'),
        (['alibaba', 'aliyun'], 'Alibaba'),
    ]
    for indicators, provider in tag_provider_map:
        for tag in tags_lower:
            if any(ind in tag for ind in indicators):
                return provider

    # ===== Hostname-based cloud detection =====

    # AWS: ip-X-X-X-X.*.ec2.internal / ip-X-X-X-X.*.compute.internal / .amazonaws.com
    if re.search(r'ip-\d+-\d+-\d+-\d+\..*\.(ec2|compute)\.internal', hostname_lower):
        return 'AWS'
    if re.search(r'\.compute\.amazonaws\.com', hostname_lower):
        return 'AWS'
    if re.search(r'\bec2\b', hostname_lower):
        return 'AWS'

    # Azure: *.cloudapp.net / *.azure.com / *.internal.cloudapp.net
    if re.search(r'\.cloudapp\.net', hostname_lower):
        return 'Azure'
    if re.search(r'\.azure\.com', hostname_lower):
        return 'Azure'

    # GCP: *.c.<project>.internal / gke-* / *.googleapis.com
    if re.search(r'\.c\.[a-z0-9-]+\.internal', hostname_lower):
        return 'GCP'
    if re.search(r'^gke-', hostname_lower):
        return 'GCP'
    if re.search(r'\.googleapis\.com', hostname_lower):
        return 'GCP'

    # ===== Default for servers =====
    if platform_name in ['Linux', 'Windows']:
        return 'On-Premise'

    return 'On-Premise'
