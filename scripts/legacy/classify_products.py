#!/usr/bin/env python3
"""
Product Classification Logic for Falcon Sensors

Classifies sensors into:
- FCS: Falcon Cloud Security (cloud VMs)
- FCSC: Falcon Cloud Security Complete (container hosts)
- FMC: Falcon Managed Cloud (Fargate, sidecars)
- EPP: Endpoint Protection Platform (traditional endpoints)
"""
import json
import re


def classify_sensor(hostname, platform_name, tags_json, groups_json=None):
    """
    Classify a sensor based on its attributes.
    
    Args:
        hostname: Host hostname
        platform_name: Platform (K8S, Linux, Windows, etc.)
        tags_json: JSON string of tags list
        groups_json: JSON string of groups list (optional)
    
    Returns:
        str: Product classification (FCSC, FMC, FCS, EPP)
    """
    # Parse tags
    try:
        tags = json.loads(tags_json) if tags_json else []
    except:
        tags = []
    
    # Parse groups
    try:
        groups = json.loads(groups_json) if groups_json else []
    except:
        groups = []
    
    # Convert to lowercase for matching
    tags_lower = [t.lower() for t in tags]
    groups_lower = [g.lower() for g in groups]
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
    
    # Check for Fargate indicators
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
        # Check if hostname looks like a cloud instance
        if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', hostname_lower):
            return "FCS"
    
    # ===== EPP: Traditional Endpoints =====
    # Everything else: laptops, workstations, on-premise servers
    
    return "EPP"


def classify_sensor_from_row(row):
    """
    Classify a sensor from a database row.
    
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
        tags_json=tags_json,
        groups_json=groups_json
    )


if __name__ == '__main__':
    # Test classification logic
    test_cases = [
        {
            'hostname': 'ip-10-0-1-55.us-west-2.compute.internal',
            'platform': 'Linux',
            'tags': '["SensorGroupingTags/kubernetes", "SensorGroupingTags/worker-node"]',
            'expected': 'FCSC'
        },
        {
            'hostname': 'fargate-task-123456',
            'platform': 'Linux',
            'tags': '["SensorGroupingTags/fargate"]',
            'expected': 'FMC'
        },
        {
            'hostname': 'ec2-instance-web01',
            'platform': 'Linux',
            'tags': '["SensorGroupingTags/aws", "SensorGroupingTags/web-server"]',
            'expected': 'FCS'
        },
        {
            'hostname': 'laptop-john-doe',
            'platform': 'Windows',
            'tags': '[]',
            'expected': 'EPP'
        },
        {
            'hostname': '/subscriptions/xxx/managedClusters/aks-cluster',
            'platform': 'K8S',
            'tags': '[]',
            'expected': 'FCSC'
        }
    ]
    
    print("Testing classification logic:\n")
    for case in test_cases:
        result = classify_sensor(
            case['hostname'],
            case['platform'],
            case['tags']
        )
        status = "✓" if result == case['expected'] else "✗"
        print(f"{status} {case['hostname'][:50]:50} -> {result:6} (expected: {case['expected']})")
