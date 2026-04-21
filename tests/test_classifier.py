"""Tests for falcon_billing.classifier."""

import json
import pytest
from falcon_billing.classifier import classify_sensor, classify_cloud_provider


class TestClassifySensor:
    def test_k8s_host_is_fcsc(self):
        result = classify_sensor(
            hostname="ip-10-0-1-5.ec2.internal",
            platform_name="Linux",
            tags=json.dumps(["SensorGroupingTag/eks-cluster"]),
            groups=json.dumps(["k8s-nodes"]),
        )
        assert result == "FCSC"

    def test_fargate_is_fmc(self):
        result = classify_sensor(
            hostname="fargate-task-abc123",
            platform_name="Linux",
            tags=json.dumps(["SensorGroupingTag/fargate"]),
            groups=json.dumps([]),
        )
        assert result == "FMC"

    def test_cloud_vm_is_fcs(self):
        result = classify_sensor(
            hostname="ip-10-0-1-5.ec2.internal",
            platform_name="Linux",
            tags=json.dumps(["SensorGroupingTag/aws-prod"]),
            groups=json.dumps([]),
        )
        assert result == "FCS"

    def test_laptop_is_epp(self):
        result = classify_sensor(
            hostname="DESKTOP-ABC123",
            platform_name="Windows",
            tags=json.dumps([]),
            groups=json.dumps([]),
        )
        assert result == "EPP"

    def test_none_inputs_handled(self):
        result = classify_sensor(hostname=None, platform_name=None, tags=None, groups=None)
        assert result == "EPP"


class TestClassifyCloudProvider:
    def test_aws_hostname(self):
        result = classify_cloud_provider(
            hostname="ip-10-0-1-5.ec2.internal",
            platform_name="Linux",
            tags=json.dumps(["SensorGroupingTag/aws"]),
        )
        assert result == "AWS"

    def test_azure_hostname(self):
        result = classify_cloud_provider(
            hostname="my-vm.internal.cloudapp.net",
            platform_name="Linux",
            tags=json.dumps([]),
        )
        assert result == "Azure"

    def test_gcp_hostname(self):
        result = classify_cloud_provider(
            hostname="gke-cluster-node-pool-abc.c.project.internal",
            platform_name="Linux",
            tags=json.dumps([]),
        )
        assert result == "GCP"

    def test_windows_desktop_is_end_user(self):
        result = classify_cloud_provider(
            hostname="LAPTOP-ABC",
            platform_name="Windows",
            tags=json.dumps([]),
        )
        assert result == "End-User-Device"

    def test_linux_server_default_on_premise(self):
        result = classify_cloud_provider(
            hostname="app-server-01",
            platform_name="Linux",
            tags=json.dumps([]),
        )
        assert result == "On-Premise"
