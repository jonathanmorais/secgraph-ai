from graphsec.connectors.k8s.cluster import parse_image_ref, parse_instance_id
from graphsec.scan.trivy import parse_trivy_json, summarize_counts, worst_severity


def test_parse_instance_id():
    assert parse_instance_id("aws:///us-east-1a/i-0abc123def") == "i-0abc123def"
    assert parse_instance_id(None) is None
    assert parse_instance_id("gce://whatever") is None


def test_parse_image_ref_tag():
    r = parse_image_ref("nginx:1.14")
    assert r["repo"] == "nginx" and r["tag"] == "1.14" and r["digest"] == ""


def test_parse_image_ref_registry_port_and_digest():
    r = parse_image_ref("registry.local:5000/app/api:v2@sha256:deadbeef")
    assert r["repo"] == "registry.local:5000/app/api"
    assert r["tag"] == "v2"
    assert r["digest"] == "sha256:deadbeef"


def test_parse_image_ref_defaults_latest():
    assert parse_image_ref("python")["tag"] == "latest"


def test_parse_trivy_json():
    data = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-1", "Severity": "CRITICAL",
                     "PkgName": "openssl", "InstalledVersion": "1.0", "FixedVersion": "1.1",
                     "Title": "buffer overflow"},
                    {"VulnerabilityID": "CVE-2021-2", "Severity": "high",
                     "PkgName": "zlib", "InstalledVersion": "1.2"},
                    {"VulnerabilityID": "CVE-2021-1", "Severity": "CRITICAL",
                     "PkgName": "openssl"},  # duplicada
                ]
            }
        ]
    }
    nodes, edges, counts = parse_trivy_json("img:1", data)
    cve_ids = {n.id for n in nodes}
    assert cve_ids == {"CVE-2021-1", "CVE-2021-2"}  # dedup de nós
    assert len(edges) == 3  # arestas mantêm todas as ocorrências
    assert counts["CRITICAL"] == 2
    assert counts["HIGH"] == 1
    assert all(e.source == "img:1" for e in edges)


def test_summarize_and_worst():
    counts = {"CRITICAL": 2, "HIGH": 5, "LOW": 1}
    s = summarize_counts(counts)
    assert s == {"cve_count": 8, "critical_count": 2, "high_count": 5}
    assert worst_severity(counts) == "CRITICAL"
    assert worst_severity({}) == "NONE"
