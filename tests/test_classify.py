from rastro.model import Artifact, Context, Host, Port, Service
from rastro.stages.classify import bucket_for, run


def test_winrm_is_not_classified_as_web():
    # 5985 speaks HTTP but is a management endpoint — dir brute-forcing it is wrong.
    assert bucket_for(5985, "Microsoft HTTPAPI httpd 2.0") == "winrm"


def test_msrpc_is_not_classified_as_web():
    assert bucket_for(593, "ncacn_http") == "rpc"


def test_kerberos_and_ldap_are_ad():
    assert bucket_for(88, "kerberos-sec") == "ad"
    assert bucket_for(389, "Microsoft Windows Active Directory LDAP") == "ad"


def test_plain_http_is_web():
    assert bucket_for(8080, "Apache Tomcat") == "web"
    assert bucket_for(443, "ssl/http nginx") == "web"


def test_unknown_is_other():
    assert bucket_for(64999, "") == "other"


def test_run_populates_buckets(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=80, service=Service(name="http", product="nginx")),
        Port(number=88, service=Service(name="kerberos")),
        Port(number=5985, service=Service(name="winrm", product="Microsoft HTTPAPI")),
    ]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert result.buckets["web"] == [80]
    assert result.buckets["ad"] == [88]
    assert result.buckets["winrm"] == [5985]


def test_findings_reference_their_source_artifact(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "445-smb.txt").write_text("message_signing: disabled (dangerous)")
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(
            number=445,
            service=Service(name="smb"),
            artifacts=[Artifact(tool="nmap", command="nmap", stdout_path="raw/445-smb.txt")],
        )
    ]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    signing = [f for f in result.findings if f.id == "smb-signing-disabled"]
    assert signing and signing[0].source_artifact == "raw/445-smb.txt"


def test_no_findings_invented_without_evidence(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445, service=Service(name="smb"))]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert result.findings == []


def test_signature_does_not_fire_on_an_unrelated_service(tmp_path):
    # An FTP artifact containing MySQL-ish words must not yield a MySQL finding.
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "21-ftp.txt").write_text("root account has empty password\n")
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=21, service=Service(name="ftp"),
             artifacts=[Artifact(tool="nmap", command="nmap", stdout_path="raw/21-ftp.txt")])
    ]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert [f.id for f in result.findings] == []


def test_identical_finding_from_two_artifacts_is_reported_once(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    body = "Message signing enabled but not required\n"
    (raw / "identify.txt").write_text(body)
    (raw / "445-smb.txt").write_text(body)
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=445, service=Service(name="smb"),
             artifacts=[Artifact(tool="nmap", command="a", stdout_path="raw/445-smb.txt")])
    ]
    host.artifacts = [Artifact(tool="nmap", command="b", stdout_path="raw/identify.txt")]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert [f.id for f in result.findings] == ["smb-signing-disabled"]


def test_modern_smb2_signing_phrasing_is_detected(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "445.txt").write_text("Message signing enabled but not required\n")
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=445, service=Service(name="smb"),
             artifacts=[Artifact(tool="nmap", command="a", stdout_path="raw/445.txt")])
    ]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert [f.id for f in result.findings] == ["smb-signing-disabled"]
    assert result.findings[0].port == 445


def test_unreadable_artifact_path_does_not_raise(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "adir").mkdir()          # a directory: exists() is True, read_text raises
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=445, service=Service(name="smb"),
             artifacts=[Artifact(tool="nmap", command="a", stdout_path="raw/adir")])
    ]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert result.findings == []


def test_bucket_keys_are_sorted(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=5985, service=Service(name="winrm")),
        Port(number=80, service=Service(name="http")),
        Port(number=88, service=Service(name="kerberos")),
    ]
    result = run(host, Context(target="10.0.0.5", output_dir=tmp_path))
    assert list(result.buckets) == sorted(result.buckets)
