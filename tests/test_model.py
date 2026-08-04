from rastro.model import CONFIDENCE_ORDER, Artifact, Finding, Host, Port, Service


def test_confidence_is_ordered_guess_lowest_confirmed_highest():
    assert CONFIDENCE_ORDER["guess"] < CONFIDENCE_ORDER["banner"]
    assert CONFIDENCE_ORDER["banner"] < CONFIDENCE_ORDER["confirmed"]


def test_host_roundtrips_through_dict():
    host = Host(target="10.0.0.1", resolved_ip="10.0.0.1")
    host.ports.append(
        Port(
            number=445,
            service=Service(name="smb", product="Samba", confidence="confirmed"),
            artifacts=[
                Artifact(
                    tool="nmap",
                    command="nmap -p445 10.0.0.1",
                    exit_code=0,
                    duration_s=1.5,
                    stdout_path="raw/nmap-445.txt",
                )
            ],
        )
    )
    host.findings.append(
        Finding(
            id="smb-signing-disabled",
            title="SMB signing not required",
            interest="high",
            evidence="message_signing: disabled",
            source_artifact="raw/nmap-445.txt",
        )
    )
    host.buckets["ad"] = [88, 389]

    restored = Host.from_dict(host.to_dict())

    assert restored.to_dict() == host.to_dict()
    assert restored.ports[0].service.confidence == "confirmed"
    assert restored.findings[0].source_artifact == "raw/nmap-445.txt"


def test_ports_default_is_not_shared_between_hosts():
    a, b = Host(target="a"), Host(target="b")
    a.ports.append(Port(number=80))
    assert b.ports == []
