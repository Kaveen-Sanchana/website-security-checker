import socket

import domain_intelligence


def test_domain_suffix_identifies_country_code_domains():
    assert domain_intelligence.get_domain_suffix_info("example.lk") == {
        "top_level_domain": ".lk",
        "country_code_domain": "LK",
    }


def test_domain_suffix_leaves_generic_tlds_without_country_code():
    assert domain_intelligence.get_domain_suffix_info("example.com") == {
        "top_level_domain": ".com",
        "country_code_domain": None,
    }


def test_first_archived_date_uses_earliest_html_capture(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return [
                ["timestamp", "statuscode", "mimetype"],
                ["20010423091500", "200", "text/html"],
            ]

    monkeypatch.setattr(
        domain_intelligence.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    assert domain_intelligence.query_first_archived_date("example.com") == "2001-04-23"


def test_first_archived_date_is_unavailable_when_archive_has_no_capture(
    monkeypatch,
):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return [["timestamp", "statuscode", "mimetype"]]

    monkeypatch.setattr(
        domain_intelligence.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    assert domain_intelligence.query_first_archived_date("example.com") is None


def test_email_security_distinguishes_missing_records_from_dns_failures(
    monkeypatch,
):
    class Resolver:
        timeout = None
        lifetime = None

        def resolve(self, name, record_type, raise_on_no_answer=False):
            if name == "example.com":
                class Record:
                    strings = (b"v=spf1 -all",)

                class Answer:
                    rrset = True

                    def __iter__(self):
                        return iter([Record()])

                return Answer()
            return type("Answer", (), {"rrset": None})()

    monkeypatch.setattr(domain_intelligence.dns.resolver, "Resolver", Resolver)
    result = domain_intelligence.query_email_security("example.com")

    assert result["spf_status"] == "found"
    assert result["spf_records"] == ["v=spf1 -all"]
    assert result["dmarc_status"] == "not_found"
    assert result["dkim_records"] == []


def test_email_security_marks_timeout_as_unavailable(monkeypatch):
    class Resolver:
        timeout = None
        lifetime = None

        def resolve(self, *args, **kwargs):
            raise OSError("simulated resolver failure")

    monkeypatch.setattr(domain_intelligence.dns.resolver, "Resolver", Resolver)
    result = domain_intelligence.query_email_security("example.com")

    assert result["spf_status"] == "unavailable"
    assert result["dmarc_status"] == "unavailable"


def test_domain_lookup_reuses_validated_scan_ip_after_secondary_dns_failure(monkeypatch):
    def fail_dns(*_args, **_kwargs):
        raise socket.gaierror("temporary resolver failure")

    monkeypatch.setattr(domain_intelligence.socket, "getaddrinfo", fail_dns)
    monkeypatch.setattr(domain_intelligence, "query_dns", lambda _domain: {"_notes": []})
    monkeypatch.setattr(domain_intelligence, "query_email_security", lambda _domain: {})
    monkeypatch.setattr(domain_intelligence, "query_registration", lambda _domain: {"available": False})
    monkeypatch.setattr(domain_intelligence, "query_first_archived_date", lambda _domain: None)

    report = domain_intelligence.collect_domain_intelligence(
        "https://example.com", resolved_ips=["93.184.216.34", "127.0.0.1"]
    )

    assert report["public_ip_addresses"] == ["93.184.216.34"]


def test_registration_lookup_reads_country_from_registrant_entity(monkeypatch):
    class Response:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [
                            ["fn", {}, "text", "Example Owner"],
                            ["adr", {}, "text", ["", "", "", "", "", "", "GB"]],
                        ]],
                    },
                ],
            }

    monkeypatch.setattr(domain_intelligence.requests, "get", lambda *_args, **_kwargs: Response())
    result = domain_intelligence.query_registration("example.com")

    assert result["registrant"] == "Example Owner"
    assert result["registrant_country"] == "GB"
