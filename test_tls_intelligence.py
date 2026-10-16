import socket

import tls_intelligence


def test_tls_connects_to_validated_public_ip_and_keeps_hostname_for_sni(monkeypatch):
    public_record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    monkeypatch.setattr(tls_intelligence.socket, "getaddrinfo", lambda *_args, **_kwargs: [public_record])
    destinations = []

    class FakeTlsSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getpeercert(self):
            return {
                "subject": ((('commonName', 'example.com'),),),
                "issuer": ((('commonName', 'Example CA'),),),
                "notBefore": "Jan  1 00:00:00 2025 GMT",
                "notAfter": "Jan  1 00:00:00 2030 GMT",
                "subjectAltName": (("DNS", "example.com"),),
                "version": 3,
                "serialNumber": "01",
            }

        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    class FakeContext:
        def wrap_socket(self, raw_socket, server_hostname):
            assert server_hostname == "example.com"
            return FakeTlsSocket()

    def fake_create_connection(address, timeout):
        destinations.append(address)
        return FakeTlsSocket()

    monkeypatch.setattr(tls_intelligence.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(tls_intelligence.ssl, "create_default_context", FakeContext)

    result = tls_intelligence.inspect_tls_certificate("https://example.com")

    assert destinations == [("93.184.216.34", 443)]
    assert result["certificate_valid"] is True
    assert result["tls_version"] == "TLSv1.3"
