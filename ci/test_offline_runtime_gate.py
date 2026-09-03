import unittest

from ci import offline_runtime_gate


class OfflineRuntimeGateTests(unittest.TestCase):
    def test_finds_forbidden_resolved_packages_only(self) -> None:
        metadata = {
            "packages": [
                {"id": "local", "name": "aura-runtime"},
                {"id": "http-id", "name": "http"},
                {"id": "unused", "name": "ureq"},
            ],
            "resolve": {"nodes": [{"id": "local"}, {"id": "http-id"}]},
        }

        self.assertEqual(offline_runtime_gate.forbidden_packages(metadata), ["http"])

    def test_extended_http_and_tls_packages_are_rejected(self) -> None:
        metadata = {
            "packages": [
                {"id": "local", "name": "aura-runtime"},
                {"id": "body", "name": "http-body-util"},
                {"id": "tls", "name": "hyper-rustls"},
            ],
            "resolve": {
                "nodes": [{"id": "local"}, {"id": "body"}, {"id": "tls"}]
            },
        }

        self.assertEqual(
            offline_runtime_gate.forbidden_packages(metadata),
            ["http-body-util", "hyper-rustls"],
        )

    def test_socket_and_client_apis_are_rejected(self) -> None:
        for source in (
            "use std::net::TcpStream;",
            "let client = reqwest::Client::new();",
            "let socket = tokio::net::TcpSocket::new_v4();",
        ):
            self.assertTrue(offline_runtime_gate.forbidden_source_matches(source))

    def test_offline_ip_address_parsing_is_allowed(self) -> None:
        source = "use std::net::{Ipv4Addr, Ipv6Addr};"

        self.assertEqual(offline_runtime_gate.forbidden_source_matches(source), [])


if __name__ == "__main__":
    unittest.main()
