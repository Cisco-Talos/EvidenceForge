# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for the spillage event type: model, templated data, safety,
per-event synthesis, carrier rendering, and machine-readable ground truth."""

import hashlib
import re
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import SecretFamiliesConfig
from evidenceforge.config.secret_families import (
    allowlisted_domains,
    family_names,
    get_family,
    load_secret_families,
    poison_markers,
    vendor_fakes,
)
from evidenceforge.generation import spillage as sp
from evidenceforge.generation.ground_truth import GroundTruthGenerator, _redact_secret
from evidenceforge.models.scenario import SpillageEventSpec, StorylineEvent

# --- Model ---------------------------------------------------------------------


class TestSpillageModel:
    def test_family_only_is_valid(self):
        spec = SpillageEventSpec(surface="shell_history", family="aws_iam")
        assert spec.type == "spillage" and spec.family == "aws_iam" and spec.value is None

    def test_value_only_is_valid(self):
        spec = SpillageEventSpec(surface="syslog_message", value="EvidenceForgeFake_T")
        assert spec.value == "EvidenceForgeFake_T" and spec.family is None

    def test_both_rejected(self):
        with pytest.raises(ValidationError, match="exactly one"):
            SpillageEventSpec(surface="shell_history", family="aws_iam", value="x")

    def test_neither_rejected(self):
        with pytest.raises(ValidationError, match="exactly one"):
            SpillageEventSpec(surface="shell_history")

    @pytest.mark.parametrize(
        "surface",
        [
            "shell_history",
            "process_command_line",
            "syslog_message",
            "http_request_url",
            "http_referrer",
        ],
    )
    def test_all_v1_surfaces_accepted(self, surface):
        assert SpillageEventSpec(surface=surface, family="aws_iam").surface == surface

    @pytest.mark.parametrize("bad", ["proxy_header", "sysmon_cmdline", "windows_4688", ""])
    def test_emitter_specific_surface_rejected(self, bad):
        with pytest.raises(ValidationError):
            SpillageEventSpec(surface=bad, family="aws_iam")

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            SpillageEventSpec(surface="shell_history", family="aws_iam", carrier="x")

    def test_routes_through_discriminated_union(self):
        event = StorylineEvent(
            id="s1",
            time="+1h",
            actor="nina",
            system="APP-SRV-01",
            activity="leak",
            events=[{"type": "spillage", "surface": "process_command_line", "family": "db_uri"}],
        )
        assert isinstance(event.events[0], SpillageEventSpec)


# --- Templated data + schema ---------------------------------------------------


class TestSecretFamiliesData:
    def test_curated_family_set_present(self):
        names = family_names()
        assert {
            "aws_iam",
            "github_pat",
            "db_uri",
            "slack_token",
            "jwt",
            "password_generic",
        } <= names
        assert len(names) >= 10  # quantity: a richer curated set

    def test_value_templates_expand_to_safe_regex_matching_values(self):
        for fam in load_secret_families()["families"]:
            rx = re.compile(fam["regex"])
            for i in range(6):
                value = sp.synthesize_value(fam["name"], f"spill:e{i}:shell_history:{fam['name']}")
                assert rx.search(value), f"{fam['name']}: {value!r} !~ {fam['regex']}"
                sp.check_spillage_safety(value, family=fam["name"])  # must not raise

    def test_values_vary_per_event(self):
        for name in family_names():
            values = {
                sp.synthesize_value(name, f"spill:e{i}:shell_history:{name}") for i in range(8)
            }
            assert len(values) >= 6, f"{name} produced low variety: {values}"

    def test_accessors(self):
        assert "EvidenceForgeFake" in poison_markers()
        assert "AKIAIOSFODNN7EXAMPLE" in vendor_fakes()
        assert "example.com" in allowlisted_domains()
        assert get_family("aws_iam")["value_template"]
        assert get_family("does_not_exist") is None

    def test_schema_validates_bundled_config(self):
        SecretFamiliesConfig(**load_secret_families())

    def test_process_command_line_carriers_are_local_only(self):
        # A process_command_line spill is a LIVE, in-window EDR process record, so
        # its carrier must not imply an outbound connection the engine doesn't model
        # (DavidJBianco PR #289 item 8c). Network-tool leaks belong on shell_history
        # (a history-file artifact) or the correlated http_* surfaces. This guards
        # every family carrier + the generic fallbacks, Linux and Windows.
        net_binaries = {
            "curl",
            "wget",
            "psql",
            "mysql",
            "mongo",
            "mongosh",
            "nc",
            "ncat",
            "netcat",
            "telnet",
            "ssh",
            "scp",
            "sftp",
            "ftp",
            "dig",
            "nslookup",
        }
        net_substrings = [
            "://",
            "fetch origin",
            "git clone",
            "git pull",
            "git push",
            "ls-remote",
            "aws sts",
            "get-caller-identity",
            "invoke-restmethod",
            "invoke-webrequest",
            "s3 ls",
            "s3api",
        ]
        carriers: list[str] = []
        for fam in load_secret_families()["families"]:
            for key in ("process_command_line", "process_command_line_windows"):
                carriers.extend((fam.get("carriers") or {}).get(key, []))
        carriers.extend(sp._GENERIC_CARRIERS.get("process_command_line", ()))
        carriers.extend(sp._GENERIC_CARRIERS_WINDOWS.get("process_command_line", ()))
        assert carriers  # sanity: we actually checked some
        for c in carriers:
            binary = (
                c.split()[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower().removesuffix(".exe")
            )
            assert binary not in net_binaries, f"network binary in process carrier: {c!r}"
            low = c.lower()
            for s in net_substrings:
                assert s not in low, f"network indicator {s!r} in process carrier: {c!r}"

    def test_schema_rejects_carrier_without_value_placeholder(self):
        with pytest.raises(ValidationError, match=r"must contain \{value\}"):
            SecretFamiliesConfig(
                families=[
                    {
                        "name": "x",
                        "regex": ".+",
                        "value_template": "EvidenceForgeFake{alnum:6}",
                        "carriers": {"shell_history": ["export X=nope"]},
                    }
                ],
                poison_markers=["EvidenceForgeFake"],
            )

    def test_schema_rejects_family_without_template_or_examples(self):
        with pytest.raises(ValidationError, match="value_template or examples"):
            SecretFamiliesConfig(
                families=[{"name": "x", "regex": ".+"}],
                poison_markers=["EvidenceForgeFake"],
            )

    def test_schema_rejects_duplicate_names(self):
        with pytest.raises(ValidationError, match="duplicate"):
            SecretFamiliesConfig(
                families=[
                    {"name": "d", "regex": ".+", "value_template": "EvidenceForgeFake1"},
                    {"name": "d", "regex": ".+", "value_template": "EvidenceForgeFake2"},
                ],
                poison_markers=["EvidenceForgeFake"],
            )

    _GOOD_FAMILY = {
        "name": "x",
        "regex": "AKIA[0-9A-Z]{16}",
        "value_template": "AKIA{upper:9}EXAMPLE",
    }

    @pytest.mark.parametrize(
        "overrides,match",
        [
            ({"poison_markers": [""]}, "too short"),  # empty marker marks any value synthetic
            (
                {"poison_markers": ["EvidenceForgeFake"], "vendor_fakes": ["AKIA"]},
                "too short",
            ),  # 4-char fake vouches for real AWS keys
            (
                {
                    "poison_markers": ["EvidenceForgeFake"],
                    "network_allowlist": {"domains": ["com"]},
                },
                "reserved",
            ),  # bare TLD allowlists all of *.com
        ],
    )
    def test_schema_rejects_degenerate_marker_fake_domain(self, overrides, match):
        cfg = {"families": [self._GOOD_FAMILY], **overrides}
        with pytest.raises(ValidationError, match=match):
            SecretFamiliesConfig(**cfg)


# --- Safety guardrails ---------------------------------------------------------


class TestSafety:
    @pytest.mark.parametrize(
        "value,family",
        [
            ("AKIAIOSFODNN7EXAMPLE", "aws_iam"),  # vendor fake + marker
            ("sk_test_4eC39HqLyjWDarjtT1zdp7dc", None),  # vendor fake, no marker
            ("Bearer EvidenceForgeFake_TOKEN", None),  # marker
            (
                "postgresql://u:EvidenceForgeFake_pw@db.example.com/app",
                "db_uri",
            ),  # allowlisted host
            ("postgresql://u:EvidenceForgeFake_pw@192.0.2.5/app", "db_uri"),  # RFC5737 host
            ("EvidenceForgeFake this is a normal sentence with twelvecharword", None),  # multi-word
        ],
    )
    def test_safe_values_accepted(self, value, family):
        sp.check_spillage_safety(value, family=family)

    @pytest.mark.parametrize(
        "value,family,match",
        [
            ("AKIAREALLOOKINGKEY123456", None, "poison marker"),
            ("EvidenceForgeFake\ninjected", None, "single-line"),
            ("EvidenceForgeFake_not_aws", "aws_iam", "does not match family"),
            ("", None, "non-empty"),
            ("EvidenceForgeFake_v", "no_such_family", "unknown spillage family"),
        ],
    )
    def test_unsafe_values_rejected(self, value, family, match):
        with pytest.raises(sp.SpillageSafetyError, match=match):
            sp.check_spillage_safety(value, family=family)

    @pytest.mark.parametrize(
        "value",
        [
            "AKIA1234567890ABCDEF EXAMPLE",  # real-shaped key + appended marker
            "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xYz0 DO_NOT_USE",  # 36-char PAT body + marker
        ],
    )
    def test_per_token_blocks_appended_marker(self, value):
        with pytest.raises(sp.SpillageSafetyError, match="credential-shaped token"):
            sp.check_spillage_safety(value)

    @pytest.mark.parametrize(
        "value", ["EvidenceForgeFake reach evil.attacker.com", "EvidenceForgeFake exfil to evil.io"]
    )
    def test_bare_real_host_rejected(self, value):
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    def test_public_ip_rejected_but_jwt_is_not_a_host(self):
        with pytest.raises(sp.SpillageSafetyError):
            sp.check_spillage_safety("EvidenceForgeFake exfil 8.8.8.8")
        # A JWT's dotted base64 must not be misread as a hostname.
        jwt = "eyJhbGciOiJIUzI1NiJ9.abcEvidenceForgeFake.F5BhvdzTRdeQqNAdHJSGs4suaaoj3vKC"
        assert sp._extract_hosts(jwt) == []

    @pytest.mark.parametrize(
        "value",
        [
            "token EvidenceForgeFake_X from user@8.8.8.8",  # real IP hidden behind userinfo
            "EvidenceForgeFake_Y admin@93.184.216.34/db",  # real IP in user@host with a path
            "EvidenceForgeFake_Z x@allowed.example.com@8.8.8.8",  # double-@ smuggling a real IP
            "EvidenceForgeFake_W user@[2606:2800:220:1:248:1893:25c8:1946]",  # real IPv6 via userinfo
        ],
    )
    def test_real_host_smuggled_via_userinfo_rejected(self, value):
        # A real host (esp. an IP) must not slip past the allowlist by hiding behind
        # an "@" — the email-form regex used to require an alpha TLD and missed IPs.
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    @pytest.mark.parametrize(
        "value",
        ["EvidenceForgeFake_OK svc@192.0.2.5", "EvidenceForgeFake_OK2 svc@10.0.0.5"],
    )
    def test_allowlisted_host_via_userinfo_accepted(self, value):
        sp.check_spillage_safety(value)  # RFC 5737 / RFC 1918 hosts via userinfo stay allowed

    @pytest.mark.parametrize(
        "value",
        [
            "EXAMPLE curl http://134744072/upload",  # dotless-decimal 8.8.8.8 in a URL
            "EXAMPLE http://0x08080808/x",  # hex-encoded 8.8.8.8 in a URL
            "EXAMPLE http://16843009/x",  # dotless-decimal 1.1.1.1
            "EXAMPLE curl http://010.010.010.010/",  # octal dotted-quad 8.8.8.8
            "EXAMPLE curl http://0x8.0x8.0x8.0x8/",  # hex dotted-quad 8.8.8.8
            "postgresql://a:EvidenceForgeFakePwd@134744072/db",  # obfuscated host in a db_uri
        ],
    )
    def test_obfuscated_ip_host_rejected(self, value):
        # A real public IP a resolver accepts (inet_aton) must be caught even when
        # encoded so Python's ipaddress rejects it.
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    @pytest.mark.parametrize(
        "value",
        [
            "curl https://president.xn--p1ai/ EXAMPLE",  # punycode / IDN TLD
            "curl https://telegram.md EXAMPLE",  # real ccTLD colliding with a file-ext
            "curl https://pool.key EXAMPLE",  # real gTLD colliding with a file-ext
        ],
    )
    def test_real_tld_host_rejected(self, value):
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    def test_file_extension_is_not_a_host_outside_url(self):
        # In a bare command (not a URL host position) deploy.sh is a filename.
        sp.check_spillage_safety("bash deploy.sh EvidenceForgeFake")  # must not raise
        assert sp._extract_hosts("bash deploy.sh") == []

    @pytest.mark.parametrize(
        "value",
        [
            "leaked президент.рф EXAMPLE",  # bare IDN host (no scheme)
            "user@президент.рф EXAMPLE",  # IDN host after userinfo @ (no scheme)
            "token=EXAMPLE leaked via paуpal.com/login",  # Cyrillic homoglyph of paypal.com
            "api.раздел.com leaked EXAMPLE",  # non-ASCII label, ASCII dots/TLD
            "example.рф leaked EXAMPLE",  # non-ASCII TLD
            "host ８.８.８.８ leaked EXAMPLE",  # fullwidth-digit IPv4 of 8.8.8.8
        ],
    )
    def test_non_ascii_idn_host_without_scheme_is_rejected(self, value):
        # A real resolver IDNA-encodes these to a real registrable domain, so the
        # value is NOT provably synthetic — must be rejected even with no scheme and
        # in a bare or userinfo-@ position (same class as the unicode-dot bypass).
        assert sp._extract_hosts(value)  # the IDN host is extracted, not silently dropped
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    def test_non_ascii_subdomain_of_allowlisted_host_is_accepted(self):
        # A non-ASCII label UNDER an allowlisted (reserved) domain IDNA-encodes to a
        # subdomain still under that reserved domain — safe, must not false-reject.
        sp.check_spillage_safety("EvidenceForgeFake naïve.api.example.com")  # must not raise
        # and a bare non-ASCII word (no dot) is not a host at all
        sp.check_spillage_safety("EvidenceForgeFake café token")  # must not raise

    @pytest.mark.parametrize(
        "value",
        [
            "EvidenceForgeFake https://evil-real-c2.com?x=1",  # query string after host
            "EvidenceForgeFake https://evil-real-c2.com#frag",  # fragment after host
            "EvidenceForgeFake https://evil-real-c2.com?a=b#c",  # both
        ],
    )
    def test_url_host_before_query_or_fragment_is_checked(self, value):
        # The netloc ends at "?"/"#"; the host must still be extracted and checked,
        # not swallowed into "host?x=1" (which would dodge the allowlist).
        assert sp._extract_hosts(value) == ["evil-real-c2.com"]
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    def test_allowlisted_url_host_with_query_string_accepted(self):
        sp.check_spillage_safety("EvidenceForgeFake https://api.example.com?ok=1")  # must not raise

    @pytest.mark.parametrize(
        "value",
        [
            "EvidenceForgeFake https://evil-real-c2.com\\loot",  # backslash (WHATWG = '/')
            "EvidenceForgeFake //evil-real-c2.com/loot",  # scheme-relative URL
            "EvidenceForgeFake https://evil-real-c2．com/x",  # U+FF0E fullwidth dot
            "EvidenceForgeFake https://evil-real-c2。com/x",  # U+3002 ideographic dot
            "EvidenceForgeFake https://evil-real-c2｡com/x",  # U+FF61 halfwidth dot
            "EvidenceForgeFake https://%65vil-real-c2.com/x",  # percent-encoded 'e'
        ],
    )
    def test_alternate_url_encodings_do_not_dodge_the_host_allowlist(self, value):
        # A real client/browser would resolve all of these to evil-real-c2.com; the
        # guardrail normalizes the encoding first so the host is still allowlisted.
        assert sp._extract_hosts(value) == ["evil-real-c2.com"]
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    def test_ipv6_zone_id_userinfo_host_is_checked(self):
        # A zone-id ("%eth0") must not make the bracketed IPv6 host unparseable and
        # thus skip the allowlist; the zone is stripped and the public IP rejected.
        value = "EvidenceForgeFake user@[2606:4700:4700::1111%eth0]/loot"
        assert sp._extract_hosts(value) == ["2606:4700:4700::1111"]
        with pytest.raises(sp.SpillageSafetyError, match="non-allowlisted host"):
            sp.check_spillage_safety(value)

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil-real-c2.com/p",
            "https://evil-real-c2.com?q=1",
            "https://evil-real-c2.com#f",
            "https://evil-real-c2.com\\p",
            "//evil-real-c2.com/p",
            "https://user:pw@evil-real-c2.com/p",
            "https://evil-real-c2.com:8443/p",
        ],
    )
    def test_extract_hosts_agrees_with_urlsplit_hostname(self, url):
        # Differential guard: for any scheme/scheme-relative URL, our hand-rolled
        # extractor must find the same host a real URL parser would. Backslash is
        # normalized to '/' (WHATWG) before comparison, matching browser behavior.
        import urllib.parse

        expected = urllib.parse.urlsplit(url.replace("\\", "/")).hostname
        assert expected in sp._extract_hosts("EvidenceForgeFake " + url)

    @pytest.mark.parametrize("sep", ["\x0b", "\x0c", "\x85", "\u2028", "\u2029", "\x1c"])
    def test_line_separator_chars_are_rejected(self, sep):
        # Any character str.splitlines() treats as a line boundary could split a
        # credential across log lines, so it is rejected (not just CR/LF).
        assert (sep + "x").splitlines() == ["", "x"]  # confirms it IS a line boundary
        with pytest.raises(sp.SpillageSafetyError, match="single-line"):
            sp.check_spillage_safety(f"export TOKEN=EvidenceForgeFake{sep}INJECTED")

    @pytest.mark.parametrize("ctrl", ["\x00", "\x1b", "\x07", "\x7f", "\x9b"])
    def test_non_line_control_chars_are_rejected(self, ctrl):
        # NUL/ESC/BEL/DEL/C1 don't split lines but would survive RAW into a
        # shell/process command line (shlex.quote passes control bytes through),
        # injecting a terminal-escape sequence or confusing a parser. Rejected at
        # the value level so the "not a log-injection primitive" guarantee holds.
        with pytest.raises(sp.SpillageSafetyError, match="control character"):
            sp.check_spillage_safety(f"export TOKEN=EvidenceForgeFake{ctrl}TAIL")

    def test_tab_is_the_one_allowed_control(self):
        sp.check_spillage_safety("app: secret=EvidenceForgeFake\twith-tab")  # must not raise

    def test_mixed_case_letters_only_high_entropy_secret_is_rejected(self):
        # A long mixed-case letters-only token (no digit) is still real-key-shaped;
        # it must carry an IN-TOKEN marker, not just a detached one. Closes the gap
        # where _looks_high_entropy required both a letter AND a digit.
        with pytest.raises(sp.SpillageSafetyError, match="credential-shaped token"):
            sp.check_spillage_safety(
                "key=QwErTyUiOpAsDfGhJkLzXcVbNmQwErTy EvidenceForgeFake", family=None
            )
        # A single-class lowercase word of the same length is still spared.
        sp.check_spillage_safety("note=correcthorsebatterystaplexyz EvidenceForgeFake", family=None)

    @pytest.mark.parametrize(
        "value",
        [
            "sk-proj-Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2Mm3 EXAMPLE",  # OpenAI-shaped key
            "EXAMPLE 1f8b7e3c9a2d4f6b0c5e7a1d3f9b2e4c6a8d0f1e",  # 40-hex API key
            "SG.aBcDeFgHiJkLmNoPqRsT.uVwXyZ0123456789aBcDeFgHiJkLmNoPq # DO_NOT_USE",  # SendGrid-shaped
        ],
    )
    def test_unstructured_real_credential_needs_in_token_marker(self, value):
        # A long, random-looking secret not covered by a structured family must
        # still carry an IN-TOKEN marker; a detached marker does not vouch for it.
        with pytest.raises(sp.SpillageSafetyError, match="credential-shaped token"):
            sp.check_spillage_safety(value)

    def test_high_entropy_sweep_spares_hostnames_and_words(self):
        # The generic high-entropy sweep must not false-flag a db_uri's host or a
        # marked multi-word value (regression for widening the per-token sweep).
        sp.check_spillage_safety(
            "postgresql://u:EvidenceForgeFake_pw@records3.example.com/payments"
        )
        sp.check_spillage_safety("EvidenceForgeFake this is a perfectly ordinary sentence here")

    def test_short_low_entropy_secret_with_detached_marker_is_residual_risk(self):
        # The generic high-entropy sweep now requires a long, random-looking secret
        # to carry an IN-TOKEN marker (see test_unstructured_real_credential_...).
        # What remains accepted with only a *detached* marker is a SHORT or
        # low-entropy secret below the sweep threshold (e.g. a weak password) — a
        # documented residual risk: such a token cannot be told apart from an
        # ordinary word. A high-entropy generic password is NOT exempt.
        sp.check_spillage_safety("hunter2 EvidenceForgeFake_DO_NOT_USE", family=None)
        with pytest.raises(sp.SpillageSafetyError, match="credential-shaped token"):
            sp.check_spillage_safety("P4ssw0rd-Tr0ub4dor-2024 EvidenceForgeFake", family=None)

    def test_docstring_lists_real_guardrails(self):
        doc = SpillageEventSpec.__doc__ or ""
        assert "entropy ceiling" not in doc
        assert "single-line" in doc


# --- Documentation sync (drift guard) ------------------------------------------


class TestDocsSync:
    """Cheap grep gate: keep operational skill docs and the reference doc in sync
    with the spillage feature, so a new artifact / scope change can't slip through
    undocumented (the recurring doc-drift class behind several review items)."""

    _ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]

    def _read(self, rel: str) -> str:
        return (self._ROOT / rel).read_text(encoding="utf-8")

    def test_skill_docs_reference_ground_truth_json_and_config(self):
        assert "GROUND_TRUTH.json" in self._read("commands/eforge/generate.md")
        assert "GROUND_TRUTH.json" in self._read("commands/eforge/evaluate.md")
        assert "secret_families.yaml" in self._read("commands/eforge/config.md")

    def test_validate_skill_documents_spillage_errors(self):
        # AGENTS.md convention: validate.md must carry error-handling guidance for
        # new event types. Spillage has surface/family/value-specific errors.
        validate = self._read("commands/eforge/validate.md")
        assert "spillage" in validate.lower()
        assert "web_server" in validate  # the http_* surface error
        assert "family" in validate and "value" in validate  # mutual-exclusivity error

    def test_reference_doc_does_not_overclaim_process_command_line_network(self):
        # process_command_line is a standalone process record in v1; the docs must
        # not claim it produces correlated "command-owned network" (the code does
        # not). Allow the word only in an explicit NOT-emitted disclaimer.
        spill = self._read("docs/reference/spillage.md")
        for line in spill.splitlines():
            if "command-owned network" in line:
                assert "not" in line.lower(), f"overclaim re-introduced: {line.strip()!r}"


class TestSynthesisRendering:
    def test_synthesis_deterministic_per_seed(self):
        k = "spill:e1:shell_history:github_pat"
        assert sp.synthesize_value("github_pat", k) == sp.synthesize_value("github_pat", k)

    def test_resolve_value_literal_path(self):
        value, fam = sp.resolve_value(None, "Bearer EvidenceForgeFake_T", seed_key="k")
        assert fam == "" and value == "Bearer EvidenceForgeFake_T"

    def test_resolve_value_requires_exactly_one(self):
        with pytest.raises(sp.SpillageSafetyError):
            sp.resolve_value(None, None, seed_key="k")

    @pytest.mark.parametrize("surface", ["shell_history", "process_command_line", "syslog_message"])
    def test_render_embeds_encoded_value_in_a_carrier_line(self, surface):
        value, fam = sp.resolve_value("db_uri", None, seed_key=f"spill:e:{surface}:db_uri")
        r = sp.render_for_surface(value, surface, fam, f"spill:e:{surface}:db_uri")
        line = r.command or r.syslog_message
        assert r.encoded_value in line
        assert r.expected_sources == sp.expected_sources_for_surface(surface)
        if surface == "process_command_line":
            assert r.process_name and r.process_name == line.split()[0]

    def test_carrier_choice_varies_across_events(self):
        lines = set()
        for i in range(8):
            v, f = sp.resolve_value("aws_iam", None, seed_key=f"spill:e{i}:shell_history:aws_iam")
            r = sp.render_for_surface(v, "shell_history", f, f"spill:e{i}:shell_history:aws_iam")
            lines.add(r.command)
        assert len(lines) >= 6  # both the value and the carrier vary

    def test_metachar_literal_is_shell_quoted(self):
        r = sp.render_for_surface("EvidenceForgeFake pw;id", "shell_history", "", "k")
        assert "'" in r.encoded_value and r.encoded_value in r.command

    @pytest.mark.parametrize("family", ["aws_iam", "github_pat", "gcp_api_key", "db_uri", "jwt"])
    def test_process_command_line_windows_renders_native_command(self, family):
        # On a Windows host the process carrier must be a cmd/PowerShell/.exe
        # command, never a Linux /usr/bin command line (would be implausible in
        # Windows 4688/eCAR). The credential still lands verbatim in the command.
        value, fam = sp.resolve_value(family, None, seed_key=f"spill:e:{family}")
        win = sp.render_for_surface(
            value, "process_command_line", fam, f"spill:e:{family}", os_category="windows"
        )
        assert "/usr/" not in win.command and "/bin/" not in win.command
        lowered = win.command.lower()
        assert ".exe" in lowered or "powershell" in lowered or "cmd.exe" in lowered
        assert win.encoded_value in win.command
        # the same family on Linux still renders a POSIX command line
        lin = sp.render_for_surface(
            value, "process_command_line", fam, f"spill:e:{family}", os_category="linux"
        )
        assert "/usr/" in lin.command or "python3" in lin.command or "login(" in lin.command

    def test_syslog_escapes_control_chars(self):
        assert "\\x09" in sp._escape_controls("EvidenceForgeFake\tx")

    def test_unsupported_surface_raises(self):
        with pytest.raises(sp.SpillageSafetyError, match="unsupported"):
            sp.render_for_surface("EvidenceForgeFake", "http_user_agent", "", "k")

    def test_http_surfaces_map_to_web_access_and_are_cross_os(self):
        assert sp.SURFACE_FORMATS["http_request_url"] == "web_access"
        assert sp.SURFACE_FORMATS["http_referrer"] == "web_access"
        assert sp.HTTP_SURFACES == {"http_request_url", "http_referrer"}
        assert not (sp.HTTP_SURFACES & sp.LINUX_ONLY_SURFACES)

    def test_url_surface_percent_encodes_metacharacters(self):
        # A db_uri (with :// and @) must survive as one percent-encoded query
        # component rather than corrupting the request line.
        value, fam = sp.resolve_value("db_uri", None, seed_key="k:http_request_url:db_uri")
        r = sp.render_for_surface(value, "http_request_url", fam, "k:http_request_url:db_uri")
        assert "://" not in r.encoded_value and "@" not in r.encoded_value
        assert "%3A%2F%2F" in r.encoded_value  # :// percent-encoded
        assert r.encoded_value in (r.http_uri or "")
        assert r.http_referrer == "" and r.command is None
        assert r.expected_sources == ("web_access",)

    def test_referrer_surface_carries_value_in_referer_with_benign_path(self):
        value, fam = sp.resolve_value("jwt", None, seed_key="k:http_referrer:jwt")
        r = sp.render_for_surface(value, "http_referrer", fam, "k:http_referrer:jwt")
        assert r.http_referrer.startswith("http") and r.encoded_value in r.http_referrer
        assert r.encoded_value not in (r.http_uri or "")  # the request path stays benign
        assert r.expected_sources == ("web_access",)

    def test_url_encoded_value_has_no_spaces_or_controls(self):
        r = sp.render_for_surface("EvidenceForgeFake a b\tc", "http_request_url", "", "k")
        assert " " not in r.encoded_value and "\t" not in r.encoded_value
        assert "EvidenceForgeFake" in r.encoded_value  # marker (alnum) survives encoding

    def test_process_command_line_renders_have_balanced_quoting(self):
        # A carrier must never wrap {value} inside its own quotes, or a value with a
        # shell metacharacter (e.g. password_generic's trailing '!', a db_uri with a
        # metachar password) renders doubled/nested quotes — a malformed-command-line
        # tell. shlex.split raises on unbalanced quoting; assert it never does, for
        # every family + literal-metachar values, and the value always survives.
        import shlex

        for fam in family_names():
            for i in range(12):
                value, rf = sp.resolve_value(fam, None, seed_key=f"q{i}:{fam}")
                r = sp.render_for_surface(value, "process_command_line", rf, f"q{i}:{fam}")
                shlex.split(r.command)  # raises ValueError on nested/unbalanced quotes
                assert r.encoded_value in r.command
        for literal in ("EvidenceForgeFake P@ss w0rd&x|y", "EvidenceForgeFake-x!"):
            r = sp.render_for_surface(literal, "process_command_line", "", "k")
            shlex.split(r.command)
            assert r.encoded_value in r.command


# --- Machine-readable ground truth ---------------------------------------------


def _gt(events, scenarios_dir):
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils.files import load_yaml

    scenario = Scenario(**load_yaml(scenarios_dir / "minimal.yaml"))
    return GroundTruthGenerator(scenario=scenario, malicious_events=events)


def _spill_event(**over):
    base = {
        "time": datetime(2024, 3, 18, 14, 20, 7, tzinfo=UTC),
        "actor": "nina",
        "system": "APP-SRV-01",
        "activity": "leak",
        "type": "spillage",
        "storyline_cluster_id": "spill-1",
        "surface": "shell_history",
        "family": "aws_iam",
        "value": "AKIA8QCYHI724EXAMPLE",
        "rendered_value": "AKIA8QCYHI724EXAMPLE",
        "expected_sources": ["bash_history"],
    }
    base.update(over)
    return base


class TestGroundTruthJson:
    def test_record_shape_hash_and_rendered(self, scenarios_dir):
        document = _gt([_spill_event(rendered_value="'q v'")], scenarios_dir).build_document()
        rec = document.model_dump(mode="python", exclude_none=True)["events"][0]
        assert document.schema_version == 1 and rec["kind"] == "spillage"
        assert rec["storyline_id"] == "spill-1" and rec["record_id"] == "spill-1#0"
        assert rec["ground_truth_section"] == "storyline" and rec["emitted"] is True
        assert (
            rec["attributes"]["value_sha256"] == hashlib.sha256(b"AKIA8QCYHI724EXAMPLE").hexdigest()
        )
        assert rec["attributes"]["rendered_value"] == "'q v'"
        assert rec["attributes"]["rendered_sha256"] == hashlib.sha256(b"'q v'").hexdigest()

    def test_literal_has_null_family_and_record_ids_unique(self, scenarios_dir):
        recs = (
            _gt(
                [
                    _spill_event(
                        family=None, value="Bearer EvidenceForgeFake_T", storyline_cluster_id="d"
                    ),
                    _spill_event(storyline_cluster_id="d", surface="syslog_message"),
                ],
                scenarios_dir,
            )
            .build_document()
            .model_dump(mode="python", exclude_none=True)["events"]
        )
        assert "family" not in recs[0]["attributes"]
        assert len({r["record_id"] for r in recs}) == 2

    def test_non_spillage_records_are_included_under_details(self, scenarios_dir):
        logon = {
            "time": datetime(2024, 3, 18, 14, tzinfo=UTC),
            "actor": "a",
            "system": "s",
            "activity": "logon",
            "type": "logon",
            "storyline_cluster_id": "e1",
            "source_ip": "203.0.113.10",
            "logon_type": 3,
        }
        recs = (
            _gt([logon, _spill_event()], scenarios_dir)
            .build_document()
            .model_dump(mode="python", exclude_none=True)["events"]
        )
        assert [r["kind"] for r in recs] == ["logon", "spillage"]
        assert recs[0]["attributes"]["source_ip"] == "203.0.113.10"
        assert recs[0]["ground_truth_section"] == "storyline"

    def test_md_redacts_but_keeps_hash(self, scenarios_dir):
        details = _gt([_spill_event()], scenarios_dir)._format_event_details(_spill_event())
        assert "AKIA8QCYHI724EXAMPLE" not in details
        assert hashlib.sha256(b"AKIA8QCYHI724EXAMPLE").hexdigest()[:12] in details

    def test_redact_secret_never_returns_full_value(self):
        assert "AKIA8QCYHI724EXAMPLE" not in _redact_secret("AKIA8QCYHI724EXAMPLE")


# --- Overlay merge + validate-config -------------------------------------------


@pytest.fixture
def _isolated_secret_families():
    from evidenceforge.config.secret_families import reset_secret_families_cache

    reset_secret_families_cache()
    yield
    reset_secret_families_cache()


def test_secret_families_overlay_merges(tmp_path, monkeypatch, _isolated_secret_families):
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "secret_families.yaml").write_text(
        "families:\n"
        "  - name: corp_token\n"
        "    structured: true\n"
        '    regex: "xtok-EvidenceForgeFake[A-Za-z0-9]+"\n'
        '    value_template: "xtok-EvidenceForgeFake{alnum:12}"\n'
        "    carriers:\n"
        "      shell_history:\n"
        '        - "export CORP_TOKEN={value}"\n'
        "poison_markers:\n"
        "  - CUSTOM_POISON\n"
        "network_allowlist:\n"
        "  domains:\n"
        "    - corp.example\n"
    )
    monkeypatch.chdir(tmp_path)
    from evidenceforge.config.secret_families import reset_secret_families_cache

    reset_secret_families_cache()

    assert {"corp_token", "aws_iam"} <= family_names()
    assert {"CUSTOM_POISON", "EvidenceForgeFake"} <= set(poison_markers())
    assert {"corp.example", "example.com"} <= set(allowlisted_domains())
    value = sp.synthesize_value("corp_token", "spill:e:shell_history:corp_token")
    sp.check_spillage_safety(value, family="corp_token")


def test_validate_config_rejects_broken_secret_families(monkeypatch):
    import evidenceforge.config.secret_families as sf
    from evidenceforge.cli.validate_config import ValidationResult, _validate_secret_families

    monkeypatch.setattr(
        sf,
        "load_secret_families",
        lambda: {
            "families": [
                {"name": "d", "regex": ".+", "value_template": "EvidenceForgeFake1"},
                {"name": "d", "regex": ".+", "value_template": "EvidenceForgeFake2"},
            ],
            "poison_markers": ["EvidenceForgeFake"],
        },
    )
    result = ValidationResult()
    _validate_secret_families(result)
    assert any(i.file == "secret_families.yaml" and i.severity == "ERROR" for i in result.issues)


def test_validate_config_rejects_value_template_not_matching_regex(monkeypatch):
    # A value_template that cannot satisfy the family regex must fail at
    # validate-config time, not silently pass until generation.
    import evidenceforge.config.secret_families as sf
    from evidenceforge.cli.validate_config import ValidationResult, _validate_secret_families

    monkeypatch.setattr(
        sf,
        "load_secret_families",
        lambda: {
            "families": [
                {
                    "name": "bad",
                    "structured": True,
                    "regex": "AKIA[0-9A-Z]{16}",
                    "value_template": "EvidenceForgeFake{alnum:6}",  # never matches AKIA...
                }
            ],
            "poison_markers": ["EvidenceForgeFake"],
        },
    )
    result = ValidationResult()
    _validate_secret_families(result)
    assert any("value_template" in i.message for i in result.issues if i.severity == "ERROR")


def test_slack_token_has_three_segments():
    # Real Slack bot tokens are xoxb-<W>-<X>-<Y>; the template should reflect that.
    value = sp.synthesize_value("slack_token", "spill:e:syslog_message:slack_token")
    assert value.startswith("xoxb-") and value.count("-") >= 3
