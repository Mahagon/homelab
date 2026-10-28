import contextlib
import datetime as dt
import io
import ipaddress
import json
import re
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import render_configmap  # noqa: E402
import sync_ip_bans as m  # noqa: E402

APP_DIR = Path(__file__).resolve().parents[2]
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)
ENV = {
    "CLOUDFLARE_API_TOKEN": "test-token",
    "CLOUDFLARE_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
    "CLOUDFLARE_ZONE_ID": "fedcba9876543210fedcba9876543210",
    "CLOUDFLARE_LIST_ID": "2c0fc9fa937b11eaa1b71c4d701ab86e",
    "ABUSEIPDB_API_KEY": "test-abuseipdb-key",
}
# Only RFC 5737 / RFC 3849 documentation addresses appear in this file.
PROBE_V4 = "192.0.2.10"
PROBE_V6 = "2001:db8:1:2::abcd"
LISTED_V4 = "198.51.100.7"
MANUAL_V4 = "203.0.113.5"
OWN_V4 = "203.0.113.77"
OWN_V6 = "2001:db8:aa:bb::1"


Call = tuple[str, str, str]


def config(**overrides: Any) -> m.Config:
    return m.Config(
        cloudflare_token="t", account_id="a", zone_id="z", list_id="l", **overrides
    )


def item(item_id: str, ip: str, comment: str = "") -> m.ListItem:
    return m.ListItem(item_id, ipaddress.ip_network(ip, strict=False), comment)


def items(*entries: m.ListItem) -> dict[str, m.ListItem]:
    return {entry.value: entry for entry in entries}


def hit(ip: str, seen: dt.datetime, path: str = "/.env") -> tuple[str, m.Hit]:
    return m.list_value(m.ban_network(ip)), m.Hit(ip, path, seen)


class HelperTests(unittest.TestCase):
    def test_tag_round_trip(self):
        tag = m.make_tag(m.RECON, NOW)
        self.assertEqual(tag, "ip-bans:recon:2026-10-25T12:00:00Z")
        self.assertEqual(m.parse_tag(tag), (m.RECON, NOW))

    def test_foreign_comments_are_not_tags(self):
        for comment in ("", "manual ban", "ip-bans:other:2026-10-25T12:00:00Z", "ip-bans:recon:soon"):
            self.assertIsNone(m.parse_tag(comment))

    def test_ipv6_bans_cover_the_slash_64(self):
        self.assertEqual(m.list_value(m.ban_network(PROBE_V6)), "2001:db8:1:2::/64")
        self.assertEqual(m.list_value(m.ban_network(PROBE_V4)), PROBE_V4)

    def test_redact_hides_addresses_and_keeps_ids(self):
        text = (
            f"bad item ip:{PROBE_V4}. net {LISTED_V4}/24, v6 {PROBE_V6} "
            "id 34b12448945f11eaa1b71c4d701ab86e at 2026-10-25T12:00:00Z v3.15.1"
        )
        redacted = m.redact(text)
        for address in (PROBE_V4, LISTED_V4, PROBE_V6):
            self.assertNotIn(address, redacted)
        self.assertIn("34b12448945f11eaa1b71c4d701ab86e", redacted)
        self.assertIn("2026-10-25T12:00:00Z", redacted)
        self.assertIn("v3.15.1", redacted)

    def test_config_requires_cloudflare_settings(self):
        env = dict(ENV)
        del env["CLOUDFLARE_LIST_ID"]
        with self.assertRaisesRegex(m.SyncError, "CLOUDFLARE_LIST_ID"):
            m.Config.from_env(env)

    def test_invalid_allowlist_entry_is_not_echoed(self):
        with self.assertRaises(m.SyncError) as raised:
            m.Config.from_env(ENV | {"IP_BAN_ALLOWLIST": f"{PROBE_V4}, 192.0.2.300"})
        self.assertNotIn("192.0.2", str(raised.exception))

    def test_config_defaults(self):
        parsed = m.Config.from_env(ENV | {"IP_BAN_ALLOWLIST": f"{MANUAL_V4} 2001:db8::/48"})
        self.assertEqual(parsed.ban_hours, 24)
        self.assertEqual(parsed.countries, frozenset({"DE"}))
        self.assertEqual(len(parsed.allowlist), 2)


class PlanReconTests(unittest.TestCase):
    def test_new_hit_is_banned_and_reported(self):
        value, h = hit(PROBE_V6, NOW - dt.timedelta(minutes=3))
        plan = m.plan_recon({}, {value: h}, NOW, config())
        self.assertEqual(plan.upserts, {value: m.make_tag(m.RECON, h.seen)})
        self.assertEqual(plan.new_bans, [h])

    def test_active_ban_is_kept_and_only_moved_forward(self):
        banned_at = NOW - dt.timedelta(hours=1)
        existing = items(item("i1", PROBE_V4, m.make_tag(m.RECON, banned_at)))
        older = dict([hit(PROBE_V4, banned_at - dt.timedelta(minutes=5))])
        self.assertEqual(m.plan_recon(existing, older, NOW, config()).upserts, {})
        newer = dict([hit(PROBE_V4, banned_at + dt.timedelta(minutes=2))])
        plan = m.plan_recon(existing, newer, NOW, config())
        self.assertEqual(list(plan.upserts), [PROBE_V4])
        self.assertEqual(plan.new_bans, [])
        self.assertEqual(plan.deletes, [])

    def test_expired_ban_is_removed(self):
        existing = items(item("i1", PROBE_V4, m.make_tag(m.RECON, NOW - dt.timedelta(hours=25))))
        self.assertEqual(m.plan_recon(existing, {}, NOW, config()).deletes, ["i1"])

    def test_manual_entries_are_untouched(self):
        existing = items(item("i1", MANUAL_V4, "blocked by hand"))
        plan = m.plan_recon(existing, dict([hit(MANUAL_V4, NOW)]), NOW, config())
        self.assertEqual((plan.upserts, plan.deletes, plan.new_bans), ({}, [], []))

    def test_abuseipdb_entry_becomes_recon_ban(self):
        existing = items(item("i1", LISTED_V4, m.make_tag(m.ABUSEIPDB, NOW - dt.timedelta(days=1))))
        plan = m.plan_recon(existing, dict([hit(LISTED_V4, NOW)]), NOW, config())
        self.assertEqual(plan.upserts, {LISTED_V4: m.make_tag(m.RECON, NOW)})
        self.assertEqual(len(plan.new_bans), 1)
        self.assertEqual(plan.deletes, [])

    def test_allowlist_skips_hits_and_removes_tagged_items(self):
        allow = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8:1::/48"))
        existing = items(item("i1", PROBE_V4, m.make_tag(m.ABUSEIPDB, NOW)))
        hits = dict([hit(PROBE_V4, NOW), hit(PROBE_V6, NOW)])
        plan = m.plan_recon(existing, hits, NOW, config(allowlist=allow))
        self.assertEqual((plan.upserts, plan.deletes), ({}, ["i1"]))


class PlanImportTests(unittest.TestCase):
    @staticmethod
    def entry(ip: str, country: str = "DE", age: dt.timedelta = dt.timedelta(days=1)) -> m.JsonMap:
        return {"ipAddress": ip, "countryCode": country, "lastReportedAt": (NOW - age).isoformat()}

    def test_keeps_recent_entries_from_allowed_countries(self):
        entries = [
            self.entry(LISTED_V4),
            self.entry("198.51.100.8", country="US"),
            self.entry("198.51.100.9", age=dt.timedelta(days=8)),
            self.entry(PROBE_V6),
        ]
        plan = m.plan_import({}, entries, NOW, config())
        self.assertEqual(sorted(plan.upserts), sorted([LISTED_V4, "2001:db8:1:2::/64"]))
        self.assertEqual(plan.listed, 2)

    def test_recon_and_manual_items_take_precedence(self):
        existing = items(
            item("i1", PROBE_V4, m.make_tag(m.RECON, NOW)),
            item("i2", MANUAL_V4, "blocked by hand"),
        )
        plan = m.plan_import(existing, [self.entry(PROBE_V4), self.entry(MANUAL_V4)], NOW, config())
        self.assertEqual((plan.upserts, plan.deletes), ({}, []))

    def test_unchanged_entries_are_not_rewritten_and_stale_ones_removed(self):
        current = self.entry(LISTED_V4)
        existing = items(
            item("i1", LISTED_V4, m.make_tag(m.ABUSEIPDB, m.parse_time(str(current["lastReportedAt"])))),
            item("i2", "198.51.100.20", m.make_tag(m.ABUSEIPDB, NOW - dt.timedelta(days=2))),
        )
        plan = m.plan_import(existing, [current], NOW, config())
        self.assertEqual((plan.upserts, plan.deletes), ({}, ["i2"]))

    def test_respects_item_cap_in_blacklist_order(self):
        entries = [self.entry(f"198.51.100.{n}") for n in range(1, 6)]
        plan = m.plan_import({}, entries, NOW, config(abuseipdb_max_items=2))
        self.assertEqual(list(plan.upserts), ["198.51.100.1", "198.51.100.2"])


class FakeResponse:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> bool:
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


class FakeTextResponse(FakeResponse):
    def __init__(self, text: str) -> None:
        super().__init__(200, None)
        self.text = text

    def read(self) -> bytes:
        return self.text.encode()


class FakeApi:
    """Routes requests to canned Cloudflare and AbuseIPDB responses."""

    def __init__(
        self,
        events: list[dict[str, str]],
        list_items: tuple[dict[str, str], ...] = (),
        blacklist: tuple[m.JsonMap, ...] = (),
        own: tuple[str, ...] = (OWN_V4,),
    ) -> None:
        self.events = events
        self.list_items = list(list_items)
        self.blacklist = list(blacklist)
        self.own = own
        self.calls: list[Call] = []

    def bodies(self, method: str, suffix: str) -> list[str]:
        return [body for verb, url, body in self.calls if verb == method and url.endswith(suffix)]

    def __call__(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        method, url = request.get_method(), request.full_url
        data = request.data
        body = data.decode() if isinstance(data, bytes) else ""
        self.calls.append((method, url, body))
        path = urllib.parse.urlsplit(url).path
        if "icanhazip" in url:
            version = 6 if "ipv6" in url else 4
            for address in self.own:
                if ipaddress.ip_address(address).version == version:
                    return FakeTextResponse(f"{address}\n")
            raise urllib.error.URLError(OSError(101, "Network is unreachable"))
        if url.startswith(m.ABUSEIPDB_API):
            if path.endswith("/blacklist"):
                return FakeResponse(200, {"data": self.blacklist})
            return FakeResponse(200, {"data": {"abuseConfidenceScore": 100}})
        if path.endswith("/graphql"):
            return FakeResponse(200, {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": self.events}]}}, "errors": None})
        if path.endswith("/entrypoint"):
            rules = [{"id": "rule-1", "ref": "home_assistant_https_only"}, {"id": "rule-3", "ref": "home_assistant_reconnaissance_paths"}]
            return FakeResponse(200, {"success": True, "result": {"rules": rules}})
        if "/bulk_operations/" in path:
            return FakeResponse(200, {"success": True, "result": {"status": "completed"}})
        if path.endswith("/items") and method == "GET":
            return FakeResponse(200, {"success": True, "result": self.list_items, "result_info": {"cursors": {}}})
        if path.endswith("/items"):
            return FakeResponse(200, {"success": True, "result": {"operation_id": "op-1"}})
        raise AssertionError(f"unexpected request {method} {path}")


def run(mode: str, api: FakeApi, env: dict[str, str] = ENV) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    http = m.Http(opener=api, sleep=lambda _: None)
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = m.main([mode], env=env, http=http, now=NOW)
    return code, out.getvalue() + err.getvalue()


class EndToEndTests(unittest.TestCase):
    def assert_no_addresses(self, output: str) -> None:
        for address in (PROBE_V4, PROBE_V6, LISTED_V4, MANUAL_V4, OWN_V4, OWN_V6, "2001:db8:1:2::"):
            self.assertNotIn(address, output)

    def test_recon_bans_reports_and_logs_counts_only(self):
        events = [
            {"clientIP": PROBE_V4, "clientRequestPath": "/.git/config", "datetime": "2026-10-25T11:58:00Z"},
            {"clientIP": PROBE_V4, "clientRequestPath": "/.env", "datetime": "2026-10-25T11:55:00Z"},
            {"clientIP": PROBE_V6, "clientRequestPath": "/wp-login.php", "datetime": "2026-10-25T11:50:00Z"},
        ]
        expired = {"id": "old", "ip": MANUAL_V4, "comment": "ip-bans:recon:2026-10-24T08:00:00Z"}
        api = FakeApi(events, list_items=(expired,))
        code, output = run("recon", api)

        self.assertEqual(code, 0, output)
        self.assertIn("banned=2", output)
        self.assertIn("removed=1", output)
        self.assertIn("reported=2", output)
        self.assertIn("own_ipv4=exempt own_ipv6=not detected", output)
        self.assert_no_addresses(output)

        graphql = json.loads(api.bodies("POST", "/graphql")[0])
        self.assertEqual(graphql["variables"]["ruleId"], "rule-3")
        upsert: list[dict[str, str]] = json.loads(api.bodies("POST", "/items")[0])
        self.assertEqual(
            sorted(upsert, key=lambda entry: entry["ip"]),
            [
                {"ip": PROBE_V4, "comment": "ip-bans:recon:2026-10-25T11:58:00Z"},
                {"ip": "2001:db8:1:2::/64", "comment": "ip-bans:recon:2026-10-25T11:50:00Z"},
            ],
        )
        self.assertEqual(json.loads(api.bodies("DELETE", "/items")[0]), {"items": [{"id": "old"}]})

        reports = [urllib.parse.parse_qs(body) for body in api.bodies("POST", "/report")]
        self.assertEqual(sorted(r["ip"][0] for r in reports), sorted([PROBE_V4, PROBE_V6]))
        for report in reports:
            self.assertEqual(report["categories"], ["21"])
            self.assertTrue(report["comment"][0].startswith("Blocked by Cloudflare WAF: probe for /"))

    def test_recon_without_key_skips_reporting(self):
        env = {k: v for k, v in ENV.items() if k != "ABUSEIPDB_API_KEY"}
        events = [{"clientIP": PROBE_V4, "clientRequestPath": "/.env", "datetime": "2026-10-25T11:58:00Z"}]
        api = FakeApi(events)
        code, output = run("recon", api, env)
        self.assertEqual(code, 0, output)
        self.assertFalse(any(url.startswith(m.ABUSEIPDB_API) for _, url, _ in api.calls))

    def test_abuseipdb_mode_mirrors_german_entries(self):
        blacklist: tuple[m.JsonMap, ...] = (
            {"ipAddress": LISTED_V4, "countryCode": "DE", "abuseConfidenceScore": 100, "lastReportedAt": "2026-10-25T10:00:00+00:00"},
            {"ipAddress": MANUAL_V4, "countryCode": "NL", "abuseConfidenceScore": 100, "lastReportedAt": "2026-10-25T10:00:00+00:00"},
        )
        api = FakeApi([], blacklist=blacklist)
        code, output = run("abuseipdb", api)
        self.assertEqual(code, 0, output)
        self.assertIn("listed=1", output)
        self.assert_no_addresses(output)
        upsert = json.loads(api.bodies("POST", "/items")[0])
        self.assertEqual(upsert, [{"ip": LISTED_V4, "comment": "ip-bans:abuseipdb:2026-10-25T10:00:00Z"}])

    def test_empty_blacklist_leaves_mirrored_entries(self):
        mirrored = {"id": "kept", "ip": LISTED_V4, "comment": "ip-bans:abuseipdb:2026-10-24T08:00:00Z"}
        api = FakeApi([], list_items=(mirrored,), blacklist=())
        code, output = run("abuseipdb", api)
        self.assertNotEqual(code, 0)
        self.assertIn("empty blacklist", output)
        self.assertEqual(api.bodies("DELETE", "/items"), [])
        self.assert_no_addresses(output)

    def test_config_repr_hides_credentials_and_allowlist(self):
        config = m.Config(
            cloudflare_token="cf-secret-token",
            account_id="a",
            zone_id="z",
            list_id="l",
            abuseipdb_key="abuse-secret-key",
            allowlist=(ipaddress.ip_network(f"{OWN_V4}/32"),),
        )
        for hidden in ("cf-secret-token", "abuse-secret-key", OWN_V4):
            self.assertNotIn(hidden, repr(config))

    def test_off_disables_boolean_settings(self):
        self.assertFalse(m.env_bool({"ABUSEIPDB_REPORT": "off"}, "ABUSEIPDB_REPORT", True))

    def test_own_addresses_are_never_banned(self):
        events = [
            {"clientIP": OWN_V4, "clientRequestPath": "/.git/config", "datetime": "2026-10-25T11:58:00Z"},
            {"clientIP": "2001:db8:aa:bb::99", "clientRequestPath": "/.env", "datetime": "2026-10-25T11:57:00Z"},
        ]
        listed = {"id": "own", "ip": OWN_V4, "comment": "ip-bans:abuseipdb:2026-10-24T08:00:00Z"}
        api = FakeApi(events, list_items=(listed,), own=(OWN_V4, OWN_V6))
        code, output = run("recon", api)
        self.assertEqual(code, 0, output)
        self.assertIn("banned=0", output)
        self.assertIn("own_ipv6=exempt", output)
        self.assert_no_addresses(output)
        self.assertEqual(api.bodies("POST", "/items"), [])
        self.assertEqual(json.loads(api.bodies("DELETE", "/items")[0]), {"items": [{"id": "own"}]})
        self.assertEqual(api.bodies("POST", "/report"), [])

    def test_missing_own_ipv4_changes_nothing(self):
        events = [{"clientIP": PROBE_V4, "clientRequestPath": "/.env", "datetime": "2026-10-25T11:58:00Z"}]
        api = FakeApi(events, own=())
        code, output = run("recon", api)
        self.assertEqual(code, 1)
        self.assertIn("could not detect the own public IPv4", output)
        self.assertFalse(any("cloudflare.com/client" in url for _, url, _ in api.calls))

    def test_api_errors_are_redacted(self):
        class FailingApi(FakeApi):
            def __call__(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
                if request.get_method() == "POST" and request.full_url.endswith("/items"):
                    error: m.JsonMap = {"code": 10001, "message": f"invalid item {PROBE_V4}"}
                    payload: m.JsonMap = {"success": False, "errors": [error]}
                    return FakeResponse(400, payload)
                return super().__call__(request, timeout)

        events = [{"clientIP": PROBE_V4, "clientRequestPath": "/.env", "datetime": "2026-10-25T11:58:00Z"}]
        code, output = run("recon", FailingApi(events))
        self.assertEqual(code, 1)
        self.assertIn("10001", output)
        self.assert_no_addresses(output)


class RepositoryTests(unittest.TestCase):
    def test_configmap_matches_script(self):
        configmap = render_configmap.CONFIGMAP.read_text(encoding="utf-8")
        self.assertEqual(
            configmap,
            render_configmap.render(),
            "Run python k8s/apps/ip-bans/scripts/render_configmap.py after editing the script.",
        )

    def test_no_public_addresses_are_committed(self):
        candidate = re.compile(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?")
        offenders: list[str] = []
        for path in sorted(APP_DIR.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            for token in candidate.findall(path.read_text(encoding="utf-8")):
                if not m.is_address(token):
                    continue
                if ipaddress.ip_network(token, strict=False).network_address.is_global:
                    offenders.append(f"{path.relative_to(APP_DIR)}: {token}")
        self.assertEqual(offenders, [], "Use RFC 5737/3849 documentation addresses instead.")


if __name__ == "__main__":
    unittest.main()
