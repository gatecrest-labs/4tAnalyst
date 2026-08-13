"""
FortiManager JSON-RPC API client (7.4.x / 7.6.x compatible).

Handles:
  - REST API Administrator auth: the API key is sent as an "Authorization:
    Bearer" header on every call, with session left null. This admin type
    has no /sys/login/user session — unlike a regular admin account, there
    is no password-based login and nothing to keep alive.
  - Primary/secondary host failover — if primary is unreachable, retries on secondary
  - Transparent pagination via the 'range' parameter
  - Version-aware policy package path (7.4 vs 7.6 compatibility flag)
  - JSON-RPC error code mapping to clear exception messages

All methods raise FortiManagerAPIError on connection failure or API-level errors.
"""

import logging
import threading
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# JSON-RPC error codes
_FMG_ERRORS = {
    -6:  "Invalid URL / endpoint not found",
    -9:  "Object not found",
    -10: "Permission denied (check API key has read access)",
    -11: "No permission for the resource (check the admin profile's JSON API Access / ADOM scope)",
    -22: "Login fail (bad credential, JSON API Access disabled, or Trusted Hosts block this source IP)",
}


class FortiManagerAPIError(Exception):
    """Raised for HTTP errors or JSON-RPC error responses from FortiManager."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class FortiManagerClient:
    """
    Thread-safe FortiManager JSON-RPC client with primary/secondary failover.

    Parameters
    ----------
    primary_host    : Primary FortiManager hostname or IP
    primary_key     : API key for primary (REST API Administrator's key, sent as Bearer token)
    secondary_host  : Secondary FortiManager hostname or IP (failover)
    secondary_key   : API key for secondary
    port            : HTTPS port (default 443)
    verify_ssl      : Verify TLS certificate
    version         : "7.4" or "7.6" — controls policy package path prefix
    session_timeout : Unused for Bearer-token auth; kept for config compatibility.
    """

    _JSONRPC_PATH = "/jsonrpc"

    def __init__(
        self,
        primary_host: str,
        primary_key: str,
        secondary_host: str = "",
        secondary_key: str = "",
        port: int = 443,
        verify_ssl: bool = True,
        version: str = "7.4",
        session_timeout: int = 300,
    ) -> None:
        self._hosts = []
        if primary_host:
            self._hosts.append((primary_host, primary_key))
        if secondary_host:
            self._hosts.append((secondary_host, secondary_key))
        if not self._hosts:
            raise ValueError("At least one FortiManager host must be configured")

        self._port = port
        self._verify_ssl = verify_ssl
        self._version = version

        self._active_host: str = ""
        self._active_key: str = ""
        self._request_id = 0
        self._id_lock = threading.Lock()

        self._http = httpx.Client(
            verify=verify_ssl,
            timeout=httpx.Timeout(connect=10.0, read=300.0, write=10.0, pool=5.0),
            headers={"Content-Type": "application/json"},
        )

    # ------------------------------------------------------------------
    # Version-aware path helpers
    # ------------------------------------------------------------------

    @property
    def _policy_pkg_prefix(self) -> str:
        """
        Policy package path prefix differs slightly between 7.4 and 7.6.
        Currently identical; kept as a flag for when 7.6 migration is confirmed.
        """
        # 7.4: /pm/config/adom/<adom>/pkg/<pkg>/firewall/policy
        # 7.6: verify at migration time — update here and flip version flag in credentials.yaml
        return "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy"

    # ------------------------------------------------------------------
    # Connection setup
    # ------------------------------------------------------------------

    def login(self) -> None:
        """
        Pick the first reachable host (failover to secondary) and verify the
        API key works. No session is established — Bearer-token auth is
        stateless, so this just confirms connectivity + auth up front rather
        than surfacing the failure on the first real call.
        """
        last_exc: Exception | None = None
        for host, key in self._hosts:
            self._active_host = host
            self._active_key = key
            try:
                self._rpc("get", "/dvmdb/adom", {"range": [0, 1]})
                logger.info("FortiManager API key verified against %s", host)
                return
            except FortiManagerAPIError as exc:
                logger.warning("FortiManager %s auth/connection failed: %s", host, exc)
                last_exc = exc

        self._active_host = ""
        self._active_key = ""
        raise FortiManagerAPIError(
            f"All FortiManager hosts unreachable or unauthorized. Last error: {last_exc}"
        )

    def logout(self) -> None:
        """No-op — Bearer-token auth has no session to invalidate."""

    # ------------------------------------------------------------------
    # JSON-RPC core
    # ------------------------------------------------------------------

    def _rpc(self, method: str, url_path: str, params: dict) -> Any:
        """
        Execute a JSON-RPC call authenticated via the Bearer API key.
        Returns the 'data' field from the first result object, or the full
        result if 'data' is absent.
        """
        if not self._active_host:
            raise FortiManagerAPIError("FortiManagerClient.login() must be called first")

        base_url = f"https://{self._active_host}:{self._port}{self._JSONRPC_PATH}"
        with self._id_lock:
            self._request_id += 1
            request_id = self._request_id

        payload: dict[str, Any] = {
            "id": request_id,
            "method": method,
            "params": [{**params, "url": url_path}],
            "session": None,
            "verbose": 1,
        }

        try:
            resp = self._http.post(
                base_url,
                json=payload,
                headers={"Authorization": f"Bearer {self._active_key}"},
            )
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise FortiManagerAPIError(
                f"Connection to FortiManager {self._active_host} failed: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise FortiManagerAPIError(
                f"FortiManager returned HTTP {exc.response.status_code}"
            ) from exc

        data = resp.json()
        result = data.get("result", [{}])[0]
        status = result.get("status", {})
        code = status.get("code", -1)

        if code != 0:
            msg = _FMG_ERRORS.get(code, status.get("message", "Unknown error"))
            raise FortiManagerAPIError(
                f"FortiManager API error on {url_path}: [{code}] {msg}", code=code
            )

        return result.get("data", result)

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    def _get_all(self, url_path: str, extra_params: dict | None = None) -> list:
        """Fetch all items for a list endpoint using range-based pagination."""
        results = []
        offset = 0
        limit = 2000
        extra = extra_params or {}

        while True:
            params = {**extra, "range": [offset, limit]}
            batch = self._rpc("get", url_path, params)
            if not batch:
                break
            if isinstance(batch, list):
                results.extend(batch)
                if len(batch) < limit:
                    break
                offset += len(batch)
            else:
                # Single-object response (not a list)
                return [batch]

        return results

    # ------------------------------------------------------------------
    # System status
    # ------------------------------------------------------------------

    def get_system_status(self) -> dict:
        """Return FortiManager system status (version, hostname, serial, platform)."""
        result = self._rpc("get", "/sys/status", {})
        return result if isinstance(result, dict) else {}

    def get_ha_status(self) -> dict:
        """Return FortiManager HA cluster status."""
        result = self._rpc("get", "/sys/ha/status", {})
        return result if isinstance(result, dict) else {}

    # ------------------------------------------------------------------
    # ADOM / device discovery
    # ------------------------------------------------------------------

    def get_adoms(self) -> list[dict]:
        """List all ADOMs."""
        return self._get_all("/dvmdb/adom")

    def get_devices(self, adom: str) -> list[dict]:
        """List FortiGates managed in an ADOM."""
        return self._get_all(f"/dvmdb/adom/{adom}/device")

    def get_device_meta(self, adom: str, device: str) -> dict:
        """Return firmware version, HA state, and last sync status for a device."""
        result = self._rpc("get", f"/dvmdb/adom/{adom}/device/{device}", {})
        return result if isinstance(result, dict) else {}

    def get_device_vdoms(self, adom: str, device: str) -> list[dict]:
        """List VDOMs configured on a device."""
        return self._get_all(f"/dvmdb/adom/{adom}/device/{device}/vdom")

    # ------------------------------------------------------------------
    # Policy packages
    # ------------------------------------------------------------------

    def get_policy_packages(self, adom: str) -> list[dict]:
        """List all leaf policy packages in an ADOM, with full folder paths.

        FortiManager nests packages inside folders (subobj). The policy API
        path for a nested package uses the full slash-separated folder path,
        e.g. "PRODUCTION/Perimeter/SITE01-CORE-FW01". This method flattens the
        tree so callers always get leaf packages with their correct path in the
        "name" field and scope member preserved for device matching.
        """
        raw = self._get_all(f"/pm/pkg/adom/{adom}")
        return self._flatten_packages(raw, prefix="")

    @staticmethod
    def _flatten_packages(items: list, prefix: str) -> list[dict]:
        """Recursively flatten a nested package tree into leaf packages."""
        result = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            full_path = f"{prefix}/{name}" if prefix else name
            pkg_type = item.get("type", "")
            children = item.get("subobj") or []
            if pkg_type == "pkg":
                result.append({**item, "name": full_path})
            elif children:
                result.extend(FortiManagerClient._flatten_packages(children, full_path))
            else:
                result.append({**item, "name": full_path})
        return result

    def get_global_policy_packages(self) -> list[dict]:
        """List global ADOM policy packages (inherited by per-ADOM policies)."""
        return self._get_all("/pm/pkg/global")

    # ------------------------------------------------------------------
    # Policy search
    # ------------------------------------------------------------------

    def get_policies(self, adom: str, pkg: str) -> list[dict]:
        """Return all policies in a package."""
        path = self._policy_pkg_prefix.format(adom=adom, pkg=pkg)
        return self._get_all(path)

    def get_policy(self, adom: str, pkg: str, policy_id: int) -> dict:
        """Return a single policy by ID."""
        path = self._policy_pkg_prefix.format(adom=adom, pkg=pkg)
        result = self._rpc("get", f"{path}/{policy_id}", {})
        return result if isinstance(result, dict) else {}

    # ------------------------------------------------------------------
    # Address objects
    # ------------------------------------------------------------------

    def get_address_objects(self, adom: str) -> list[dict]:
        """List all address objects in an ADOM."""
        return self._get_all(f"/pm/config/adom/{adom}/obj/firewall/address")

    def get_address_object(self, adom: str, name: str) -> dict:
        """Fetch a single address object by exact name."""
        result = self._rpc(
            "get", f"/pm/config/adom/{adom}/obj/firewall/address/{name}", {}
        )
        return result if isinstance(result, dict) else {}

    def get_address_groups(self, adom: str) -> list[dict]:
        """List all address group objects in an ADOM."""
        return self._get_all(f"/pm/config/adom/{adom}/obj/firewall/addrgrp")

    def get_global_address_objects(self) -> list[dict]:
        """List address objects in the global ADOM."""
        return self._get_all("/pm/config/global/obj/firewall/address")

    def get_global_address_groups(self) -> list[dict]:
        """List address group objects in the global ADOM."""
        return self._get_all("/pm/config/global/obj/firewall/addrgrp")

    # ------------------------------------------------------------------
    # Service objects
    # ------------------------------------------------------------------

    def get_service_objects(self, adom: str) -> list[dict]:
        """List all service objects in an ADOM."""
        return self._get_all(f"/pm/config/adom/{adom}/obj/firewall/service/custom")

    def get_service_object(self, adom: str, name: str) -> dict:
        """Fetch a single service object by exact name."""
        result = self._rpc(
            "get",
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}",
            {},
        )
        return result if isinstance(result, dict) else {}

    def get_service_groups(self, adom: str) -> list[dict]:
        """List service group objects in an ADOM."""
        return self._get_all(f"/pm/config/adom/{adom}/obj/firewall/service/group")

    # ------------------------------------------------------------------
    # Interface / zone map
    # ------------------------------------------------------------------

    def get_device_interfaces(self, adom: str, device: str) -> list[dict]:
        """Return interface definitions for a managed device."""
        return self._get_all(
            f"/pm/config/device/{device}/vdom/root/system/interface"
        )

    def get_device_interface_config(
        self, device: str, vlanids: list[int] | None = None, name: str | None = None
    ) -> Any:
        """Return device-DB interface CONFIG objects, optionally filtered.

        Unlike get_device_interfaces (live monitor proxy, no filtering),
        this reads FortiManager's device-DB interface config and supports
        server-side filtering by exact name and/or VLAN id membership.
        """
        name_clause = ["name", "==", name] if name else None
        vlan_clause = ["vlanid", "in", *vlanids] if vlanids else None
        params: dict[str, Any] = {}
        if name_clause and vlan_clause:
            params["filter"] = [name_clause, "&&", vlan_clause]
        elif name_clause:
            params["filter"] = name_clause
        elif vlan_clause:
            params["filter"] = vlan_clause
        return self._rpc("get", f"/pm/config/device/{device}/global/system/interface", params)

    def _proxy(self, action: str, resource: str, target: list[str]) -> Any:
        """Execute a FortiGate REST call via FortiManager's device proxy (EXEC /sys/proxy/json).

        FMG JSON-RPC requires proxy parameters nested under a "data" key:
            params[0] = {"url": "/sys/proxy/json", "data": {"action": ..., "resource": ..., "target": ...}}

        _rpc spreads the params dict with "url", so passing {"data": {...}} produces the correct shape.
        """
        return self._rpc("exec", "/sys/proxy/json", {
            "data": {
                "action": action,
                "resource": resource,
                "target": target,
            }
        })

    def get_device_client_location(self, adom: str, device: str) -> Any:
        """Return the raw detected-client inventory proxy envelope for a device."""
        return self._proxy(
            action="get",
            resource="/api/v2/monitor/user/device/query",
            target=[f"/adom/{adom}/device/{device}"],
        )

    def get_device_sdwan(self, device: str, vdom: str = "root") -> Any:
        """Return the device-DB SD-WAN config (members/zones/rules) for a managed device."""
        return self._rpc("get", f"/pm/config/device/{device}/vdom/{vdom}/system/sdwan", {})

    def get_device_sdwan_monitor(self, adom: str, device: str) -> tuple[Any, Any]:
        """Return raw (members, health_check) proxy envelopes for live SD-WAN monitor state."""
        target = [f"/adom/{adom}/device/{device}"]
        members = self._proxy(action="get", resource="/api/v2/monitor/virtual-wan/members", target=target)
        health = self._proxy(action="get", resource="/api/v2/monitor/virtual-wan/health-check", target=target)
        return members, health

    # ------------------------------------------------------------------
    # Routing table
    # ------------------------------------------------------------------

    def get_routing_table_live(self, adom: str, device: str) -> Any:
        """Return the live IPv4 routing table via FMG proxy with vdom=*.

        Uses the FortiGate monitor API so BGP, OSPF, and connected routes
        are included — not just configured static routes. Returns the raw
        proxy envelope; callers must unpack it with _parse_live_routes().
        Raises FortiManagerAPIError if the proxy call fails.
        """
        return self._proxy(
            action="get",
            resource="/api/v2/monitor/router/ipv4?vdom=*",
            target=[f"/adom/{adom}/device/{device}"],
        )

    def get_routing_table(self, adom: str, device: str) -> list[dict]:
        """Return static routes across all VDOMs configured on a managed device.

        Iterates every VDOM returned by get_device_vdoms (falling back to
        'root' for non-VDOM devices). One VDOM's failure is skipped rather
        than propagated so partially-configured devices return what they have.
        """
        try:
            vdom_names = [
                v.get("name", "root")
                for v in self.get_device_vdoms(adom, device)
                if isinstance(v, dict) and v.get("name")
            ]
        except Exception:
            vdom_names = []
        if not vdom_names:
            vdom_names = ["root"]

        routes: list[dict] = []
        for vname in vdom_names:
            try:
                for route in self._get_all(
                    f"/pm/config/device/{device}/vdom/{vname}/router/static"
                ):
                    if isinstance(route, dict):
                        r = dict(route)
                        r.setdefault("_vdom", vname)
                        routes.append(r)
            except Exception:
                pass
        return routes

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "FortiManagerClient":
        self.login()
        return self

    def __exit__(self, *_) -> None:
        self.logout()
        self._http.close()
