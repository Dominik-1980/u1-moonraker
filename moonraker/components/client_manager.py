# LAN client management – thin proxy that delegates business logic to unisrv.
#
# All state, cert generation, MQTT notifications, and cloud auth are now
# handled by unisrv's LanManager.  This module only keeps the GUI-facing
# HTTP/WebSocket endpoints and screen event forwarding.
#
# Copyright (C) 2025 Snapmaker
#
# This file may be distributed under the terms of the GNU GPLv3 license.
from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import random
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Optional,
)

from ..common import RequestType, TransportType
from ..utils import json_wrapper as jsonw

if TYPE_CHECKING:
    from ..confighelper import ConfigHelper
    from ..common import WebRequest
    from .mqtt import MQTTClient

DEFAULT_CODE = 12345678
LINK_MODE_CLOUD = 0
LINK_MODE_LAN = 1


class ClientManager:
    def __init__(self, config: ConfigHelper) -> None:
        self.server = config.get_server()
        self.mqtt: Optional[MQTTClient] = None

        app_args = self.server.get_app_args()
        self.datapath: pathlib.Path = pathlib.Path(app_args["data_path"])
        self.client_cfg_path = self.datapath.joinpath("mqtt").joinpath("client.json")
        self.machine = None  # set in component_init

        self.server.register_notification("snapmaker:client_access")
        self.server.register_notification("snapmaker:user_access")
        self.server.register_notification("snapmaker:update_mdns_info")

        # Track last userid sent to mDNS so we can detect agent-initiated changes
        self._last_mdns_userid: str = ""

        # ---------- GUI endpoints (HTTP/WebSocket → forward to unisrv) ----------
        self.server.register_endpoint(
            "/server/client_manager/info", RequestType.POST,
            self._handle_get_info, transports=TransportType.WEBSOCKET)
        self.server.register_endpoint(
            "/server/client_manager/approve", RequestType.POST,
            self._handle_approve_connection,
            transports=TransportType.WEBSOCKET | TransportType.MQTT)
        self.server.register_endpoint(
            "/server/client_manager/disconnect_all", RequestType.POST,
            self._handle_disconnection_all, transports=TransportType.WEBSOCKET)
        self.server.register_endpoint(
            "/server/client_manager/set_link_mode", RequestType.POST,
            self._handle_set_link_mode, transports=TransportType.WEBSOCKET)
        self.server.register_endpoint(
            "/server/client_manager/set_region", RequestType.POST,
            self._handle_set_region,
            transports=TransportType.WEBSOCKET | TransportType.MQTT)
        self.server.register_endpoint(
            "/server/client_manager/logout", RequestType.POST,
            self._handle_logout,
            transports=TransportType.WEBSOCKET | TransportType.MQTT)
        self.server.register_endpoint(
            "/server/client_manager/refresh_access_code", RequestType.POST,
            self._handle_refresh_access_code, transports=TransportType.WEBSOCKET)
        self.server.register_endpoint(
            "/server/client_manager/refresh_pin_code", RequestType.POST,
            self._handle_refresh_pin_code, transports=TransportType.WEBSOCKET)

    async def component_init(self) -> None:
        self.mqtt = self.server.lookup_component("mqtt", None)
        self.machine = self.server.lookup_component("machine", None)
        if self.mqtt is None:
            logging.info("smclient: MQTT not available")
            return

        # Subscribe to screen notifications from C++ LanManager
        # (e.g. new LAN client access request → show auth dialog)
        self.screen_notif_hdl = self.mqtt.subscribe_topic(
            "lan_manager/screen_event",
            self._handle_screen_notification,
            qos=1)
        logging.info("smclient: subscribed to lan_manager/screen_event")

        # Subscribe to agent status notifications so we can detect
        # agent-initiated userid changes and keep mDNS up-to-date
        self._last_mdns_userid = self.get_userid()
        self.agent_notif_hdl = self.mqtt.subscribe_topic(
            "mqtt_agent/notification",
            self._handle_agent_notification,
            qos=1)
        logging.info("smclient: subscribed to mqtt_agent/notification")

    async def _handle_screen_notification(self, data: bytes) -> None:
        """Forward screen notifications from C++ LanManager to moonraker events."""
        try:
            msg = jsonw.loads(data)
            method = msg.get("method", "")
            params = msg.get("params", {})
            if method == "screen.client_access":
                self.server.send_event("snapmaker:client_access", params)
            elif method == "screen.user_access":
                self.server.send_event("snapmaker:user_access", params)
        except Exception as e:
            logging.error(f"Failed to handle screen notification: {e}")

    async def _handle_agent_notification(self, data: bytes) -> None:
        """Handle agent status notifications — detect userid changes for mDNS."""
        try:
            msg = jsonw.loads(data)
            method = msg.get("method", "")
            if method != "notify_mqtt_agent_status":
                return
            params = msg.get("params", [])
            if not params or not isinstance(params, list):
                return
            agent_userid = params[0].get("userid", "")
            if agent_userid != self._last_mdns_userid:
                logging.info(
                    f"smclient: agent userid changed '{self._last_mdns_userid}'"
                    f" -> '{agent_userid}', updating mDNS")
                self._last_mdns_userid = agent_userid
                self.server.send_event(
                    "snapmaker:update_mdns_info", {'userid': agent_userid})
        except Exception as e:
            logging.error(f"Failed to handle agent notification: {e}")

    # ==================================================================
    # MQTT helper – unified call to unisrv
    # ==================================================================

    async def _call_unisrv(self, method: str, params: dict = None,
                           timeout: int = 10, qos: int = 1) -> Optional[dict]:
        if self.mqtt is None:
            logging.warning(f"client_manager: mqtt not available, cannot call {method}")
            return None
        req_id = random.randint(0, 0x7FFFFFFF)
        req = {"jsonrpc": "2.0", "method": method, "id": req_id}
        if params:
            req["params"] = params

        # Subscribe and match by JSON-RPC id ourselves. moonraker's
        # publish_topic_with_response doesn't filter by id, so concurrent
        # calls would race and resolve each other's future with the wrong body.
        resp_fut: asyncio.Future = asyncio.get_event_loop().create_future()

        def _on_resp(raw: bytes) -> None:
            if resp_fut.done():
                return
            try:
                msg = jsonw.loads(raw)
            except Exception:
                return
            if msg.get("id") == req_id:
                resp_fut.set_result(raw)

        hdl = self.mqtt.subscribe_topic("mqtt_agent/response", _on_resp, qos=qos)
        try:
            await self.mqtt.publish_topic("mqtt_agent/request", req, qos=qos)
            resp_raw = await asyncio.wait_for(resp_fut, timeout=timeout)
        except asyncio.TimeoutError:
            logging.warning(f"client_manager: {method} no response in {timeout}s")
            return None
        finally:
            self.mqtt.unsubscribe(hdl)

        try:
            resp = jsonw.loads(resp_raw)
        except Exception as e:
            logging.warning(
                f"client_manager: {method} bad json response: {resp_raw!r} ({e})"
            )
            return None
        if "error" in resp:
            logging.warning(f"client_manager: {method} returned error: {resp['error']}")
        return resp

    # ==================================================================
    # Query helpers – used by external components
    # ==================================================================

    def get_userid(self) -> str:
        try:
            with open(self.client_cfg_path, "r") as f:
                cfg = json.load(f)
            return cfg.get("userid", "")
        except Exception:
            return ""

    def get_link_mode(self) -> int:
        try:
            with open(self.client_cfg_path, "r") as f:
                val = json.load(f).get("link_mode", LINK_MODE_CLOUD)
            if isinstance(val, str):
                return 1 if val.lower() == "lan" else 0
            if val is None:
                return LINK_MODE_CLOUD
            return int(val)
        except Exception:
            return LINK_MODE_CLOUD

    def get_access_code(self) -> int:
        try:
            with open(self.client_cfg_path, "r") as f:
                return json.load(f).get("access_code", DEFAULT_CODE)
        except Exception:
            return DEFAULT_CODE

    def get_region(self) -> str:
        try:
            with open(self.client_cfg_path, "r") as f:
                return json.load(f).get("region", "")
        except Exception:
            return ""

    def _local_info(self) -> Dict[str, Any]:
        """Fallback for _handle_get_info when unisrv is unreachable at boot;
        reads the same client.json that unisrv persists to."""
        try:
            with open(self.client_cfg_path, "r") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        return {
            "state": "success",
            "access_code": str(cfg.get("access_code", DEFAULT_CODE)),
            "link_mode": self.get_link_mode(),
            "userid": cfg.get("userid", ""),
            "username": cfg.get("username", ""),
            "region": cfg.get("region", ""),
            "client_count": len(cfg.get("clients", {})),
        }

    # ==================================================================
    # Factory reset (called from server.py)
    # ==================================================================

    async def handle_factory_reset(self):
        # C++ LanManager::FactoryReset() handles state reset,
        # cert regeneration, and config file writing.
        await self._call_unisrv("mqtt_agent.factory_reset", timeout=5, qos=0)

    # ==================================================================
    # GUI endpoints – forward to unisrv, C++ handles notifications
    # ==================================================================

    async def _handle_get_info(self, web_request: WebRequest) -> Dict[str, Any]:
        resp = await self._call_unisrv("lan_manager.get_info")
        if resp and "result" in resp:
            return resp["result"]
        logging.warning("client_manager: unisrv unreachable, falling back to local client.json")
        return self._local_info()

    async def _handle_refresh_access_code(self, web_request: WebRequest
                                          ) -> Dict[str, Any]:
        return {"state": "success",
                "access_code": str(self.get_access_code())}

    async def _handle_refresh_pin_code(self, web_request: WebRequest
                                       ) -> Dict[str, Any]:
        if self.get_link_mode() != LINK_MODE_CLOUD:
            return {"state": "error", "message": "device is in LAN mode"}
        resp = await self._call_unisrv("mqtt_agent.refresh_auth_code", timeout=25)
        if resp and "result" in resp:
            return resp["result"]
        return {"state": "failed", "message": "unable to refresh pin code"}

    async def _handle_set_link_mode(self, web_request: WebRequest
                                    ) -> Dict[str, Any]:
        mode = web_request.get_int("link_mode", 0)
        mode_str = "lan" if mode > 0 else "wan"
        # C++ SetLinkMode publishes notify_logout + notify_link_mode_update
        resp = await self._call_unisrv("mqtt_agent.set_link_mode",
                                        {"link_mode": mode_str})
        if resp and resp.get("result", {}).get("state") == "success":
            userid = self.get_userid()
            self._last_mdns_userid = userid
            self.server.send_event("snapmaker:update_mdns_info",
                                   {'link_mode': mode_str,
                                    'userid': userid})
            return {"state": "success", "link_mode": mode}
        return {"state": "error", "message": "failed"}

    async def _handle_set_region(self, web_request: WebRequest
                                 ) -> Dict[str, Any]:
        region = web_request.get_str("region", "")
        resp = await self._call_unisrv("mqtt_agent.set_region",
                                        {"region": region})
        if resp and resp.get("result", {}).get("state") == "success":
            self._last_mdns_userid = ""
            self.server.send_event("snapmaker:update_mdns_info",
                                   {'region': region, 'userid': ""})
            return {"state": "success", "region": region}
        return {"state": "error", "message": "failed"}

    async def _handle_logout(self, web_request: WebRequest
                             ) -> Dict[str, Any]:
        # C++ Logout() publishes notify_logout notification
        resp = await self._call_unisrv("mqtt_agent.logout", timeout=15, qos=2)
        if resp and resp.get("result"):
            self._last_mdns_userid = ""
            self.server.send_event("snapmaker:update_mdns_info", {'userid': ""})
            return resp["result"]
        return {"state": "error", "message": "logout failed"}

    async def _handle_approve_connection(self, web_request: WebRequest
                                         ) -> Dict[str, Any]:
        clientid = web_request.get_str("clientid", "")
        userid = web_request.get_str("userid", "")
        app_id = web_request.get_str("app_id", "")
        username = web_request.get_str("username", "")
        approve = web_request.get_int("approve", 0) > 0
        is_lan = clientid != "" and userid == ""

        if not clientid and userid in ("", "none"):
            return {"state": "error", "message": "must specify clientid or userid"}

        # Both approve and reject go through C++.
        # C++ HandleLanAuth / HandleCloudAuth publish the ack notification.
        params = {
            "clientid": clientid, "userid": userid,
            "app_id": app_id, "username": username,
            "approve": approve, "is_lan": is_lan,
        }
        resp = await self._call_unisrv("lan_manager.approve", params, timeout=15)
        if resp and resp.get("result"):
            # mDNS userid is updated via notify_mqtt_agent_status after the
            # cloud confirms the binding with set_userinfo — not here.
            return {"state": "success"}
        return {"state": "error", "message": "approve failed"}

    async def _handle_disconnection_all(self, web_request: WebRequest
                                        ) -> Dict[str, Any]:
        # C++ DisconnectAll() publishes notify_disconnecting_lan_clients
        resp = await self._call_unisrv("lan_manager.disconnect_all")
        if resp and resp.get("result", {}).get("state") == "success":
            return {"state": "success"}
        return {"state": "error", "message": "disconnect failed"}


def load_component(config: ConfigHelper) -> ClientManager:
    return ClientManager(config)
