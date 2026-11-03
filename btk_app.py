







import base64
import csv
import hashlib
import math
import os
import queue
import re
import socket
import threading
import time
import tkinter as tk
from collections import Counter
from datetime import datetime
from difflib import unified_diff
from importlib.resources import files
from io import StringIO
from ipaddress import ip_interface
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import quote

import requests
import urllib3
import yaml

CONFIG_FILE = Path(__file__).with_name("config.yaml")
SSH_HOST_KEY_LOCK = threading.Lock()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_settings(path=CONFIG_FILE):
    '''Read application settings; timing values are positive seconds.'''
    settings = {
        "default_window_size": "1024x768",
        "minimum_window_size": "1000x600",
        "request_timeout": 15,
        "paged_timeout": 60,
        "token_refresh_interval": 60,
        "token_refresh_retry": 10,
        "default_token_lifetime": 600,
    }
    try:
        with open(path, encoding="utf-8") as source:
            data = yaml.safe_load(source) or {}
    except FileNotFoundError:
        return settings
    if not isinstance(data, dict) or not isinstance(data.get("settings", {}), dict):
        raise ValueError("Config must contain a mapping with an optional 'settings' mapping.")
    settings.update({key: value for key, value in data.get("settings", {}).items() if key in settings})
    for key, value in settings.items(): 
        if key.endswith("window_size"):
            if not isinstance(value, str) or not re.fullmatch(r"[1-9]\d*x[1-9]\d*", value):
                raise ValueError(f"settings.{key} must use WIDTHXHEIGHT, for example '1024x768'.")
        elif isinstance(value,bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <=0:
            raise ValueError(f"settings.{key} must be a positive number of seconds.")
    default_size = tuple(int (part) for part in settings ["default_window_size"].split("x"))
    minimum_size = tuple(int (part) for part in settings ["minimum_window_size"].split("x"))
    if any (minimum > default for minimum, default in zip(minimum_size, default_size)):
        raise ValueError("settings.minimum_window_size cannot exceed settings.default_window_size.")
    return settings


APP_SETTINGS = load_settings()
DEFAULT_WINDOW_SIZE = APP_SETTINGS["default_window_size"]
MINIMUM_WINDOW_SIZE = tuple(int(part) for part in APP_SETTINGS["minimum_window_size"].split("x"))
REQUEST_TIMEOUT = APP_SETTINGS["request_timeout"]
PAGED_TIMEOUT = APP_SETTINGS["paged_timeout"]
TOKEN_REFRESH_INTERVAL = APP_SETTINGS["token_refresh_interval"]
TOKEN_REFRESH_RETRY = APP_SETTINGS["token_refresh_retry"]
DEFAULT_TOKEN_LIFETIME = APP_SETTINGS["default_token_lifetime"]


def _credentials(entry, default=None):
    """Return (username, password) from a config block; password_env wins over password"""
    default = default or ("", "")
    if not isinstance(entry, dict):
        return default
    username = str(entry.get("username") or default[0] or "")
    if entry.get("password_env"):
        password = os.environ.get(str(entry["password_env"]), "")
    elif entry.get("password") is not None:
        password = str(entry["password"])
    else:
        password = default[1]
    return username, password


def load_apics(path=CONFIG_FILE):
    """Return a list of dicts: {name, url, verify_ssl, username, password}."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    default_creds = _credentials(data.get("credentials"))
    apics = []
    for entry in data.get("apics", []):
        if isinstance(entry, str):
            entry = {"name": entry, "url": entry}
        url = str(entry["url"]).rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        username, password = _credentials(entry, default_creds)
        apics.append({
            "name": entry.get("name", url),
            "url": url,
            "verify_ssl": bool(entry.get("verify_ssl", False)),
            "username": username,
            "password": password,
        })
    return apics


class APICSession:
    """Minimal APIC REST session handling aaaLogin/aaaRefresh/aaaLogout."""

    def __init__(self, url, verify_ssl=False):
        self.url = url
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = None
        self.refresh_timeout = DEFAULT_TOKEN_LIFETIME

    @staticmethod
    def _imdata(resp):
        try:
            body = resp.json()
        except ValueError:
            resp.raise_for_status()
            raise RuntimeError(f"Unexpected response from APIC (HTTP {resp.status_code})")
        imdata = body.get("imdata", [])
        if imdata and "error" in imdata[0]:
            attrs = imdata[0]["error"]["attributes"]
            raise RuntimeError(f"APIC error {attrs.get('code')}: {attrs.get('text')}")
        resp.raise_for_status()
        return imdata

    def _store_token(self, imdata):
        attrs = imdata[0]["aaaLogin"]["attributes"]
        self.token = attrs["token"]
        self.refresh_timeout = int(attrs.get("refreshTimeoutSeconds", DEFAULT_TOKEN_LIFETIME))
        self.session.cookies.set("APIC-cookie", self.token)
        return attrs

    def login(self, username, password):
        payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
        resp = self.session.post(f"{self.url}/api/aaaLogin.json", json=payload, timeout=REQUEST_TIMEOUT)
        return self._store_token(self._imdata(resp))

    def refresh(self):
        resp = self.session.get(f"{self.url}/api/aaaRefresh.json", timeout=REQUEST_TIMEOUT)
        return self._store_token(self._imdata(resp))
    
    def logout(self, username):
        payload = {"aaaUser": {"attributes": {"name": username}}}
        try:
            resp = self.session.post(f"{self.url}/api/aaaLogout.json", json=payload, timeout=REQUEST_TIMEOUT)
            self._imdata(resp)
        finally:
            self.token = None
            self.session.cookies.clear()

    def get (self, path, timeout=REQUEST_TIMEOUT, **params):
        """GET helper for further API calls, e.g. get('/api/class/fvTenant.json')."""
        resp = self.session.get(f"{self.url}{path}", params=params, timeout=timeout)
        return self._imdata(resp)

    def get_all(self, path, page_size=10000, **params):
        """GET with APIC paging, for classes that can return very many objects."""
        out, page = [], 0
        while True:
            chunk = self.get(path, timeout=PAGED_TIMEOUT, page=page, **{"page-size": page_size}, **params)
            out.extend(chunk)
            if len(chunk) < page_size:
                return out
            page += 1
    

def _attrs(imdata, cls):
    return [obj[cls]["attributes"] for obj in imdata if cls in obj]


def _format_last_flap(value):
    if not value:
        return ""
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return timestamp.strftime("%Y.%m.%d - %H:%M:%S")


def get_bgp_peers(session) :







    peers = _attrs(session.get("/api/class/bgpPeer.json"), "bgpPeer")
    entries = _attrs(session.get("/api/class/bgpPeerEntry.json"), "bgpPeerEntry")
    af_entries = _attrs(session.get("/api/class/bgpPeerAfEntry.json"), "bgpPeerAfEntry")

    afs_by_entry = {}
    for af in af_entries:
        afs_by_entry.setdefault(af["dn"].rsplit("/af-", 1)[0], []).append(af)
    entries_by_peer = {}
    for ent in entries:
        entries_by_peer.setdefault(ent["dn"].rsplit("/ent-", 1)[0], []).append(ent)
    
    rows = []
    for peer in peers:
        node = re.search(r"/node-(\d+)/", peer["dn"])
        vrf = re.search(r"/dom-([^/]+)", peer["dn"])
        for ent in entries_by_peer.get(peer["dn"]) or [{}]:
            afs = afs_by_entry.get(ent.get("dn"), [])
            rows.append ({
                "node": node.group(1) if node else"",
                "vrf": vrf.group(1) if vrf else "",
                "peer": ent.get("addr") or re.sub(r"/(32|128)$", "", peer.get("addr", "")),
                "asn": peer.get("asn", ""),
                "state": ent.get("operSt", "not-created" if not ent else ""),
                "type": ent.get("type", ""),
                "local_ip": ent.get("localIp", ""),
                "router_id": ent.get("rtrId", ""),
                "last_flap": _format_last_flap(ent.get("lastFlapTs", "")),
                "pfx_rcvd": sum(int(af.get("acceptedPaths") or 0) for af in afs),
                "pfx_sent": sum(int(af.get("pfxSent") or 0) for af in afs),
                "details": {"bgpPeer": peer, "bgpPeerEntry": ent,
                            **{f"bgpPeerAfEntry ({af.get('type')})": af for af in afs}},
            })
    rows.sort(key=lambda r: (int(r["node"] or 0), r["vrf"], r["peer"]))
    return rows


BGP_ROUTE_COLUMNS = (
    ("status", "Status", 60), ("path selection", "Selection", 70), 
    ("route_source", "Source", 60), ("prefix", "Prefix", 180), 
    ("next_hop", "Next hop", 150), ("metric", "Metric", 80), 
    ("local_pref", "Local preference", 110), ("weight", "Weight", 80), 
    ("as_path", "AS path", 260), ("origin", "Origin", 60),
)


def normalize_bgp_routes(parsed):
    if not isinstance(parsed, list) or any(not isinstance(row, dict) for row in parsed):
        raise ValueError("TextFSM did not return structured BGP routes; the NX-OS template may not match this BTK output.")
    rows = []
    for record in parsed:
        if not record.get("prefix") or not record.get("prefix_length"):
            raise ValueError("TextFSM returned a route without a prefix or prefix length.")
        prefix = str(ip_interface(f"{record['prefix']}/{record['prefix_length']}").network)
        rows.append({key: prefix if key == "prefix" else record.get(key, "")
                    for key, _title, _width in BGP_ROUTE_COLUMNS})
    return rows


def read_bgp_routes_csv(path):
    required = [col[0] for col in BGP_ROUTE_COLUMNS]
    with open(path, newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source, strict=True)
        if not reader.fieldnames or not set(required).issubset(reader.fieldnames):
            raise ValueError("The CSV is not a BTK BGP-table export (missing required columns).")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("The CSV contains duplicate column names.")
        rows = []
        for record in reader:
            if None in record or any(record.get(key) is None for key in required):
                raise ValueError(f"Incomplete or malformed CSV row at line {reader.line_num}.")
            row = {key: record[key] for key in required}
            prefix = row["prefix"].strip()
            if "/" not in prefix:
                raise ValueError(f"Missing prefix length at line {reader.line_num}.")
            row["prefix"] = str(ip_interface(prefix).network)
            rows.append(row)
    return rows


def build_bgp_diff(saved, current, saved_name="Saved CSV"):
    keys = [col[0] for col in BGP_ROUTE_COLUMNS]

    def lines(rows):
        output = StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=keys, lineterminator="\n")
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: (row["prefix"], row["next_hop"],
                                                       tuple(row[key] for key in keys))))
        return output.getvalue().splitlines(keepends=True)

    return "".join(unified_diff(lines(saved), lines(current), fromfile=saved_name, tofile="Current BGP table"))


def verify_ssh_host_key(host, confirm_key=None, known_hosts_path=None):
    from paramiko import HostKeys, Transport

    path = Path(known_hosts_path) if known_hosts_path is not None else Path.home() / ".ssh" / "known_hosts"

    def load_keys():
        keys = HostKeys()
        if path.exists():
            keys.load(str(path))
        return keys
    
    def is_trusted(keys, key):
        if keys.lookup(host) is None:
            return False
        if not keys.check(host, key):
            raise RuntimeError(f"SSH host key changed for {host}. Connection blocked. "
                              "Verify the new fingerprint independently before updating known_hosts.")
        return True

    known = load_keys()
    with socket.create_connection((host, 22), timeout=REQUEST_TIMEOUT) as sock:
        with Transport(sock) as transport:
            existing = known.lookup(host)
            if existing:
                options = transport.get_security_options()
                preferred = [name for name in options.key_types if name in existing]
                options.key_types = preferred + [name for name in options.key_types if name not in existing]
            transport.start_client(timeout=REQUEST_TIMEOUT)
            key = transport.get_remote_server_key()
    if is_trusted(known, key):
        return
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
    if confirm_key is None or not confirm_key(host, key.get_name(), fingerprint):
        raise RuntimeError(f"SSH host key for {host} was not accepted. Connection cancelled.")
    with SSH_HOST_KEY_LOCK:
        if is_trusted(load_keys(), key):
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as output:
            output.seek(0)
            contents = output.read()
            output.seek(0, os.SEEK_END)
            if contents and not contents.endswith("\n"):
                output.write("\n")
            output.write(f"{host} {key.get_name()} {key.get_base64()}\n")


def get_bgp_received_routes(session, row, username, password, advertised=False, parsed=True, neighbor_info=False, 
                           confirm_key=None):
    """Retrieve IPv4 BGP routes or raw neighbor information over SSH."""
    if neighbor_info:
        parsed = False
    peer = row["details"].get("bgpPeer", {})
    entry = row["details"].get("bgpPeerEntry", {})
    node = re.match(r"topology/pod-(\d+)/node-(\d+)/", peer.get("dn") or entry.get ("dn", ""))
    if not node:
        raise ValueError("Cannot determine the peer's leaf and pod from its DN.")
    neighbor = ip_interface(row["peer"]).ip
    if neighbor.version != 4:
        raise ValueError("This command supports IPv4 neighbors only.")
    vrf = row["vrf"]
    if not re.fullmatch(r" [A-Za-z0-9_.:-]+", vrf):
        raise ValueError("The VRF name contains unsupported CLI characters.")
    pod_id, node_id = node.groups()
    systems = _attrs(session.get(f"/api/node/mo/topology/pod-{pod_id}/node-{node_id}/sys.json"), "topSystem")
    if not systems or not systems[0].get("oobMgmtAddr"):
        raise ValueError(f"No OOB management address found for leaf {node_id} in pod {pod_id}.")
    host = ip_interface(systems[0]["oobMgmtAddr"]).ip
    if host.is_unspecified:
        raise ValueError(f"Leaf {node_id} has no usable OOB management address.")
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError("BGP retrieval requires Netmiko. Install the BTK requirements in your Python environment.") from exc
    parse_options = {"use_textfsm": False}
    if parsed:
        try:
            template = files("ntc_templates").joinpath(
                "templates", "cisco_nxos_show_bgp_vrf_all_ipv4_unicast_neighbors_routes.textfsm")
        except ImportError as exc:
            raise RuntimeError("Parsed BGP retrieval requires ntc-templates. Install the BTK requirements.") from exc
        if not template.is_file():
            raise RuntimeError("The installed ntc-templates package lacks the NX-OS BGP neighbor routes template.")
        parse_options = {"use_textfsm": True, "textfsm_template": str(template), "raise_parsing_error": True}
    route_command = "advertised-routes" if advertised else "routes"
    if neighbor_info:
        command = f"show bgp ipv4 unicast neighbors {neighbor} vrf {vrf}"
    else:
        command = f"show bgp ipv4 unicast neighbors {neighbor} {route_command} vrf {vrf}"
    verify_ssh_host_key(str(host), confirm_key)
    with ConnectHandler(device_type="cisco_nxos", host=str(host), username=username, password=password,
                        ssh_strict=True, system_host_keys=True, conn_timeout=REQUEST_TIMEOUT,
                        auth_timeout=REQUEST_TIMEOUT, banner_timeout=REQUEST_TIMEOUT) as connection:
        output = connection.send_command(command, read_timeout=PAGED_TIMEOUT,
                                         strip_prompt=True, strip_command=True, **parse_options)
    return str(host), command, normalize_bgp_routes(output) if parsed else output


class BGPReceivedRoutes(ttk.Frame):
    def __init__(self, master, app, session, row, advertised=False, neighbor_info=False):
        super().__init__(master, padding=8)
        self.app, self.session, self.row = app, session, row
        self.advertised = advertised
        self.neighbor_info = neighbor_info
        self.route_label = "BGP neighbor" if neighbor_info else ("Advertised routes" if advertised else "Received routes")
        self.rows = []
        self.results = queue.Queue()
        self._closed = threading.Event()
        self.bind("<Destroy>", lambda event: self._closed.set () if event.widget is self else None)
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="SSH username:").grid(row=0, column=0, sticky="w")
        self.username = tk.StringVar(value=app.username or "")
        ttk.Entry(bar, textvariable=self.username, width=24).grid(row=0, column=1, padx=6, pady=3)
        ttk.Label(bar, text="SSH password:").grid(row=1, column=0, sticky="w")
        self.password = tk.StringVar()
        password_entry = ttk.Entry(bar, textvariable=self.password, show="*", width=24)
        password_entry.grid(row=1, column=1, padx=6, pady=3)
        password_entry.bind("<Return>", lambda _event: self.retrieve())
        self.retrieve_btn = ttk.Button(bar, text=f"Retrieve {self.route_label.lower()}", command=self.retrieve)
        self.retrieve_btn.grid(row=0, column=2, rowspan=2, padx=6)
        self.export_btn = ttk.Button(bar, text="Export CSV", command=self.export, state="disabled")
        self.export_btn.grid(row=0, column=3, rowspan=2, padx=6)
        self.compare_btn = ttk.Button(bar, text="Compare CSV", command=self.compare, state="disabled")
        self.compare_btn.grid(row=0, column=4, rowspan=2, padx=6)
        mode_bar = ttk.Frame(self)
        mode_bar.pack(fill="x", pady=(0, 6))
        ttk.Label(mode_bar, text="Output:").pack(side="left")
        self.mode = tk.StringVar(value="raw" if neighbor_info else "parsed")
        self.mode_buttons = []
        for value, label in (("raw", "Raw"), ("parsed", "Parsed")):
            button = ttk.Radiobutton(mode_bar, text=label, value=value, variable=self.mode,
                                     command=self._change_mode)
            button.pack(side="left", padx=6)
            self.mode_buttons.append(button)
        if neighbor_info:
            mode_bar.pack_forget()
        self.status = tk.StringVar(value="Not retrieved yet")
        ttk.Label(self, textvariable=self.status, wraplength=900).pack(anchor="w", pady=(0, 6))
        content = ttk.Frame(self)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)
        self.parsed_frame = ttk.Frame(content)
        self.parsed_frame.grid(row=0, column=0, sticky="nsew")
        self.tree = build_route_tree(self.parsed_frame, BGP_ROUTE_COLUMNS)
        self.raw_frame = ttk.Frame(content)
        self.raw_frame.grid(row=0, column=0, sticky="nsew")
        self.raw_frame.columnconfigure(0, weight=1)
        self.raw_frame.rowconfigure(0, weight=1)
        self.raw_output = tk.Text(self.raw_frame, wrap="none", font=("Menlo", 11), state="disabled")
        ysb = ttk.Scrollbar(self.raw_frame, orient="vertical", command=self.raw_output.yview)
        xsb = ttk.Scrollbar(self.raw_frame, orient="horizontal", command=self.raw_output.xview)
        self.raw_output.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.raw_output.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        self.fetching = False
        self.loaded = False
        self._change_mode()

    def _change_mode(self):
        if self.neighbor_info:
            self.mode.set("raw")
        self.loaded = False
        self.rows = []
        self.tree.delete(*self.tree.get_children())
        self.raw_output.configure(state="normal")
        self.raw_output.delete("1.0", "end")
        self.raw_output.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.compare_btn.configure(state="disabled")
        self.status.set("Not retrieved yet")
        if self.mode.get() == "raw":
            self.parsed_frame.grid_remove()
            self.raw_frame.grid()
            self.export_btn.grid_remove()
            self.compare_btn.grid_remove()
        else:
            self.raw_frame.grid_remove()
            self.parsed_frame.grid()
            self.export_btn.grid()
            self.compare_btn.grid()

    def _confirm_ssh_key(self, host, key_type, fingerprint):
        request = {"host": host, "key_type": key_type, "fingerprint": fingerprint,
                   "approved": False, "done": threading.Event()}
        self.results.put((None, request)) 
        while not request["done"].wait(0.2):
            if self._closed.is_set():
                return False
        return request["approved"] and not self._closed.is_set()

    def retrieve(self):
        if self.fetching:
            return
        if self.session is None or self.session is not self.app.apic_session:
            messagebox.showwarning(self.route_label, "Reopen the peer from the current APIC session.", parent=self)
            return
        username, password = self.username.get().strip(), self.password.get()
        if not username or not password:
            messagebox.showwarning(self.route_label, "Enter the leaf SSH username and password.", parent=self)
            return
        self.password.set("")
        self.fetching = True
        self.loaded = False
        parsed = self.mode.get() == "parsed"
        for button in self.mode_buttons:
            button.configure(state="disabled")
        self.retrieve_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.compare_btn.configure(state="disabled")
        self.rows = []
        self.tree.delete(*self.tree.get_children())
        self.raw_output.configure(state="normal")
        self.raw_output.delete("1.0", "end")
        self.raw_output.configure(state="disabled")
        self.status.set(f"Looking up leaf {self.row['node']} OOB address and retrieving {self.route_label.lower()} over SSH...")

        def worker():
            try:
                self.results.put((True, get_bgp_received_routes(
                    self.session, self.row, username, password, advertised=self.advertised,
                    parsed=parsed, neighbor_info=self.neighbor_info, confirm_key=self._confirm_ssh_key)))
            except Exception as exc:
                self.results.put ((False, exc))

        threading.Thread(target=worker, daemon=True).start()
        self.app.after(100, self._poll)

    def _poll(self):
        if not self.winfo_exists():
            return
        try:
            ok, value = self.results.get_nowait()
        except queue.Empty:
            self.app.after(100, self._poll)
            return
        if ok is None:
            try:
                if self.session is self.app.apic_session:
                    approved = messagebox.askyesno(
                        "Trust SSH host key?",
                        f"Node {self.row['node']} at {value['host']} has an unknown SSH key.\n\n"
                        f"Key type: {value['key_type']}\nFingerprint: {value['fingerprint']}\n\n"
                        "Verify this fingerprint independently before accepting.\n"
                        "Accept and save this key to ~/.ssh/known_hosts?",
                        parent=self, default=messagebox.NO)
                    value["approved"] = approved and self.session is self.app.apic_session and not self._closed.is_set()
            except tk.TclError:
                value["approved"] = False
            finally:
                value["done"].set()
            if not self._closed.is_set():
                self.app.after(100, self._poll)
            return
        self.fetching = False
        for button in self.mode_buttons:
            button.configure(state="normal")
        self.retrieve_btn.configure(state="normal")
        if self.session is not self.app.apic_session:
            self.status.set("APIC session changed. Reopen the peer to retrieve routes.")
            return
        if not ok:
            self.status.set(f"{self.route_label} retrieval failed") 
            messagebox.showerror(self.route_label, f"Could not retrieve {self.route_label.lower()}:\n{value}", parent=self)
            return
        host, command, output = value
        self.loaded = True
        if self.mode.get() == "raw":
            self.raw_output.configure(state="normal")
            self.raw_output.insert("1.0", output)
            self.raw_output.configure(state="disabled")
            self.status.set(f"{host} - {command}")
            return
        self.rows = output
        for row in self.rows:
            self.tree.insert("", "end", values=[row[key] for key, _title, _width in BGP_ROUTE_COLUMNS])
        count = len({row["prefix"] for row in self.rows})
        self.status.set(f"{host} - {command} - {count} prefixes / {len(self.rows)} paths")
        self.export_btn.configure(state="normal") 
        self.compare_btn.configure(state="normal")

    def export(self):
        if self.mode.get() != "parsed" or not self.loaded:
            return
        direction = "ADV" if self.advertised else "RCV"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        peer = str(ip_interface(self.row["peer"]).ip)
        filename = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{direction}_{self.row['vrf']}_{peer}_{timestamp}.csv")
        path = Path(__file__).with_name("bgp_tables") / filename
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.DictWriter(output, fieldnames=[col[0] for col in BGP_ROUTE_COLUMNS])
                writer.writeheader()
                writer.writerows(self.rows)
        except (OSError, csv.Error) as exc:
            messagebox.showerror("Export CSV", f"Could not export BGP routes;\n{exc}", parent=self)
            return
        self.status.set(f"Exported {len (self.rows)} rows to {path}")

    def compare(self):
        if self.mode.get() != "parsed" or not self.loaded:
            return
        path = filedialog.askopenfilename(parent=self, title=f"Compare {self.route_label.lower()}",
                                          initialdir=str(Path(__file__).with_name("bgp_tables")),
                                          filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            saved = read_bgp_routes_csv(path)
            changes = compare_routing_tables(saved, self.rows, columns=BGP_ROUTE_COLUMNS, identity="prefix")
        except (OSError, UnicodeError, csv.Error, ValueError) as exc:
            messagebox.showerror("Compare BGP tables", f"Could not compare BGP tables:\n{exc}", parent=self)
            return
        if not changes:
            messagebox.showinfo("Compare BGP tables", "The saved and current BGP tables match.", parent=self)
            return
        win = tk.Toplevel(self)
        win.title(f"{self.route_label} changes - {self.row['vrf']} / {self.row['peer']} - {Path(path).name}")
        win.geometry(DEFAULT_WINDOW_SIZE)
        counts = {label: len({row["prefix"] for row in changes if row["change"] == label})
                  for label in ("Added", "Removed", "Changed (current)")}
        ttk.Label(win, text=f"{counts['Added']} added / {counts ['Removed']} removed / "
                           f"{counts['Changed (current) ']} changed prefixes",
                  padding=8).pack(anchor="w")
        explanation = ttk.Label(
            win, justify="left", wraplength=1150, padding=(8, 0, 8, 8),
            text="Baseline: selected CSV. Current: last retrieved table, not a live refresh.\n"
                 "Added: only in current. Removed: only in saved. Changed: a path or attribute differs; "
                 "'Changed (saved)' and 'Changed (current)' show before and after.\n"
                 "Diff: red '-' Lines are saved values; green '+' lines are current values. "
                 "A modified row appears as a removal followed by an addition.\n"
                 "Counts refer to prefixes, not paths; row order is ignored. "
                 "Choose a CSV for the same leaf, VRF, peer and direction.")
        explanation.pack(fill="x")
        win.bind("<Configure>", lambda event: explanation.configure(wraplength=max(800, event.width - 32))
                 if event.widget is win else None)
        tabs = ttk.Notebook(win)
        tabs.pack(fill="both", expand=True)
        changes_page = ttk.Frame(tabs)
        diff_page = ttk.Frame(tabs)
        tabs.add(changes_page, text="Changes")
        tabs.add(diff_page, text="Diff")
        columns = (("change", "Change", 150),) + BGP_ROUTE_COLUMNS
        tree = build_route_tree(changes_page, columns)
        tree.tag_configure("Added", foreground="#1e8e3e")
        tree.tag_configure("Removed", foreground="#d93025")
        tree.tag_configure("Changed (saved)", foreground="#777777")
        for row in changes:
            tree.insert("", "end", values=[row[col[0]] for col in columns], tags=(row["change"],))
        diff_page.columnconfigure(0, weight=1)
        diff_page.rowconfigure(0, weight=1)
        text = tk.Text(diff_page, wrap="none", font=("Menlo", 11))
        ysb = ttk.Scrollbar(diff_page, orient="vertical", command=text.yview)
        xsb = ttk.Scrollbar(diff_page, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        text.tag_configure("added", foreground="#17632d",  background="#e6f4ea")
        text.tag_configure("removed", foreground="#a61c1c",  background="#fce8e6")
        text.tag_configure("header", foreground="#555555")
        for line in build_bgp_diff(saved, self.rows, Path(path).name).splitlines(keepends=True):
            if line.startswith(("---", "+++", "@@")):
                tag = "header"
            elif line.startswith("+"):
                tag = "added"
            elif line.startswith("-"):
                tag = "removed"
            else:
                tag = ""
            text.insert("end", line, (tag,) if tag else ())
        text.configure(state="disabled")


ROUTE_DN = re.compile(r"/node-(\d+)/sys/uribv([46])/dom-([^/]+)/db-rt/rt-\[(.+)\]$")
# VRFs whose switch-side routing domain name is not "<tenant>:<vrf>".
SPECIAL_DOMS = {("infra", "overlay-1"): "overlay-1", ("mgmt", "oob"): "management"}
# fvCtx attributes left out of the VRF details: VNID, enforcement, direction, description.
VRF_HIDDEN_ATTRS = {"scope", "seg", "pcTag", "pcEnfPref", "pcEnfDir", "pcEnfDirUpdated", "descr"}


def get_l3outs(session):
    """Collect all L3Outs with their tenant and tenant-free VRF name."""
    objects = session.get_all("/api/class/l3extOut.json", **{
        "rsp-subtree": "children", "rsp-subtree-class": "l3extRsEctx", "order-by": "l3extOut.dn",
    })
    rows = []
    for obj in objects:
        out = obj.get("l3extOut")
        if not out:
            continue
        attrs = out["attributes"]
        match = re.fullmatch(r"uni/tn-([^/]+)/out-([^/]+)", attrs.get("dn", ""))
        if not match:
            continue
        tenant, name = match.groups()
        relations = _attrs(out.get("children", []), "l3extRsEctx")
        relation = relations[0] if relations else {}
        target = re.fullmatch(r"uni/tn-[^/]+/ctx-(.+)", relation.get("tDn", ""))
        vrf = target.group(1) if target else relation.get("tnFvCtxName", "")
        row = {"tenant": tenant, "l3out": attrs.get("name") or name, "vrf": vrf.split(":", 1)[-1]}
        row["details"] = {"L3Out": row.copy()}
        rows.append(row)
    rows.sort(key=lambda row: (row["tenant"].lower(), row["l3out"].lower()))
    return rows


def get_l3out_details(session, row):
    """Read the selected L3Out subtree and resolve referenced route-control policies."""
    dn = f"uni/tn-{row['tenant']}/out-{row['l3out']}"
    objects = session.get_all(f"/api/mo/{quote(dn, safe='/')}.json", **{"rsp-subtree": "full"})
    roots = [obj for obj in objects if "l3extOut" in obj]
    if not roots:
        raise RuntimeError("The selected L3Out was not returned by APIC. Refresh the L3Out list.")

    def walk(items, ancestors=()):
        for obj in items:
            for cls, body in obj.items():
                yield cls, body, ancestors
                yield from walk(body.get("children", []), ancestors + (cls,))

    pending, visited, linked, errors = list(roots), {dn}, [], []
    while pending:
        targets = set()
        for cls, body, _ancestors in walk(pending):
            target = body.get("attributes", {}).get("tDn", "")
            if cls.startswith(("rtctrlRs", "bgpRsPeerTo")) and target.startswith("uni/"):
                targets.add(target)
    pending = []
    for target in sorted(targets - visited):
        visited.add(target)
        try:
            policy = session.get_all(f"/api/mo/{quote(target, safe='/')}.json", **{"rsp-subtree": "full"})
            if not policy:
                errors.append((target, "Referenced policy was not returned by APIC."))
            linked.extend(policy) 
            pending.extend(policy)
        except Exception as exc:
            errors.append((target, str(exc)))

    sections = {name: [] for name in ("Details", "Node profiles", "Interface profiles", "Peers", "External EPGs", "Route maps")}
    for root in roots:
        body = root["l3extOut"]
        sections["Details"].append({"l3extOut": {
                "attributes": body.get("attributes", {}),
                "children": [child for child in body.get("children", []) if "l3extLNodeP" not in child],
        }})
    for cls, body, ancestors in walk(roots + linked):
        if cls == "l3extLNodeP":
            sections["Node profiles"].append({cls: body})
        elif cls == "l3extLIfP":
            sections["Interface profiles"].append({cls: body})
        elif cls == "bgpPeerP":
            sections["Peers"].append({cls: body})
        elif cls == "l3extInstP":
            sections["External EPGs"].append({cls: body})
        if cls.startswith("rtctrl") and not any(parent.startswith("rtctrl") for parent in ancestors):
            sections["Route maps"].append({cls: body})
        elif cls.startswith("bgpRsPeerTo"):
            sections["Route maps"].append({cls: body})
    return sections, errors


class L3OutDetails(ttk.Frame):
    def __init__(self, master, app, session, row):
        super().__init__(master, padding=8)
        self.app, self.session, self.row = app, session, row
        self.results = queue.Queue()
        self.peer_items = {}
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))
        self.refresh_btn = ttk.Button(bar, text="Refresh details", command=self.retrieve)
        self.refresh_btn.pack(side="left")
        self.status = tk.StringVar(value="Not retrieved yet")
        ttk.Label(self, textvariable=self.status, wraplength=960).pack(anchor="w", pady=(0, 6))
        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True)
        self.trees = {}
        for name in ("Details", "Node profiles", "Interface profiles", "Peers", "External EPGs", "Route maps"):
            page = ttk.Frame(tabs)
            tabs.add(page, text=name)
            page.columnconfigure(0, weight=1)
            page.rowconfigure(0, weight=1)
            tree = ttk.Treeview(page, columns=("value",), show="tree headings")
            tree.heading("#0", text="Object / Attribute")
            tree.heading("value", text="Value")
            tree.column("#0", width=400, minwidth=200, stretch=False)
            tree.column("value", width=700, minwidth=200)
            ysb = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
            xsb = ttk.Scrollbar(page, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
            tree.grid(row=0, column=0, sticky="nsew")
            ysb.grid(row=0, column=1, sticky="ns")
            xsb.grid(row=1, column=0, sticky="ew")
            self.trees[name] = tree
        self.trees["Peers"].bind("<Double-1>", self._open_selected_peer)
        self.fetching = False
        self.retrieve()

    def retrieve(self):
        if self.fetching:
            return
        if self.session is None or self.session is not self.app.apic_session:
            self.status.set("APIC session changed. Reopen the L3Out to retrieve details.")
            return
        self.fetching = True
        self.refresh_btn.configure(state="disabled")
        self.status.set("Retrieving L3Out profiles, interfaces, peers, External EPGs and route maps...")
        for tree in self.trees.values():
            tree.delete(*tree.get_children())

        def worker():
            try:
                self.results.put((True, get_l3out_details(self.session, self.row)))
            except Exception as exc:
                self.results.put ((False, exc))

        threading.Thread(target=worker, daemon=True).start()
        self.app.after(100, self._poll)

    @staticmethod
    def _insert_objects(tree, objects, parent="", excluded=(), peer_items=None):
        for obj in objects:
            for cls, body in obj.items():
                if cls in excluded:
                    continue
                attrs = body.get("attributes", {})
                label = attrs.get("name") or attrs.get("addr") or attrs.get("tDn") or cls
                peer_ip = ""
                if cls == "bgpPeerP":
                    raw_ip = attrs.get("addr") or attrs.get("peerAddr") or ""
                    try:
                        peer_ip = str(ip_interface(raw_ip).ip)
                        label = f"BGP neighbor: {peer_ip}"
                    except ValueError:
                        pass
                dn = attrs.get ("dn", "")
                context = " / ".join(f"{kind}: {name}" for kind, name in
                                     re.findall(r"/(lnodep|lifp)-([^/]+)", dn)) if not parent else ""
                title = f"{cls}: {label}" if label != cls else cls
                if context:
                    title += f" ({context})"
                item = tree.insert(parent, "end", text=title, values=(dn,), open=not parent)
                if peer_ip and peer_items is not None:
                    peer_items[item] = peer_ip
                for key, value in sorted(attrs.items()):
                    if value not in ("", None) and key.lower() not in {"password", "pwd", "authkey"}:
                        tree.insert(item, "end", text=key, values=(value,))
                L3OutDetails._insert_objects(tree, body.get("children", []), item, excluded, peer_items)

    def _open_selected_peer(self, event):
        tree = self.tree["Peers"]
        item = tree.identify_row(event.y)
        while item and item not in self.peer_items:
            item = tree.parent(item)
        if item:
            self.app.open_bgp_peer_details(self.peer_items[item], self.row["tenant"], self.row["vrf"])

    @staticmethod
    def _insert_external_epgs(tree, objects):
        scope_labels = {
            "import-security": "External subnets for the External EPG",
            "import-rtctrl": "Import route control subnet",
            "export-rtctrl": "Export route control subnet",
            "shared-security": "Shared security import subnet",
            "shared-rtctrl": "Shared route control subnet",
        }
        for obj in objects:
            body = obj["l3extInstP"]
            attrs = body.get("attributes", {})
            epg = tree.insert("", "end", text=f"External EPG: {attrs.get('name') or attrs.get('dn', '')}",
                              values=(attrs.get("descr", ""),), open=True)
            networks = tree.insert(epg, "end", text="Networks", open=True)
            count = 0
            for child in body.get("children", []):
                if "l3extSubnet" in child:
                    subnet = child["l3extSubnet"].get("attributes", {})
                    scope = set(filter(None, subnet.get("scope", "").split(",")))
                    network = tree.insert(networks, "end", text=subnet.get("ip", "Network"),
                                            values=(", ".join(scope_labels.get(flag, flag) for flag in sorted(scope)) or "No scope flags",),
                                            open=True)
                    for flag, label in scope_labels.items():
                        tree.insert(network, "end", text=label, values=("Yes" if flag in scope else "No",)) 
                    tree.insert(network, "end", text="Scope (APIC)", values=(subnet.get ("scope", ""),))
                    aggregate = subnet.get ("aggregate", "")
                    tree.insert(network, "end", text="Route aggregation", values=(
                        ", ".join(scope_labels.get(flag, flag) for flag in aggregate.split(",") if flag) or "None",))
                    if subnet.get("descr"):
                        tree.insert(network, "end", text="Description", values=(subnet["descr"],))
                    count += 1
                elif "fvRsProv" in child or "fvRsCons" in child:
                    cls = "fvRsProv" if "fvRsProv" in child else "fvRsCons"
                    contract = child[cls].get("attributes", {})
                    tree.insert(epg, "end", text="Provided contract" if cls == "fvRsProv" else "Consumed contract",
                                values=(contract.get("tnVzBrCPName") or contract.get("tDn", ""),))
            if not count:
                tree.insert(networks, "end", text="No configured networks")
            raw = tree.insert(epg, "end", text="Technical details", open=False)
            L3OutDetails._insert_objects(tree, [obj], raw)

    @staticmethod
    def _insert_route_maps(tree, objects):
        labels = {
            "rtctrlProfile": "Route map", "rtctrlCtxP": "Rule", "rtctrlSubjP": "Match list",
            "rtctrlMatchRtDest": "Prefix", "rtctrlAttrP": "Set actions",
            "rtctrlRsCtxPoSubjP": "Match list reference", "rtctrlRsScopeToAttrP": "Set actions reference",
            "bgpRsPeerToProfile": "Peer route map", "bgpRsPeerToProfileIn": "Inbound peer route map",
            "bgpRsPeerToProfileOut": "Outbound peer route map",
            "rtctrlSeRtMetric": "Set metric", "rtctrlSeRtMetricType": "Set metric type",
            "rtctrlSetPref": "Set local preference", "rtctrlSetWeight": "Set weight",
            "rtctrlSetASPath": "Set AS path", "rtctrlSetASPathASN": "AS number",
            "rtctrlSetComm": "Set community", "rtctrlSetCommList": "Set community list",
            "rtctrlMatchCommTerm": "Community match", "rtctrlMatchCommRegexTerm": "Community regex match",
            "rtctrlMatchAsPath": "AS path match", "rtctrlSetNextHop": "Set next hop",
        }
        attr_labels = {
            "name": "Name", "descr": "Description", "order": "Order", "action": "Action",
            "direction": "Direction", "type": "Type", "scope": "Scope", "ip": "Network",
            "fromPfxLen": "Minimum prefix length", "toPfxLen": "Maximum prefix length",
            "aggregate": "Aggregate", "metric": "Metric", "metricType": "Metric type",
            "localPref": "Local preference", "pref": "Preference", "weight": "Weight",
            "asn": "AS number", "community": "Community", "comm": "Community", "regex": "Pattern",
        }
        index, referenced = {}, set()
    
        def collect(items):
            for obj in items:
                for cls, body in obj.items():
                    attrs = body.get("attributes", {})
                    if attrs.get("dn"):
                        index[attrs["dn"]] = {cls: body}
                    if attrs.get("tDn"):
                        referenced.add(attrs["tDn"])
                    collect(body.get("children", []))

        collect(objects)

        def render(items, parent="", trail=frozenset()):
            def order(obj):
                attrs = next(iter(obj.values())).get("attributes", {})
                value = str(attrs.get("order", ""))
                return (int(value) if value.isdigit() else -1, attrs.get("name", ""))

            for obj in sorted(items, key=order):
                for cls, body in obj.items():
                    attrs = body.get("attributes", {})
                    dn = attrs.get("dn", "")
                    if dn and dn in trail:
                        continue
                    label = labels.get(cls, cls)
                    name = attrs.get("name") or attrs.get("ip")
                    if cls == "rtctrlCtxP":
                        label = f"Rule {attrs.get('order', '?')}: {attrs.get('action', 'unspecified')}"
                    elif name:
                        label += f": {name}"
                    if cls.startswith("bgpRsPeerTo") and dn:
                        label += f" ({dn.rsplit('/', 1)[0]})"
                    item = tree.insert(parent, "end", text=label,
                                       values=(attrs.get("direction") or attrs.get("descr", ""),), open=True)
                    for key, title in attr_labels.items(): 
                        if attrs.get(key) not in ("", None):
                            tree.insert(item, "end", text=title, values=(attrs[key],))
                    next_trail = trail | {dn} if dn else trail
                    render(body.get("children", []), item, next_trail)
                    target = attrs.get("tDn")
                    if target:
                        if target in index:
                            render([index[target]], item, next_trail)
                        else:
                            tree.insert(item, "end", text="Unresolved reference", values=(target,))
                    raw = tree.insert(item, "end", text="Technical attributes", open=False)
                    for key, value in sorted(attrs.items()):
                        if value not in ("", None) and key.lower() not in {"password", "pwd", "authkey"}:
                            tree.insert(raw, "end", text=key, values=(value,))

        roots = [obj for obj in objects if next(iter(obj.values())).get("attributes", {}).get("dn") not in referenced]
        render(roots or objects)

    def _poll(self):
        if not self.winfo_exists():
            return
        try:
            ok, value = self.results.get_nowait()
        except queue.Empty:
            self.app.after(100, self._poll)
            return
        self.fetching = False
        self.refresh_btn.configure(state="normal")
        if self.session is not self.app.apic_session:
            self.status.set("APIC session changed. Reopen the L3Out to retrieve details.")
            return
        if not ok:
            self.status.set("L3Out detail retrieval failed")
            messagebox.showerror("L3Out details", f"Could not retrieve L3Out details:\n{value}", parent=self)
            return
        sections, errors = value
        for name, tree in self.trees.items():
            excluded = ("l3extLIfP",) if name == "Node profiles" else ()
            if name == "External EPGs":
                self._insert_external_epgs(tree, sections[name])
            elif name == "Route maps":
                self._insert_route_maps(tree, sections [name])
            elif name == "Peers":
                self._insert_objects(tree, sections[name], peer_items=self.peer_items)
            else:
                self._insert_objects(tree, sections[name], excluded=excluded)
            if not sections[name]:
                tree.insert("", "end", text="No configured objects")
        for target, error in errors:
            self.trees["Route maps"].insert("", "end", text=f"Unavailable policy: {target}", values=(error,))
        summary = " / ".join(f"{len(sections[name])} {name.lower()}" for name in
                            ("Node profiles", "Interface profiles", "Peers", "External EPGs"))
        self.status.set(summary + (f" / {len(errors)} referenced policies unavailable" if errors else ""))


def get_vrfs(session) :
    """Collect tenant VRFs with their L3Out count and routing-table sizes.

    fvCtx           -> tenant VRFs
    l3extRsEctx     -> L3Out -> VRF relation (counted per resolved VRF DN)
    l3Ctx           -> switches the VRF is deployed on
    uribv4/6Route   -> routing-table entries on every switch (paged, DN only)
    """
    ctxs = _attrs(session.get("/api/class/fvCtx.json"), "fvCtx")
    rs_ectx = _attrs(session.get("/api/class/l3extRsEctx.json"), "l3extRsEctx")
    l3ctxs = _attrs(session.get("/api/class/l3Ctx.json"), "l3Ctx")

    l3outs = {}
    for rs in rs_ectx:
        m = re.match(r"uni/tn-([^/]+)/out-([^/]+)/", rs["dn"])
        if not m:
            continue
        tenant, out = m.groups()
        target = rs.get("tDn") or f"uni/tn-{tenant}/ctx-{rs.get('tnFvCtxName', '')}"
        l3outs.setdefault(target, []).append((f"{tenant}/{out}", f"uni/tn-{tenant}/out-{out}"))

    deployed = {}
    for c in l3ctxs:
        node = re.search(r"/node-(\d+)/", c["dn"])
        if node:
            deployed.setdefault(c.get("name"), set()).add(node.group(1))

    routes = {}
    for af in ("4", "6"):
        cls = f"uribv{af}Route"
        objs = session.get_all(f"/api/class/{cls}.json",
                               **{"rsp-prop-include": "naming-only", "order-by": f"{cls}.dn"})
        for attrs in _attrs(objs, cls):
            m = ROUTE_DN.search(attrs["dn"])
            if not m:
                continue
            node, _af, dom, prefix = m.groups()
            r = routes.setdefault(dom, {"v4": 0, "v6": 0, "prefixes": set(), "per_node": {}})
            r[f"v{af}"] += 1
            r["prefixes"].add(prefix)
            r["per_node"].setdefault(node, [0,0])[0 if af == "4" else 1] +=1

    rows = []
    for ctx in ctxs:
        m = re.match(r"uni/tn-([^/]+)/ctx-(.+)$", ctx["dn"])
        if not m:
            continue
        tenant, vrf = m.groups()
        dom = SPECIAL_DOMS.get((tenant, vrf), f"{tenant}:{vrf}")
        r = routes.get(dom, {"v4": 0, "v6": 0, "prefixes": set(), "per_node": {}})
        nodes = deployed.get(dom, set()) | set(r["per_node"])
        outs = sorted(l3outs.get(ctx["dn"], []))
        per_node = {n: f"{v4} IPv4 / {v6} IPv6 routes"
                    for n, (v4, v6) in sorted(r["per_node"].items(), key=lambda kv: int(kv[0]))}
        per_node.update({n: "deployed, no routes" for n in nodes if n not in r["per_node"]})
        rows.append({
            "tenant": tenant,
            "vrf": vrf,
            "l3outs": len(outs),
            "l3out_names": ", ".join(name for name, _dn in outs),
            "nodes": len(nodes),
            "routes_v4": r["v4"],
            "routes_v6": r["v6"],
            "prefixes": len(r["prefixes"]),
            "details": {"fvCtx": {k: v for k, v in ctx.items() if k not in VRF_HIDDEN_ATTRS},
                        "L3Outs": dict(outs),
                        f"Switches (routing domain '{dom}')": per_node},
        })
    rows.sort(key=lambda r: (r["tenant"].lower(), r["vrf"].lower()))
    return rows


ROUTE_COLUMNS = (
    ("node", "Node", 60), ("family", "Family", 60), ("prefix", "Prefix", 180),
    ("next_hop", "Next hop", 180), ("interface", "Interface", 120),
    ("protocol", "Protocol", 90), ("preference", "Preference", 80),
    ("metric", "Metric", 80), ("dn", "Route DN", 360),
)


def get_routing_table(session, tenant, vrf):
    """Return IPv4/IPv6 routes, one row per next hop, for one routing domain."""
    domain = SPECIAL_DOMS.get((tenant, vrf), f"{tenant}:{vrf}")
    rows = []
    for family in ("4", "6"):
        cls = f"uribv{family}Route"
        nexthop_cls = f"uribv{family}Nexthop"
        objects = session.get_all(f"/api/class/{cls}.json", **{
            "query-target-filter": f'wcard({cls}.dn,"/dom-{domain}/db-rt/")',
            "order-by": f"{cls}.dn",
            "rsp-subtree": "full",
            "rsp-subtree-class": nexthop_cls,
        })
        for obj in objects:
            route = obj.get (cls)
            if not route: 
                continue
            attrs = route["attributes"]
            match = ROUTE_DN.search(attrs.get("dn",""))
            if not match or match.group(3) != domain:
                continue
            node, _af, _domain, prefix = match.groups()
            hops = _attrs(route.get("children", [1]), nexthop_cls)
            for hop in hops or [{}]:
                rows.append({
                    "node": node, "family": f"IPv{family}", "prefix": prefix,
                    "next_hop": hop.get ("addr", ""), "interface": hop.get("1f",""),
                    "protocol": hop.get ("routeType") or attrs.get("routeType", ""),
                    "preference": hop.get ("pref") or attrs.get ("pref", ""),
                    "metric": hop.get ("metric") or attrs.get("metric", ""),
                    "dn": attrs["dn"],
                })
    rows.sort(key=lambda row: (int(row["node"]), row["family"], row["prefix"], row["next_hop"]))
    return rows


def write_routes_csv(path, tenant, vrf, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=["tenant", "vrf"] + [col[0] for col in ROUTE_COLUMNS])
        writer.writeheader()
        for row in rows:
            writer.writerow({"tenant": tenant, "vrf": vrf, **row})


def read_routes_csv(path, tenant, vrf):
    required = ["tenant", "vrf"] + [col[0] for col in ROUTE_COLUMNS]
    with open(path, newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source, strict=True)
        if not reader.fieldnames or not set(required).issubset(reader.fieldnames):
            raise ValueError("The CSV is not a BTK routing-table export (missing required columns).")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("The CSV contains duplicate column names.")
        rows = []
        for row in reader:
            if None in row or any(row.get(key) is None for key in required):
                raise ValueError(f"Incomplete or malformed CSV row at line {reader.line_num}.")
            if row["tenant"] != tenant or row["vrf"] != vrf:
                raise ValueError(f"The saved table does not belong to VRF {tenant}:{vrf}.")
            if not row["dn"]:
                raise ValueError(f"Missing route DN at line {reader.line_num}.")
            rows.append({col[0]: row[col[0]] for col in ROUTE_COLUMNS})
    return rows


def compare_routing_tables(saved, current, columns=ROUTE_COLUMNS, identity="dn"):
    """Compare route snapshots by identity, preserving all paths and their attributes."""
    keys = [col[0] for col in columns]

    def group(rows):
        grouped = {}
        for row in rows:
            grouped.setdefault(row[identity], []).append(row)
        return grouped

    before, after = group(saved), group(current)
    changes = []
    for dn in sorted(before.keys() | after.keys()):
        old, new = before.get(dn, []), after.get(dn, [])
        if Counter(tuple(row[key] for key in keys) for row in old) == Counter(
                tuple(row[key] for key in keys) for row in new):
            continue
        if not old:
            changes.extend({"change": "Added", **row} for row in new)
        elif not new:
            changes.extend({"change": "Removed", **row} for row in old)
        else:
            changes.extend({"change": "Changed (saved)", **row} for row in old)
            changes.extend({"change": "Changed (current)", **row} for row in new)
    return changes


def build_route_tree(parent, columns=ROUTE_COLUMNS):
    box = ttk.Frame(parent)
    box.pack(fill="both", expand=True)
    box.columnconfigure(0, weight=1)
    box.rowconfigure(0, weight=1)
    tree = ttk.Treeview(box, columns=[col[0] for col in columns],
                        displaycolumns=[col[0] for col in columns if col[0] != "dn"], show="headings")
    for key, title, width in columns:
        tree.heading(key, text=title)
        tree.column(key, width=width, minwidth=50, stretch=False)
    ysb = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
    xsb = ttk.Scrollbar(box, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    ysb.grid(row=0, column=1, sticky="ns")
    xsb.grid(row=1, column=0, sticky="ew")
    return tree


class RoutingTable(ttk.Frame):
    def __init__(self, master, app, session, tenant, vrf):
        super().__init__(master, padding=8)
        self.app, self.session = app, session
        self.tenant, self.vrf = tenant, vrf
        self.rows = []
        self.results = queue.Queue()
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 6))
        self.retrieve_btn = ttk.Button(bar, text="Retrieve routing table", command=self.retrieve)
        self.retrieve_btn.pack(side="left")
        self.export_btn = ttk.Button(bar, text="Export CSV", command=self.export, state="disabled")
        self.export_btn.pack(side="left", padx=6)
        self.compare_btn = ttk.Button(bar, text="Compare saved CSV", command=self.compare, state="disabled")
        self.compare_btn.pack(side="left")
        self.status = tk.StringVar(value="Not retrieved yet")
        ttk.Label(self, textvariable=self.status).pack(anchor="w", pady=(0, 6))
        self.tree = build_route_tree(self)

    def retrieve(self):
        if self.session is None or self.session is not self.app.apic_session:
            messagebox.showwarning("Routing table", "Reopen the VRF from the current APIC session.", parent=self)
            return
        self.retrieve_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.compare_btn.configure(state="disabled")
        self.rows = []
        self.tree.delete(*self.tree.get_children())
        self.status.set("Retrieving IPv4 and IPv6 routes...")

        def worker():
            try:
                self.results.put((True, get_routing_table(self.session, self.tenant, self.vrf)))
            except Exception as exc:
                self.results.put((False, exc))

        threading.Thread(target=worker, daemon=True).start()
        self.app.after(100, self._poll)
    
    def _poll(self):
        if not self.winfo_exists():
            return
        try:
            ok, value = self.results.get_nowait()
        except queue.Empty:
            self.app.after(100, self._poll)
            return
        self.retrieve_btn.configure(state="normal")
        if self.session is not self.app.apic_session:
            self.status.set("APIC session changed. Reopen the VRF to retrieve routes.")
            return
        if not ok:
            self.status.set("Routing-table retrieval failed")
            messagebox.showerror("Routing table", f"Could not retrieve routing table:\n{value}", parent=self)
            return
        self.rows = value
        for row in self.rows:
            self.tree.insert("", "end", values=[row[col[0]] for col in ROUTE_COLUMNS])
        count = len({row["dn"] for row in self.rows})
        self.status.set(f"{count} routes / {len(self.rows)} next-hop rows" if self.rows else "No routes found")
        self.export_btn.configure(state="normal")
        self.compare_btn.configure(state="normal")

    def export(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{self.tenant}_{self.vrf}_routes_{timestamp}.csv")
        path = Path(__file__).with_name("routing_tables") / filename
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            write_routes_csv(path, self.tenant, self.vrf, self.rows)
        except (OSError, csv.Error) as exc:
            messagebox.showerror("Export CSV", f"Could not export routing table:\n{exc}", parent=self)
            return
        self.status.set(f"Exported {len(self.rows)} rows to {path}")

    def compare(self):
        path = filedialog.askopenfilename(parent=self, title="Compare saved routing table",
                                          initialdir=str(Path(__file__).with_name("routing_tables")),
                                          filetypes=[("CSV files", "*.csv")])
        if not path: 
            return
        try:
            saved = read_routes_csv(path, self.tenant, self.vrf)
            changes = compare_routing_tables(saved, self.rows)
        except (OSError, UnicodeError, csv.Error, ValueError) as exc:
            messagebox.showerror("Compare routing tables", f"Could not compare routing tables:\n{exc}", parent=self)
            return
        if not changes:
            messagebox.showinfo("Compare routing tables", "The saved and current routing tables match.", parent=self)
            return
        win = tk.Toplevel(self)
        win.title(f"Route changes - {self.tenant}:{self.vrf} - {Path(path).name}")
        win.geometry(DEFAULT_WINDOW_SIZE)
        counts = {label: len({row["dn"] for row in changes if row["change"] == label})
                  for label in ("Added", "Removed", "Changed (current)")}
        ttk.Label(win, text=f"{counts['Added']} added / {counts ['Removed']} removed / "
                  f"{counts['Changed (current) ']} changed routes",
                  padding=8).pack(anchor="w")
        columns = (("change", "Change", 150),) + ROUTE_COLUMNS
        tree = build_route_tree(win, columns)
        tree.tag_configure("Added", foreground="#1e8e3e")
        tree.tag_configure("Removed", foreground="#d93025")
        tree.tag_configure("Changed (saved)", foreground="#777777")
        for row in changes:
            tree.insert("", "end", values=[row[col[0]] for col in columns], tags=(row["change"],))


# Each output shown in the results list.Column kinds drive sorting: num, ip or text.
VIEWS = {
    "bgp": {
        "title": "BGP peers",
        "fetch": get_bgp_peers,
        "columns": (
            ("node", "Node", 60, "num"), ("vrf", "VRF", 170, "text"), ("peer", "Peer", 120, "ip"),
            ("asn", "Remote AS", 80, "num"), ("state", "State", 90, "text"), ("type", "Type", 60, "text"),
            ("local_ip", "Local IP", 110, "ip"),
            ("last_flap", "Last flap", 190, "text"), ("pfx_rcvd", "Pfx rcvd", 70, "num"),
            ("pfx_sent", "Pfx sent", 70, "num"),
        ),
        "stretch": ("vrf", "last_flap"),
        "quick": {
            "All": None,
            "Established": lambda r: r["state"] == "established",
            "Not established": lambda r: r["state"] != "established",
        },
        "tag": lambda r: "up" if r["state"] == "established" else "down",
        "summary": lambda rows: (f"{sum(r['state'] == 'established' for r in rows)} established, "
                                 f"{sum(r['state'] != 'established' for r in rows)} not established"),
        "detail_title": lambda r: f"BGP peer {r['peer']} - node {r['node']} / {r['vrf']}",
    },
    "vrf": {
        "title": "VRFs", 
        "fetch": get_vrfs,
        "columns": (
            ("tenant", "Tenant", 120, "text"), ("vrf", "VRF", 180, "text"),
            ("l3outs", "L3Outs", 60, "num"),
            ("nodes", "Switches", 70, "num"), ("routes_v4", "IPv4 routes", 85, "num"),
            ("routes_v6", "IPv6 routes", 85, "num"), ("prefixes", "Unique pfx", 80, "num"),
        ),
        "stretch": ("vrf",),
        "quick": {
            "All": None,
            "With L3Outs": lambda r: r["l3outs"] > 0,
            "Without L3Outs": lambda r: r["l3outs"] == 0,
            "Deployed": lambda r: r["nodes"] > 0,
            "Not deployed": lambda r: r["nodes"] == 0,
        },
        "tag": lambda r: "" if r["nodes"] else "muted",
        "summary": lambda rows: (f"{sum(r['l3outs'] > 0 for r in rows)} with L3Outs, "
                                 f"{sum(r['l3outs'] for r in rows)} L3Outs, "
                                 f"{sum(r['routes_v4'] + r['routes_v6'] for r in rows)} routes on all switches"),
        "detail_title": lambda r: f"VRF {r['tenant']}:{r['vrf']}",
    },
    "l3out": {
        "title": "L3Outs",
        "fetch": get_l3outs,
        "columns": (
            ("tenant", "Tenant", 200, "text"), ("l3out", "L3Out", 300, "text"),
            ("vrf", "VRF", 300, "text"),
        ),
        "stretch": ("tenant", "l3out", "vrf"),
        "quick": {"All": None},
        "tag": lambda row: "" if row["vrf"] else "muted",
        "summary": lambda rows: f"{sum(not row['vrf'] for row in rows)} without a VRF",
        "detail_title": lambda row: f"L3Out {row['tenant']}/{row['l3out']}",
    },
}


class StatusLight (tk.Canvas):
    COLOURS = {"off": "#9e9e9e", "busy": "#f56800", "ok": "#2ecc40", "error": "#e53935"}

    def __init__(self, master, size=22):
        super().__init__(master, width=size, height=size, highlightthickness=0)
        self._oval = self.create_oval(2, 2, size - 2, size - 2, outline="#555", width=1)
        self.set("off")

    def set(self, state):
        self.itemconfigure(self._oval, fill=self.COLOURS[state])


class BTKApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BTK - BGP ToolKit")
        self.geometry(DEFAULT_WINDOW_SIZE)
        self.resizable(True, True) 
        self.minsize(*MINIMUM_WINDOW_SIZE)

        self.apics = []
        self.apic_session = None
        self.username = None
        self._pending = None
        self._results = queue.Queue()
        self._refresh_job = None
        self._refreshing = False
        self._next_refresh_at = self._token_expires_at = 0.0
        self._logged_in_text = ""

        self._build_ui()
        self._load_apic_list()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_results)


    def _build_ui(self):
        frm = ttk.Frame(self, padding=12)
        frm.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="APIC:").grid(row=0, column=0, sticky="w", pady=3)
        self.apic_combo = ttk.Combobox(frm, state="readonly")
        self.apic_combo.grid(row=0, column=1, sticky="ew", pady=3)
        self.apic_combo.bind("<<ComboboxSelected>>", lambda _e: self._fill_credentials())
        self.reload_btn = ttk.Button(frm, text="Reload list", command=self._load_apic_list)
        self.reload_btn.grid(row=0, column=2, padx=(6, 0))

        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="w", pady=3)
        self.user_var = tk.StringVar()
        self.user_entry = ttk.Entry(frm, textvariable=self.user_var)
        self.user_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=3)

        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="w", pady=3)
        self.pwd_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(frm, textvariable=self.pwd_var, show="*")
        self.pwd_entry.grid(row=2, column=1, columnspan=2, sticky="ew", pady=3)
        self.pwd_entry.bind("<Return>", lambda _e: self.login())
        self.cred_hint_var = tk.StringVar()
        ttk.Label(frm, textvariable=self.cred_hint_var, foreground="#777").grid(
            row=3, column=1, columnspan=2, sticky="w")
        self._config_creds = ("", "")

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 4))
        self.login_btn = ttk.Button(btns, text="Login", command=self.login)
        self.login_btn.pack(side="left")
        self.logout_btn = ttk.Button(btns, text="Logout", command=self.logout, state="disabled")
        self.logout_btn.pack(side="left", padx=6)
        self.bgp_btn = ttk.Button(btns, text="Get VRFs", command=lambda: self.fetch("vrf"), state="disabled")
        self.bgp_btn.pack(side="left")
        self.vrf_btn = ttk.Button(btns, text="Get L3Out", command=lambda: self.fetch("l3out"), state="disabled")
        self.vrf_btn.pack(side="left", padx=6)
        self.l3out_btn = ttk.Button(btns, text="Get BGP peers", command=lambda: self.fetch("bgp"), state="disabled")
        self.l3out_btn.pack(side="left")

        status = ttk.Frame(frm)
        status.grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 4))
        self.light = StatusLight(status)
        self.light.pack(side="left")
        self.countdown_var = tk.StringVar()
        self.countdown_label = ttk.Label(status, textvariable=self.countdown_var, width=20,
                                         font=("Menlo", 11))
        self.countdown_label.pack(side="left", padx=(8, 0))
        self.status_var = tk.StringVar(value="Not logged in")
        ttk.Label(status, textvariable=self.status_var).pack(side="left", padx=8)

        self.list_label_var = tk.StringVar()
        ttk.Label(frm, textvariable=self.list_label_var).grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 2))
        self._build_toolbar(frm).grid(row=7, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self._build_list(frm).grid(row=8, column=0, columnspan=3, sticky="nsew") 
        frm.rowconfigure(8, weight=1) 
        self._switch_view("bgp")

    def _build_toolbar(self, parent):
        bar = ttk.Frame(parent)
        filter_row, sort_row = ttk.Frame(bar), ttk.Frame(bar)
        filter_row.pack(fill="x")
        sort_row.pack(fill="x", pady=(4, 0))

        ttk.Label(filter_row, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_row, textvariable=self.filter_var, width=22)
        filter_entry.pack(side="left", padx=(4, 4))
        filter_entry.bind("<Escape>", lambda _e: self.filter_var.set(""))
        ttk.Label(filter_row, text="in").pack(side="left")
        self.filter_col_combo = ttk.Combobox(filter_row, state="readonly", width=12)
        self.filter_col_combo.pack(side="left", padx=(4, 10))
        ttk.Label(filter_row, text="Show:").pack(side="left")
        self.quick_combo = ttk.Combobox(filter_row, state="readonly", width=15)
        self.quick_combo.pack(side="left", padx=(4, 4))
        ttk.Button(filter_row, text="Clear", command=self._clear_filter).pack(side="left")
        ttk.Label(filter_row, text='(words are ANDed, prefix "!" to exclude)', foreground="#777").pack(
            side="left", padx=(8, 0))

        ttk.Label(sort_row, text="Sort by:").pack(side="left")
        self.sort_col_combo = ttk.Combobox(sort_row, state="readonly", width=12)
        self.sort_col_combo.pack(side="left", padx=(4, 6))
        self.sort_desc_var = tk.BooleanVar(value=False)
        ttk.Radiobutton(sort_row, text="Ascending", variable=self.sort_desc_var, value=False,
                        command=self._apply_view).pack(side="left")
        ttk.Radiobutton(sort_row, text="Descending", variable=self.sort_desc_var, value=True,
                        command=self._apply_view).pack(side="left", padx=(4, 20))

        ttk.Label(sort_row, text="Output:").pack(side="left")
        self.view_var = tk.StringVar(value="bgp")
        for name, view in VIEWS.items():
            ttk.Radiobutton(sort_row, text=view["title"], variable=self.view_var, value=name,
                           command=lambda: self._switch_view(self.view_var.get())).pack(side="left", padx=(4, 0))

        self.filter_var.trace_add("write", lambda *_: self._apply_view())
        for combo in (self.filter_col_combo, self.quick_combo, self.sort_col_combo):
            combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_view())
        return bar
        
    def _build_list(self, parent):
        box = ttk.Frame(parent)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.list_tree = ttk.Treeview(box, show="headings", selectmode="browse")
        self.list_tree.tag_configure("up", foreground="#1e8e3e")
        self.list_tree.tag_configure("down", foreground="#d93025")
        self.list_tree.tag_configure("muted", foreground="#8a8a8a")
        self.list_tree.bind("<Double-1>", self._show_details)
        ysb = ttk.Scrollbar(box, orient="vertical", command=self.list_tree.yview)
        xsb = ttk.Scrollbar(box, orient="horizontal", command=self.list_tree.xview)
        self.list_tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.list_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        self._view = None
        self._switching = False
        self._fetching = None
        self._data = {name: None for name in VIEWS}
        self._view_state = {}
        self._shown_rows = {}
        return box

    def _set_inputs_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        self.apic_combo.configure(state="readonly" if enabled else "disabled")
        for widget in (self.user_entry, self.pwd_entry, self.login_btn, self.reload_btn):
            widget.configure(state=state)

    def _load_apic_list(self):
        try:
            self.apics = load_apics()
        except Exception as exc:  # noga: BLE001
            messagebox.showerror("APIC list", f"Cannot read {CONFIG_FILE.name}:\n{exc}")
            self.apics = []
        names = [f"{a['name']}  ({a['url']})" for a in self.apics]
        self.apic_combo["values"] = names
        if names:
            self.apic_combo.current(0)
        else:
            self.apic_combo.set("")
        self._fill_credentials()

    def _fill_credentials(self):
        """Pre-fill username/password from config.yaml for the selected APIC.

        Values the user typed are kept when the APIC has no configured credentials; 
        values that came from the config for another APIC are cleared.
        """
        apic = self._selected_apic() or {"username": "", "password": ""}
        user, pwd = apic["username"], apic["password"]
        old_user, old_pwd = self._config_creds
        if user or self.user_var.get() == old_user:
            self.user_var.set(user)
        if pwd or self.pwd_var.get() == old_pwd:
            self.pwd_var.set(pwd)
        self._config_creds = (user, pwd)

        loaded = [n for n, v in (("username", user), ("password", pwd)) if v]
        self.cred_hint_var.set(f"{' and '.join(loaded).capitalize()} loaded from {CONFIG_FILE.name}"
                               if loaded else "")

    def _selected_apic(self):
        idx = self.apic_combo.current()
        return self.apics[idx] if 0 <= idx < len(self.apics) else None

    # ----- background work (keeps the UI responsive) -----
    def _run_bg(self, kind, func):
        def worker():
            try:
                self._results.put((kind, True, func()))
            except Exception as exc:  # noga: BLE001
                self._results.put((kind, False, exc))
        threading.Thread(target=worker, daemon=True).start()

    def _poll_results(self):
        # Tk is not thread-safe, so worker results are applied here on the main thread.
        while not self._results.empty():
            kind, ok, value = self._results.get_nowait()
            getattr(self, f"_on_{kind}")(ok, value)
        self.after(100, self._poll_results)

    #actions
    def login(self):
        if self.apic_session or self._pending:
            return
        apic = self._selected_apic()
        user, pwd = self.user_var.get().strip(), self.pwd_var.get()
        if not apic:
            messagebox.showwarning("Login", "Select an APIC first.")
            return
        if not user or not pwd:
            messagebox.showwarning("Login", "Enter username and password.")
            return

        self._set_inputs_enabled(False)
        self.light.set("busy")
        self.status_var.set(f"Logging in to {apic['name']}...")

        session = APICSession(apic["url"], apic["verify_ssl"])
        self._pending = (apic, user, session)
        self._run_bg("login", lambda: session.login(user, pwd))

    def _on_login(self, ok, value):
        apic, user, session = self._pending
        self._pending = None
        # Only keep the password in the form if it came from config.yaml.
        self.pwd_var.set (apic ["password"])
        if not ok:
            self.light.set ("error")
            self.status_var.set (f"Login failed: {value}")
            self._set_inputs_enabled(True)
            return
        self.apic_session, self.username = session, user
        self._logged_in_text = f"Logged in to {apic['name']} as {user}"
        self.light.set("ok")
        self.status_var.set (self._logged_in_text)
        self.logout_btn.configure(state="normal")
        self._set_fetch_enabled(True)
        self._start_refresher()
    
    #results list (BGP peers, VRFs, ...)
    def _set_fetch_enabled(self, enabled):
        state = "normal" if enabled and self.apic_session else "disabled"
        for btn in (self.bgp_btn, self.vrf_btn, self.l3out_btn):
            btn.configure(state=state)

    def fetch(self, name):
        if not self.apic_session or self._fetching:
            return
        session, func = self.apic_session, VIEWS[name]["fetch"]
        self._fetching = name
        self._set_fetch_enabled(False)
        self._switch_view(name)
        self._run_bg("fetch", lambda: (name, session, func(session)))

    def _on_fetch(self, ok, value):
        name, self._fetching = self._fetching, None
        if not self.apic_session:
            return
        self._set_fetch_enabled(True)
        if not ok:
            self._apply_view()
            if self._view == name:
                self.list_label_var.set(f"{VIEWS[name]['title']} - retrieval failed")
            messagebox.showerror(VIEWS[name]["title"], f"Could not retrieve {VIEWS[name]['title']}:\n{value}")
            return
        _name, session, rows = value
        if session is not self.apic_session:
            return
        self._data[name] = rows
        if self._view == name:
            self._apply_view()
        else:
            self._switch_view(name)
    @staticmethod
    def _peer_ip(value):
        try:
            return str(ip_interface(str(value)).ip)
        except ValueError:
            return str(value).strip()

    def open_bgp_peer_details(self, peer_ip, tenant, vrf):
        if not self.apic_session:
            messagebox.showwarning("BGP peer", "Log in to an APIC before opening BGP peer details")
            return
        rows = self._data.get("bgp")
        if rows  is not None:
            self._open_bgp_peer_match(rows, peer_ip, tenant, vrf)
            return
        session = self.apic_session
        self._run.bg("l3out_peer_lookup", lambda: (session, peer_ip, tenant, vrf, get_bgp_peers(session)))
        self.staus_var.set(f"Looking up BGP peer {peer_ip} in {tenant}:{vrf}...")

    def _on_l3out_peer_lookup(self, ok, value):
        if not ok:
            messagebox.showerror("BGP peer", f"Could not retrieve peer details:\n {value}")
            return
        session, peer_ip, tenant, vrf, rows = value
        if session is not self.apic_session:
            return
        self._data["bgp"] = rows
        if self._view == "bgp":
            self._apply_view()
        self._open_bgp_peer_match(rows, peer_ip, tenant, vrf)

    def _open_bgp_peer_match(self, rows, peer_ip, tenant, vrf):
        target_ip = self._peer_ip(peer_ip)
        matches= []
        for row in rows:
            row_tenant, separator, row_vrf, = row.get("vrf").partition(":")
            if (self._peer_ip(row.get("peer", "")) == target_ip and separator
                and row_tenant == tenant and row_vrf == vrf):
                matches.append(row)
        if not matches:
            messagebox.showinfo("BGP peer", f"No BGP peer matching {target_ip} was found in {tenant}:{vrf}.")
            return
        if len(matches) == 1:
            self._open_details(matches[0], "bgp")
            return


        chooser = tk.Toplevel(self)
        chooser.title(f"Select peer {target_ip} - {tenant}:{vrf}")
        chooser.geometry("560x320")
        ttk.Label(chooser, text=f"This peer is present on {len(matches)} nodes, Select a node.",
                  padding=8).pack(anchor="w")
        tree = tk.Treeview(chooser, columns=("node", "state", "type"), show="headings", selectmode="browse")
        for key, title, width in (("node", "Node", 100), ("state", "State", 150), ("type", "Type", 120)):
            tree.heading(key, text=title)
            tree.column(key, width=width, stretch=True)
        tree.pack(fill="both", expand=True, padx=8, pady=4)
        candidates = {}
        for row in matches:
            iid = tree.insert("","end", values=(row["node"], row["state"], row["type"]))
            candidates[iid] = row

        def open_selected(_event=None):
            selection = tree.selection()
            if selection:
                chooser.sedtroy()
                self._open_details(candidates[selection[0]], "bgp")

        tree.bind("<Double-1>", open_selected)
        ttk.Button(chooser, text="Open details", command=open_selected).pack(anchor="e", padx=8, pady=8)

    def _switch_view(self, name):
        if self._view:
            self._view_state[self._view] = (
                self.filter_var.get(), self.filter_col_combo.current(), self.quick_combo.current(),
                self.sort_col_combo.current(), self.sort_desc_var.get())
        self._view = name
        self.view_var.set(name)
        view = VIEWS[name]
        titles = [c[1] for c in view["columns"]]

        self._switching = True
        self.list_tree.delete(*self.list_tree.get_children())
        self.list_tree.configure(columns=[c[0] for c in view["columns"]])
        for key, title, width, kind in view["columns"]:
            self.list_tree.heading(key, text=title, command=lambda k=key: self._sort_by_header(k))
            self.list_tree.column(key, width=width, minwidth=40, anchor="e" if kind == "num" else "w",
                                  stretch=key in view["stretch"])
        self.filter_col_combo["values"] = ["All columns"] + titles
        self.sort_col_combo["values"] = titles
        self.quick_combo["values"] = list(view["quick"])
        text, fcol, quick, scol, desc = self._view_state.get(name, ("", 0, 0, 0, False))
        self.filter_col_combo.current(fcol)
        self.quick_combo.current(quick)
        self.sort_col_combo.current(scol)
        self.sort_desc_var.set(desc)
        self.filter_var.set(text)
        self._switching = False
        self._apply_view()

    @staticmethod
    def _sort_key(key, kind):
        def sort_key(row):
            val = row[key]
            if kind == "num":
                try:
                    return (0, (int(val or 0),), "")
                except (TypeError, ValueError):
                    pass
            if kind == "ip":
                parts = str(val).split("/")[0].split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return (0, tuple(int(p) for p in parts), "")
            return (1, (), str(val).lower())
        return sort_key

    def _filtered_rows(self):
        view = VIEWS[self._view]
        cols = view["columns"]
        terms = self.filter_var.get().lower().split()
        col_idx = self.filter_col_combo.current ()
        keys = [c[0] for c in cols] if col_idx <= 0 else [cols[col_idx - 1][0]]
        quick = view["quick"].get(self.quick_combo.get())

        def match(row):
            if quick and not quick(row):
                return False
            haystack = " ".join(str(row[k]) for k in keys).lower()
            # Every word must match; a leading "!" excludes rows containing that word.
            return all((t[1:] not in haystack) if t.startswith("!") and len(t) > 1 else (t in haystack)
                       for t in terms)

        return [r for r in self._data[self._view] or [] if match(r)]

    def _apply_view(self):
        if self._switching or not self._view:
            return
        view = VIEWS[self._view]
        cols = view["columns"]
        key, _title, _w, kind = cols[max(self.sort_col_combo.current(), 0)]
        desc = self.sort_desc_var.get()
        rows = sorted(self._filtered_rows(), key=self._sort_key(key, kind), reverse=desc)

        self.list_tree.delete(*self.list_tree.get_children())
        self._shown_rows = {}
        for row in rows:
            iid = self.list_tree.insert("", "end", values=[row[c[0]] for c in cols], tags=(view["tag"](row),))
            self._shown_rows[iid] = row

        for col, title, _w, _k in cols:
            arrow = ("v" if desc else "^") if col == key else ""
            self.list_tree.heading(col, text=title + arrow)

        all_rows = self._data[self._view]
        if self._fetching == self._view:
            self.list_label_var.set(f"{view['title']} - retrieving...")
        elif all_rows is None:
            self.list_label_var.set(f"{view['title']} - not retrieved yet")
        else:
            total = len(all_rows)
            shown = f"showing {len(rows)} of {total}" if len(rows) != total else f"{total} total"
            self.list_label_var.set(
                f"{view['title']} - {shown} ({view['summary'](all_rows)}) "
                "- double-click a row for details, click a header to sort")
    
    def _sort_by_header(self, key):
        idx = [c[0] for c in VIEWS[self._view]["columns"]].index(key)
        if self.sort_col_combo.current() == idx:
            self.sort_desc_var.set(not self.sort_desc_var.get())
        else:
            self.sort_col_combo.current(idx)
            self.sort_desc_var.set(False)
        self._apply_view()

    def _clear_filter(self):
        self.filter_col_combo.current(0)
        self.quick_combo.current(0)
        self.filter_var.set("")

    def _show_details(self, _event=None):
        sel = self.list_tree.selection()
        if not sel:
            return
        row = self._shown_rows[sel[0]]
        self._open_details(row, self._view)

    def _open_details(self, row, view):
        win = tk.Toplevel(self)
        win.title(VIEWS[view]["detail_title"](row))
        win.geometry(DEFAULT_WINDOW_SIZE)
        if view == "l3out":
            L3OutDetails(win, self, self.apic_session, row).pack(fill="both", expand=True)
            return
        detail_parent = win
        if view in ("vrf", "bgp"):
            tabs = ttk.Notebook(win)
            tabs.pack(fill="both", expand=True)
            detail_parent = ttk.Frame(tabs)
            tabs.add(detail_parent, text="Details")
        if view == "vrf":
            routes = RoutingTable(tabs, self, self.apic_session, row["tenant"], row["vrf"])
            tabs.add(routes, text="Routing table")
        else:
            neighbor = BGPReceivedRoutes(tabs, self, self.apic_session, row, neighbor_info=True)
            tabs.add(neighbor, text="BGP neighbor - SSH")
            routes = BGPReceivedRoutes(tabs, self, self.apic_session, row)
            tabs.add(routes, text="BGP routes - SSH")
            advertised = BGPReceivedRoutes(tabs, self, self.apic_session, row, advertised=True)
            tabs.add(advertised, text="BGP advertised routes - SSH")

            tabs.select(detail_parent)
        txt = tk.Text(detail_parent, wrap="none", font=("Menlo", 11))
        ysb = ttk.Scrollbar(detail_parent, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=ysb.set)
        ysb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        for section, attrs in row["details"].items():
            txt.insert("end", f"[{section}]\n")
            if not attrs:
                txt.insert("end", " (none)\n")
            for k, v in sorted(attrs.items(), key=lambda kv: (len(kv[0]) if kv[0].isdigit() else 0, kv[0])):
                if section == "L3Outs":
                    txt.insert("end", f"  {k.split('/', 1)[-1]}\n")
                elif v not in ("", None):
                    txt.insert("end", f"  {k:<22} {v}\n")
            txt.insert("end", "\n")
        txt.configure(state="disabled")

    #   background token refresher
    def _start_refresher(self):
        self._stop_refresher()
        now = time.monotonic()
        self._next_refresh_at = now + TOKEN_REFRESH_INTERVAL
        self._token_expires_at = now + self.apic_session.refresh_timeout
        self._refreshing = False
        self._tick()

    def _stop_refresher(self):
        self._cancel_refresh()
        self._refreshing = False
        self.countdown_var.set("")

    def _cancel_refresh(self):
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None

    def _tick(self):
        """Runs once a second while logged in: updates the countdown, starts refreshes."""
        self._refresh_job = None
        if not self.apic_session:
            return
        delay = 1000
        if not self._refreshing:
            remaining = self._next_refresh_at - time.monotonic()
            if remaining <= 0:
                self._refreshing = True
                self.countdown_var.set("Refreshing...")
                session = self.apic_session
                self._run_bg("refresh", lambda: (session, session.refresh()))
            else:
                secs = math.ceil(remaining)
                self.countdown_var.set(f"Token refresh:{secs // 60}:{secs % 60:02d}")
                # Wake up exactly when the shown second changes so the refresh is on time.
                delay = max(10, int((remaining - (secs - 1)) * 1000))
        self._refresh_job = self.after(delay, self._tick)

    def _on_refresh(self, ok, value):
        self._refreshing = False
        if not self.apic_session:
            return
        now = time.monotonic()
        if ok:
            session, _attrs_ = value
            if session is not self.apic_session:
                return
            self._next_refresh_at = now + TOKEN_REFRESH_INTERVAL
            self._token_expires_at = now + session.refresh_timeout
            if self.light.itemcget(self.light._oval, "fill") != StatusLight.COLOURS["ok"]:
                self.light.set("ok")
                self.status_var.set(self._logged_in_text)
            self._cancel_refresh()
            self._tick()
            return

        # An APIC error (e.g. token rejected) is final; network errors are retried until the token expires.
        if isinstance(value, RuntimeError) or now + TOKEN_REFRESH_RETRY >= self._token_expires_at:
            self._reset_session()
            self.light.set("error")
            self.status_var.set(f"Session lost - token refresh failed: {value}")
            return
        self._next_refresh_at = now + TOKEN_REFRESH_RETRY
        self.light.set("busy")
        self.status_var.set(f"{self._logged_in_text} - token refresh failed, retrying: {value}")
        self._cancel_refresh()
        self._tick()

    def logout(self):
        if not self.apic_session:
            return
        self._stop_refresher()
        session, user = self.apic_session, self.username
        self.apic_session = None
        self.light.set("busy")
        self.status_var.set("Logging out...")
        self.logout_btn.configure(state="disabled")
        self._set_fetch_enabled(False)
        self._run_bg("logout", lambda: session.logout(user))

    def _on_logout(self, ok, value):
        self._reset_session()
        self.light.set ("off")
        self.status_var.set("Logged out" if ok else f"Logged out (APIC reported: {value})")

    def _reset_session(self):
        self._stop_refresher()
        self.apic_session = self.username = None
        self.logout_btn.configure(state="disabled")
        self._set_fetch_enabled(False)
        self._data = {name: None for name in VIEWS}
        self._apply_view()
        self._set_inputs_enabled(True)

    def _on_close(self):
        if self.apic_session:
            try:
                self.apic_session.logout(self.username)
            except Exception:  # noqa: BLE001
                pass
        self.destroy()

if __name__ == "__main__":
    BTKApp().mainloop()