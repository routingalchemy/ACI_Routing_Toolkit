# ACI Routing Toolkit (ART)

ART is a desktop application written in python tkinter for inspecting Cisco ACI routing. It connects to the APIC over the REST API and can optionally connect to leaf switches over SSH to get additional information.

## Features

- List BGP peers and inspect their state, prefix counts, and flap time.
- List OSPF neighbors 
- List tenant VRFs with L3Out, deployment, and IPv4/IPv6 route counts.
- Retrieve a VRF routing table, export it to CSV, and compare it with a saved snapshot.
- List L3Outs and inspect their profiles, interfaces, peers, External EPGs, and route-control policies.
- Retrieve BGP neighbor details and received or advertised routes from a leaf over SSH, in raw or parsed form.
- Run `iping`, `itraceroute`, `show vrf`, or `show interface status` from the main-menu Troubleshoot utility.
- Export parsed BGP tables to CSV and compare them with saved tables.
- Filter and sort result lists, and refresh APIC authentication tokens while logged in.

## Requirements

- Python 3.9 or later.
- Network access to the configured APIC over HTTPS.
- Network access to the leaf OOB address via SSH for retrieving BGP tables that can't be get through REST from the APIC

## Dependencies

The Python packages are listed in `requirements.txt`:

- `requests`
- `PyYAML`
- `Netmiko`
- `ntc-templates`

## Installation and launch

```bash
git clone https://github.com/routingalchemy/ACI_Routing_Toolkit.git
cd ACI_Routing_Toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python art_app.py
```

## Configuration

Edit `config.yaml` before launching. Add the APICs you are authorized to access under `apics`; each entry accepts a display `name`, `url`, and `verify_ssl` flag. URLs without a scheme are treated as HTTPS. Set `verify_ssl: true` when the APIC certificate is trusted by your environment; the sample entries disable certificate verification and should be adjusted for your deployment.

Credentials can be set once in the top-level `credentials` block or per APIC. Per-APIC values override the shared values. For passwords, prefer `password_env` to a literal `password`:

```yaml
credentials:
  username: your-apic-username
  password_env: APIC_PASSWORD

apics:
  - name: Production APIC
    url: https://apic.example.net
    verify_ssl: true
```

Set the environment variable before launching, for example:

```bash
export APIC_PASSWORD='your-secret'
```

Unset credentials can be entered in the login form. Configured credentials pre-fill the form. The sample `config.yaml` contains example lab entries, including a literal password: remove or replace those values before use, keep the file private, and do not commit real credentials. On Linux/macOS, restrict access with `chmod 600 config.yaml`.

The optional `settings` mapping controls window sizes and request/token-refresh timeouts. Numeric values must be positive, and the minimum window size must not exceed the default size. `remember_ssh_password` is a boolean, defaulting to `false`; set it to `true` to reuse the password from a successful APIC login in SSH forms. This password is kept in application memory only and is not written to `config.yaml`. SSH credentials configured in `ssh_credentials` initially take precedence until a successful APIC login replaces the in-memory password. If `config.yaml` is missing, the app uses built-in defaults for settings, but APIC entries still need to be configured.

```yaml
settings:
  remember_ssh_password: true
```

## Using the application

1. Select an APIC, enter credentials if they were not loaded from the config, and choose **Login**.
2. Select **Get VRFs**, **Get L3Out**, **Get BGP peers**, or **Get OSPF neighbors** to retrieve that view. Use the filter, quick-filter, and sort controls above the results. Choose **Troubleshoot** from the main menu to run `iping` or `itraceroute` in a selected leaf's VRF, or `show vrf` / `show interface status` on the selected leaf without entering a VRF or IP addresses.
3. Double-click a result to open its details. In the VRF routing-table tab, double-click a route to open the remote lookup; use **Reload devices** to re-read its configured SSH hosts from `config.yaml`. OSPF neighbor details include `ospfLsaRec` LSAs retrieved as children of `ospfDb`; BGP peer details include SSH tabs for neighbor information, received routes, and advertised routes.
4. For SSH retrieval, enter credentials accepted by the leaf. The first connection to an unknown SSH host key asks for confirmation. Independently verify the displayed fingerprint before accepting; accepted keys are saved in `~/.ssh/known_hosts`. A changed key is blocked.
5. Parsed routing tables and BGP routes can be exported to CSV and compared with a prior export. Exports are written under `routing_tables/` or `bgp_tables/` beside `art_app.py`. Raw BGP output is displayed but is not available for CSV export or comparison.
6. Choose **Logout** when finished.

## Security notes

- Use only APICs and switches you are authorized to access. APIC and SSH credentials are sent to those configured hosts.
- Do not store production passwords in `config.yaml`; use environment variables or enter credentials in the application.
- Protect exported CSV files: routing and peer details may be operationally sensitive.
- Keep SSH host-key checking enabled. Verify an unknown fingerprint through a trusted channel before accepting it.
- The application currently disables urllib3's insecure-request warning globally. This does not make an untrusted APIC certificate safe; configure certificate verification appropriately.

