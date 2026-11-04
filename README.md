# ACI Routing Toolkit (ART)

ART is a desktop application for inspecting Cisco ACI routing and BGP information. It connects to APIC over the REST API and can optionally connect to leaf switches over SSH for BGP neighbor and route output.

## Features

- List BGP peers and inspect their state, address families, prefix counts, and flap time.
- List tenant VRFs with L3Out, deployment, and IPv4/IPv6 route counts.
- Retrieve a VRF routing table with next hops, export it to CSV, and compare it with a saved snapshot.
- List L3Outs and inspect their profiles, interfaces, peers, External EPGs, and route-control policies.
- Retrieve BGP neighbor details and received or advertised routes from a leaf over SSH, in raw or parsed form.
- Export parsed BGP tables to CSV and compare them with saved tables.
- Filter and sort result lists, and refresh APIC authentication tokens while logged in.

## Requirements

- Python 3.9 or later.
- Tkinter for your Python installation (on Debian/Ubuntu, install the `python3-tk` system package if it is missing).
- Network access to the configured APIC over HTTPS. BGP SSH retrieval also requires SSH access to the leaf's out-of-band management address.

## Installation and launch

Run these commands from the project directory. A virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python art_app.py
```

On Windows, activate the environment with `.venv\\Scripts\\activate` instead of the `source` command. Tkinter must be available in the selected Python installation.

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

The optional `settings` mapping controls window sizes and request/token-refresh timeouts. Values must be positive, and the minimum window size must not exceed the default size. If `config.yaml` is missing, the app uses built-in defaults for settings, but APIC entries still need to be configured.

## Using the application

1. Select an APIC, enter credentials if they were not loaded from the config, and choose **Login**.
2. Select **Get VRFs**, **Get L3Out**, or **Get BGP peers** to retrieve that view. Use the filter, quick-filter, and sort controls above the results.
3. Double-click a result to open its details. VRF details include a routing-table tab; BGP peer details include SSH tabs for neighbor information, received routes, and advertised routes.
4. For SSH retrieval, enter credentials accepted by the leaf. The first connection to an unknown SSH host key asks for confirmation. Independently verify the displayed fingerprint before accepting; accepted keys are saved in `~/.ssh/known_hosts`. A changed key is blocked.
5. Parsed routing tables and BGP routes can be exported to CSV and compared with a prior export. Exports are written under `routing_tables/` or `bgp_tables/` beside `art_app.py`. Raw BGP output is displayed but is not available for CSV export or comparison.
6. Choose **Logout** when finished.

## Security notes

- Use only APICs and switches you are authorized to access. APIC and SSH credentials are sent to those configured hosts.
- Do not store production passwords in `config.yaml`; use environment variables or enter credentials in the application.
- Protect exported CSV files: routing and peer details may be operationally sensitive.
- Keep SSH host-key checking enabled. Verify an unknown fingerprint through a trusted channel before accepting it.
- The application currently disables urllib3's insecure-request warning globally. This does not make an untrusted APIC certificate safe; configure certificate verification appropriately.

## Dependencies

The Python packages are listed in `requirements.txt`: Requests, PyYAML, Netmiko, and `ntc-templates`. Parsed BGP output requires the matching NX-OS template supplied by `ntc-templates`; raw neighbor output does not require parsing.
