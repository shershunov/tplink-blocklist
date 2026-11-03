# tplink-blocklist

This interactive CLI blocks websites on a TP-Link router. It uses the parental control API of the router web interface. TP-Link does not document this API.

Tested hardware: Archer AX53 v1, firmware 1.4.4 Build 20250603. Other TP-Link routers with the same firmware API can work.

## Install

The script requires Python 3.10 or later.

```
pip install -r requirements.txt
```

## Usage

```
python blocklist.py
```

| Variable | Default | Purpose |
|---|---|---|
| `TPLINK_HOST` | `192.168.0.1` | Router address |
| `TPLINK_PASSWORD` | not set | Router admin password. If you do not set it, the script asks for the password and offers to save it in the system keyring. |

Menu:

1. List blocked sites: show the sites and the devices in the profile.
2. Add site: add one or more sites. The first site creates the profile.
3. Remove site: remove sites by number or by name.
4. Check site: test router DNS, HTTPS and HTTP for a site from this computer.
5. Devices: select the devices that the blocklist applies to.

The script keeps the blocklist in a parental control profile with the name `Blocklist`.

## Limitations

- The router matches each entry as a substring of the site address. For example, `example.com` also blocks `m.example.com` and `myexample.com`.
- The router blocks HTTPS only when the TLS ClientHello fits in one network packet. Clients with ML-KEM key exchange, for example Chrome 150, send a larger ClientHello. The router does not block them.
- A VPN on the device bypasses the router.
- When the script connects, it can end an open session in the router web interface.
- On Windows, the check sends its traffic through the LAN interface. On other systems, a local VPN can change the result.
