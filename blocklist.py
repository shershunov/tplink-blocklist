import getpass
import ipaddress
import os
import re
import secrets
import socket
import ssl
import struct
import sys

import requests

from tplink import LoginError, RouterError, TPLinkClient

try:
    import keyring
    from keyring.errors import KeyringError
except ImportError:
    keyring = None
    KeyringError = Exception

ROUTER = os.environ.get("TPLINK_HOST", "192.168.0.1")
PROFILE_NAME = "Blocklist"
KEYRING_SERVICE = "tplink-blocklist"

OWNERS = "/admin/smart_network?form=patrol_owner_list"
DEVICES = "/admin/smart_network?form=patrol_devices"
LIMITS = "/admin/smart_network?form=patrol_limit"
HOST_INFO = "/admin/access_control?form=enable"

NUMERIC_FIELDS = (
    "workday_daily_time",
    "weekend_daily_time",
    "workday_bed_time_begin",
    "workday_bed_time_end",
    "weekend_bed_time_begin",
    "weekend_bed_time_end",
)
NO_TIME_LIMITS = {
    "enable_workday_time_limit": False,
    "workday_daily_time": 120,
    "enable_weekend_time_limit": False,
    "weekend_daily_time": 120,
    "enable_workday_bed_time": False,
    "workday_bed_time_begin": 1320,
    "workday_bed_time_end": 420,
    "enable_weekend_bed_time": False,
    "weekend_bed_time_begin": 1320,
    "weekend_bed_time_end": 420,
}
FREE_OWNER_IDS = ("", "-1", "None")
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")
DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
CHECK_TIMEOUT = 6

MENU = """
Website blocking on router {router}
  1. List blocked sites
  2. Add site
  3. Remove site
  4. Check site
  5. Devices
  0. Exit"""

LONG_HELLO = ssl.OPENSSL_VERSION_INFO >= (3, 5)
TLS_TEXT = {
    "open": "opens",
    "dropped": "the connection fails",
    "no_connect": "the server does not accept the connection",
}
DNS_TEXT = {
    "real": "returns the real address",
    "blocked": "does not return the site address",
    "no_answer": "no answer. A VPN on this computer probably intercepts DNS.",
}
HTTP_TEXT = {
    "block_page": "HTTP: the router returned its block page",
    "open": "HTTP: the server responds",
    "dropped": "HTTP: the connection opens, but no response arrives",
    "no_connect": "HTTP: the server does not accept the connection",
}


def as_list(value) -> list:
    return value if isinstance(value, list) else []


def mac_key(mac) -> str:
    return re.sub(r"[^0-9A-F]", "", str(mac or "").upper())


def split_input(text: str) -> list[str]:
    return [part for part in re.split(r"[\s,]+", text.strip()) if part]


def host_of(text: str) -> str:
    host = text.strip().lower().split("://", 1)[-1]
    host = re.split(r"[/?#]", host, maxsplit=1)[0]
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    return host.strip(".")


def site_entry(text: str) -> str:
    host = host_of(text)
    return host[4:] if host.startswith("www.") else host


def ask_yes(question: str) -> bool:
    return input(f"{question} [y/N]: ").strip().lower() in ("y", "yes")


def client_entry(device: dict) -> dict:
    return {
        "client_type": device.get("client_type", ""),
        "name": device.get("name", ""),
        "mac": device["mac"],
        "device_id": device.get("device_id") or mac_key(device["mac"]),
    }


class Blocklist:
    def __init__(self, client: TPLinkClient):
        self.client = client
        limits = client.read(LIMITS) or {}
        self.max_sites = int(limits.get("category_len", 32))
        self.max_devices = int(limits.get("devices_len", 32))
        self.my_mac = mac_key((client.read(HOST_INFO) or {}).get("host_mac"))

    def state(self) -> tuple[list[dict], int, dict | None]:
        profiles = as_list(self.client.load(OWNERS))
        for index, profile in enumerate(profiles):
            if profile.get("name") == PROFILE_NAME:
                return profiles, index, profile
        return profiles, -1, None

    def devices(self) -> list[dict]:
        return as_list(self.client.load(DEVICES))

    def create(self, sites: list[str], clients: list[dict]) -> None:
        record = {"name": PROFILE_NAME, "client_list": clients, "website_list": sites, **NO_TIME_LIMITS}
        self.client.insert(OWNERS, record)

    def save(self, index: int, profile: dict, sites: list[str] | None = None,
             clients: list[dict] | None = None) -> None:
        new = dict(profile)
        new["website_list"] = sites if sites is not None else as_list(profile.get("website_list"))
        new["client_list"] = clients if clients is not None else as_list(profile.get("client_list"))
        for field in NUMERIC_FIELDS:
            if field in new:
                new[field] = int(new[field])
        self.client.update(OWNERS, profile["key"], index, profile, new)

    def describe(self, device: dict) -> str:
        text = f"{device.get('name') or '?'}  {device.get('mac')}"
        return f"{text}  (this computer)" if mac_key(device.get("mac")) == self.my_mac else text


def foreign_owner(device: dict, own_id: str | None, owners: dict[str, str]) -> str | None:
    owner = str(device.get("owner_id"))
    if owner in FREE_OWNER_IDS or owner == own_id:
        return None
    return owners.get(owner, owner)


def pick_devices(blocklist: Blocklist, profiles: list[dict], profile: dict | None) -> list[dict] | None:
    devices = blocklist.devices()
    devices.sort(key=lambda d: (not int(d.get("online") or 0), str(d.get("name") or "").lower()))
    own_id = str(profile.get("owner_id")) if profile else None
    owners = {str(p.get("owner_id")): p.get("name") or "?" for p in profiles}
    current = {mac_key(c.get("mac")): c for c in as_list(profile.get("client_list"))} if profile else {}
    selected = set(current)
    while True:
        print()
        for number, device in enumerate(devices, 1):
            mac = mac_key(device.get("mac"))
            notes = []
            if mac == blocklist.my_mac:
                notes.append("this computer")
            if int(device.get("online") or 0):
                notes.append("online")
            other = foreign_owner(device, own_id, owners)
            if other:
                notes.append(f'in profile "{other}"')
            mark = "x" if mac in selected else " "
            name = str(device.get("name") or "?")
            print(f"  {number:>2}. [{mark}] {name:<24} {device.get('mac')}  {', '.join(notes)}")
        print("Type device numbers to select or unselect them. Put spaces between the numbers.")
        print("Press Enter to finish. Type q to cancel.")
        raw = input("> ").strip().lower()
        if raw == "q":
            return None
        if not raw:
            break
        for item in split_input(raw):
            if not item.isdigit() or not 1 <= int(item) <= len(devices):
                print(f"  {item}: no device has this number.")
                continue
            device = devices[int(item) - 1]
            mac = mac_key(device.get("mac"))
            other = foreign_owner(device, own_id, owners)
            if other and mac not in selected:
                print(f'  {device.get("name")} is in profile "{other}". Remove it from that profile first.')
                continue
            selected ^= {mac}
    if len(selected) > blocklist.max_devices:
        print(f"The router allows a maximum of {blocklist.max_devices} devices in a profile.")
        return None
    known = {mac_key(d.get("mac")): d for d in devices}
    return [client_entry(known.get(mac) or current[mac]) for mac in sorted(selected)]


def show_list(blocklist: Blocklist) -> None:
    profiles, _, profile = blocklist.state()
    if profile is None:
        print("The blocklist is empty. The router has no Blocklist profile yet.")
    else:
        sites = as_list(profile.get("website_list"))
        print(f"Blocked sites ({len(sites)} of {blocklist.max_sites}):")
        for number, site in enumerate(sites, 1):
            print(f"  {number}. {site}")
        clients = as_list(profile.get("client_list"))
        print(f"Devices in the profile ({len(clients)}):")
        for client in clients:
            print(f"  {blocklist.describe(client)}")
        if not clients:
            print("  None. Add devices in menu item 5.")
    for other in profiles:
        if other is not profile:
            sites = len(as_list(other.get("website_list")))
            clients = len(as_list(other.get("client_list")))
            print(f'Other profile on the router: "{other.get("name")}", {sites} sites, {clients} devices.')


def add_sites(blocklist: Blocklist) -> None:
    print("Type one or more sites. Put spaces or commas between the sites.")
    raw = input("> ")
    profiles, index, profile = blocklist.state()
    current = as_list(profile.get("website_list")) if profile else []
    added = []
    for item in split_input(raw):
        site = site_entry(item)
        if not site:
            continue
        if site in current or site in added:
            print(f"  {site} is already in the blocklist.")
            continue
        question = f'  "{site}" has no dot. The router will block every address that contains it. Add it?'
        if "." not in site and not ask_yes(question):
            continue
        added.append(site)
    if not added:
        return
    if len(current) + len(added) > blocklist.max_sites:
        print(
            f"Too many entries. The router allows a maximum of {blocklist.max_sites} entries. "
            f"The blocklist has {len(current)} entries."
        )
        return
    if profile is None:
        print("The router has no Blocklist profile yet. Select the devices that the blocklist applies to.")
        clients = pick_devices(blocklist, profiles, None)
        if clients is None:
            print("Cancelled.")
            return
        blocklist.create(added, clients)
        if not clients:
            print("You selected no devices. The blocklist applies to no device. Add devices in menu item 5.")
    else:
        blocklist.save(index, profile, sites=current + added)
    print("Added: " + ", ".join(added))


def remove_sites(blocklist: Blocklist) -> None:
    _, index, profile = blocklist.state()
    sites = as_list(profile.get("website_list")) if profile else []
    if not sites:
        print("The blocklist is empty.")
        return
    for number, site in enumerate(sites, 1):
        print(f"  {number}. {site}")
    print("Type the numbers or the sites to remove. Put spaces between them. Press Enter to cancel.")
    raw = input("> ")
    chosen = []
    for item in split_input(raw):
        if item.isdigit() and 1 <= int(item) <= len(sites):
            site = sites[int(item) - 1]
        else:
            site = site_entry(item)
            if site not in sites:
                print(f"  {item} is not in the blocklist.")
                continue
        if site not in chosen:
            chosen.append(site)
    if not chosen:
        return
    blocklist.save(index, profile, sites=[site for site in sites if site not in chosen])
    print("Removed: " + ", ".join(chosen))


def edit_devices(blocklist: Blocklist) -> None:
    profiles, index, profile = blocklist.state()
    clients = pick_devices(blocklist, profiles, profile)
    if clients is None:
        return
    before = {mac_key(c.get("mac")) for c in as_list(profile.get("client_list"))} if profile else set()
    if {mac_key(c["mac"]) for c in clients} == before:
        print("No changes.")
        return
    if profile is None:
        blocklist.create([], clients)
    else:
        blocklist.save(index, profile, clients=clients)
    print(f"Saved. Devices in the profile: {len(clients)}.")


def lan_address() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((ROUTER, 9))
        return sock.getsockname()[0]


def resolve(host: str) -> list[str]:
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ValueError:
        pass
    for server in DOH_SERVERS:
        try:
            response = requests.get(
                server,
                params={"name": host, "type": "A"},
                headers={"accept": "application/dns-json"},
                timeout=CHECK_TIMEOUT,
            )
            answers = response.json().get("Answer") or []
        except (requests.RequestException, ValueError):
            continue
        addresses = [answer["data"] for answer in answers if answer.get("type") == 1]
        if addresses:
            return addresses
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return [info[4][0] for info in infos if ipaddress.ip_address(info[4][0]) not in FAKE_IP_NET]


def skip_dns_name(data: bytes, pos: int) -> int:
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += length + 1


def router_dns_query(host: str, source: str) -> tuple[int, list[str]]:
    labels = b"".join(bytes([len(part)]) + part for part in host.encode("idna").split(b"."))
    header = struct.pack(">HHHHHH", secrets.randbelow(65536), 0x0100, 1, 0, 0, 0)
    packet = header + labels + b"\x00" + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.bind((source, 0))
        sock.sendto(packet, (ROUTER, 53))
        data = sock.recv(4096)
    flags, questions, answers = struct.unpack(">HHH", data[2:8])
    pos = 12
    for _ in range(questions):
        pos = skip_dns_name(data, pos) + 4
    addresses = []
    for _ in range(answers):
        pos = skip_dns_name(data, pos)
        record_type, _, _, length = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if record_type == 1 and length == 4:
            addresses.append(socket.inet_ntoa(data[pos:pos + 4]))
        pos += length
    return flags & 0xF, addresses


def router_dns_state(host: str, source: str) -> str:
    try:
        rcode, addresses = router_dns_query(host, source)
    except (OSError, struct.error, IndexError):
        return "no_answer"
    if rcode == 3 or not addresses:
        return "blocked"
    if all(ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_unspecified for a in addresses):
        return "blocked"
    return "real"


def probe_tls(host: str, address: str, source: str, short_hello: bool) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CHECK_TIMEOUT)
    try:
        sock.bind((source, 0))
        sock.connect((address, 443))
    except OSError:
        sock.close()
        return "no_connect"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if short_hello:
        context.set_ecdh_curve("X25519")
    try:
        with context.wrap_socket(sock, server_hostname=host):
            return "open"
    except OSError:
        return "dropped"
    finally:
        sock.close()


def probe_http(host: str, address: str, source: str) -> str:
    try:
        sock = socket.create_connection((address, 80), timeout=CHECK_TIMEOUT, source_address=(source, 0))
    except OSError:
        return "no_connect"
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    data = b""
    with sock:
        try:
            sock.sendall(request.encode())
            while len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
    if b"blocking" in data and b"tplinkwifi" in data:
        return "block_page"
    return "open" if data else "dropped"


def verdict(dns: str, short: str, long: str | None, http: str | None, by_router: bool) -> str:
    if dns == "blocked":
        return "The router does not return the site address. Devices that use the router DNS cannot open the site."
    if short == "no_connect" and long in ("no_connect", None):
        if http == "block_page":
            return "The router blocks the site over HTTP."
        return "The server does not respond. The script cannot check the site."
    if short == "open" and long in ("open", None):
        if by_router:
            return "The site opens, but it is in the blocklist. Wait a short time and check again."
        return "The site opens."
    if short == "dropped" and long == "open":
        if by_router:
            return "The router blocks only the short ClientHello. A recent Chrome will open the site."
        return "The short ClientHello fails. The long ClientHello passes."
    if short == "dropped" and long is None:
        return "The short ClientHello fails. This Python cannot test the long ClientHello."
    if short == "dropped" and long == "dropped":
        if by_router:
            return "The router blocks the site."
        return (
            "The site does not open. The router does not block it for this computer. "
            "Something else blocks it, for example the ISP."
        )
    return "The results do not agree. Read the lines above."


def check_site(blocklist: Blocklist) -> None:
    host = host_of(input("Site: "))
    if not host:
        return
    try:
        host = host.encode("idna").decode()
    except UnicodeError:
        pass
    _, _, profile = blocklist.state()
    sites = as_list(profile.get("website_list")) if profile else []
    clients = as_list(profile.get("client_list")) if profile else []
    matches = [site for site in sites if site in host]
    mine = any(mac_key(c.get("mac")) == blocklist.my_mac for c in clients)
    print(f"  In the blocklist: {', '.join(matches) if matches else 'no'}")
    print(f"  This computer is in the profile: {'yes' if mine else 'no'}")
    addresses = resolve(host)
    if not addresses:
        print("  The script cannot find the site IP address. It cannot check the connection.")
        return
    source = lan_address()
    address = addresses[0]
    dns = router_dns_state(host, source)
    short = probe_tls(host, address, source, short_hello=True)
    long = probe_tls(host, address, source, short_hello=False) if LONG_HELLO else None
    http = None if short == "open" else probe_http(host, address, source)
    print(f"  Check from {source} through the router, without a local VPN. Site IP address: {address}.")
    print(f"    Router DNS: {DNS_TEXT[dns]}")
    print(f"    HTTPS, short ClientHello like curl: {TLS_TEXT[short]}")
    if long:
        print(f"    HTTPS, long ClientHello with ML-KEM like a recent Chrome: {TLS_TEXT[long]}")
    else:
        print("    HTTPS, long ClientHello: this Python cannot send it. It needs OpenSSL 3.5 or later.")
    if http:
        print(f"    {HTTP_TEXT[http]}")
    print(f"  Result: {verdict(dns, short, long, http, bool(matches) and mine)}")
    if matches and not mine:
        print(
            "  This computer is not in the profile. The check does not show the result for the devices in the profile.")


def stored_password() -> str | None:
    if keyring is None:
        return None
    try:
        return keyring.get_password(KEYRING_SERVICE, ROUTER)
    except KeyringError:
        return None


def remember_password(password: str) -> None:
    if keyring is None or not ask_yes("Save the password in the system keyring?"):
        return
    try:
        keyring.set_password(KEYRING_SERVICE, ROUTER, password)
    except KeyringError as error:
        print(f"Could not save the password: {error}")


def forget_password() -> None:
    if keyring is None:
        return
    try:
        keyring.delete_password(KEYRING_SERVICE, ROUTER)
    except KeyringError:
        pass


def connect() -> TPLinkClient:
    env_password = os.environ.get("TPLINK_PASSWORD")
    saved = None if env_password else stored_password()
    password = env_password or saved
    for _ in range(3):
        typed = password is None
        if typed:
            password = getpass.getpass(f"Password for router {ROUTER}: ")
        client = TPLinkClient(ROUTER, password)
        try:
            client.login()
        except LoginError as error:
            print(f"Login failed: {error}")
            if saved is not None and password == saved:
                forget_password()
                saved = None
            if not error.can_retry or env_password:
                break
            password = None
            continue
        if typed:
            remember_password(password)
        return client
    raise SystemExit(1)


ACTIONS = {"1": show_list, "2": add_sites, "3": remove_sites, "4": check_site, "5": edit_devices}


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    try:
        client = connect()
    except requests.RequestException as error:
        raise SystemExit(f"Router {ROUTER} does not respond: {error}")
    try:
        blocklist = Blocklist(client)
        while True:
            print(MENU.format(router=ROUTER))
            choice = input("> ").strip().lower()
            if choice in ("0", "q"):
                break
            action = ACTIONS.get(choice)
            if action is None:
                continue
            try:
                action(blocklist)
            except RouterError as error:
                print(f"The router returned an error: {error}")
            except requests.RequestException as error:
                print(f"The router does not respond: {error}")
    except (KeyboardInterrupt, EOFError):
        print()
    except (RouterError, requests.RequestException) as error:
        print(f"Error: {error}")
    finally:
        client.logout()


if __name__ == "__main__":
    main()
