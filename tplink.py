import base64
import hashlib
import json
import secrets
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class RouterError(Exception):
    pass


class LoginError(RouterError):
    def __init__(self, message: str, can_retry: bool = True):
        super().__init__(message)
        self.can_retry = can_retry


def rsa_encrypt(text: str, modulus_hex: str, exponent_hex: str) -> str:
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)
    size = (modulus.bit_length() + 7) // 8
    data = text.encode()
    if len(data) > size - 11:
        raise ValueError("text does not fit into one RSA block")
    filler = bytes(secrets.randbelow(255) + 1 for _ in range(size - len(data) - 3))
    block = int.from_bytes(b"\x00\x02" + filler + b"\x00" + data, "big")
    return format(pow(block, exponent, modulus), "x").zfill(max(len(modulus_hex), size * 2))


def random_digits(count: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(count))


def to_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def encode_form(params: dict) -> str:
    pairs = []
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif isinstance(value, (dict, list)):
            value = to_json(value)
        pairs.append(f"{quote(str(key), safe='')}={quote(str(value), safe='')}")
    return "&".join(pairs)


def error_code(result: dict) -> str:
    for key in ("errorcode", "errorCode", "error_code", "error"):
        if result.get(key):
            return str(result[key])
    return ""


def login_error(result: dict | None) -> LoginError:
    if not result:
        return LoginError("the router did not answer the login request")
    code = error_code(result)
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    if code == "login failed":
        left = data.get("attemptsAllowed")
        if left is not None and int(left) <= 0:
            return LoginError("wrong password. The router allows no more attempts and blocks login temporarily.",
                              can_retry=False)
        return LoginError(f"wrong password. Attempts left: {left if left is not None else '?'}")
    if code == "exceeded max attempts":
        return LoginError("the router blocks login temporarily after failed attempts. Try again later.",
                          can_retry=False)
    return LoginError(code or to_json(result))


class TPLinkClient:
    def __init__(self, host: str, password: str, timeout: float = 20):
        self.host = host
        self.password = password
        self.timeout = timeout
        self.http = requests.Session()
        self.http.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.stok = ""
        self.aes_key = ""
        self.aes_iv = ""
        self.auth_hash = ""
        self.sequence = 0
        self.sign_key = ("", "")

    def url(self, path: str) -> str:
        return f"http://{self.host}/cgi-bin/luci/;stok={self.stok}{path}"

    def cipher(self) -> Cipher:
        return Cipher(algorithms.AES(self.aes_key.encode()), modes.CBC(self.aes_iv.encode()))

    def encrypt(self, text: str) -> str:
        padder = padding.PKCS7(128).padder()
        data = padder.update(text.encode()) + padder.finalize()
        encryptor = self.cipher().encryptor()
        return base64.b64encode(encryptor.update(data) + encryptor.finalize()).decode()

    def decrypt(self, text: str) -> str:
        decryptor = self.cipher().decryptor()
        data = decryptor.update(base64.b64decode(text)) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(data) + unpadder.finalize()).decode()

    def signature(self, data_length: int, with_aes_key: bool) -> str:
        text = f"h={self.auth_hash}&s={self.sequence + data_length}"
        if with_aes_key:
            text = f"k={self.aes_key}&i={self.aes_iv}&{text}"
        return "".join(rsa_encrypt(text[pos:pos + 53], *self.sign_key) for pos in range(0, len(text), 53))

    def post_plain(self, path: str, params: dict) -> dict:
        response = self.http.post(self.url(path), data=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def post_encrypted(self, path: str, params: dict, with_aes_key: bool = False) -> dict | None:
        payload = self.encrypt(encode_form(params))
        body = {"sign": self.signature(len(payload), with_aes_key), "data": payload}
        response = self.http.post(self.url(path), data=body, timeout=self.timeout)
        if response.status_code in (401, 403):
            return None
        response.raise_for_status()
        try:
            return json.loads(self.decrypt(response.json()["data"]))
        except (ValueError, KeyError, TypeError):
            return None

    def login(self) -> None:
        self.stok = ""
        self.http.cookies.clear()
        password_key = self.post_plain("/login?form=keys", {"operation": "read"})["data"]["password"]
        auth = self.post_plain("/login?form=auth", {"operation": "read"})["data"]
        self.sign_key = tuple(auth["key"])
        self.sequence = int(auth["seq"])
        self.auth_hash = hashlib.md5(f"admin{self.password}".encode()).hexdigest()
        self.aes_key = random_digits(16)
        self.aes_iv = random_digits(16)
        params = {
            "operation": "login",
            "password": rsa_encrypt(self.password, *password_key),
            "confirm": True,
        }
        result = self.post_encrypted("/login?form=login", params, with_aes_key=True)
        if not result or not result.get("success"):
            raise login_error(result)
        self.stok = result["data"]["stok"]

    def request(self, path: str, params: dict) -> dict:
        if not self.stok:
            self.login()
        result = self.post_encrypted(path, params)
        if result is None or error_code(result) == "timeout":
            self.login()
            result = self.post_encrypted(path, params)
        if result is None:
            raise RouterError(f"{path}: the router did not accept the request")
        if result.get("success") is False:
            raise RouterError(f"{path}: {error_code(result) or to_json(result)}")
        return result

    def read(self, path: str):
        return self.request(path, {"operation": "read"}).get("data")

    def load(self, path: str):
        return self.request(path, {"operation": "load"}).get("data")

    def insert(self, path: str, record: dict, index: int = 0) -> dict:
        return self.request(path, {"operation": "insert", "index": index, "old": "add", "new": to_json(record)})

    def update(self, path: str, key: str, index: int, old: dict, new: dict) -> dict:
        params = {"operation": "update", "key": key, "index": index, "old": to_json(old), "new": to_json(new)}
        return self.request(path, params)

    def remove(self, path: str, key: str, index: int) -> dict:
        return self.request(path, {"operation": "remove", "key": key, "index": index})

    def logout(self) -> None:
        if not self.stok:
            return
        try:
            self.post_encrypted("/admin/system?form=logout", {"operation": "write"})
        except requests.RequestException:
            pass
        self.stok = ""
