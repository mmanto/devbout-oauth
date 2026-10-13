"""
Passkey (WebAuthn) tests.

They run a real ceremony end-to-end: `SoftWebauthnDevice` implements the
authenticator side in software (ES256 keypair, CBOR attestation, signature
counter), which is exactly what Face ID / Windows Hello / a security key do
natively, and we adapt its bytes to the JSON shape
`@simplewebauthn/browser` posts. So attribution, challenge, origin and sign
count are verified by py_webauthn against real crypto — no mocking of the
WebAuthn layer.
"""
import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from soft_webauthn import SoftWebauthnDevice

from devbout_oauth import (
    InMemoryConnectionStorage,
    InMemoryPasskeyStorage,
    NangoConfig,
    PasskeyConfig,
    PasskeyUser,
    create_router,
)

SIGNING_KEY = "test-signing-key"
RP_ID = "app.example.com"
ORIGIN = "https://app.example.com"


# ── Storage / app wiring ──────────────────────────────────────────────────────

class _Storage(InMemoryConnectionStorage, InMemoryPasskeyStorage):
    """The single object a consumer usually passes for both contracts."""

    def __init__(self) -> None:
        InMemoryConnectionStorage.__init__(self)
        InMemoryPasskeyStorage.__init__(self)


def _nango_config() -> NangoConfig:
    return NangoConfig(
        nango_host="http://nango.test",
        nango_secret_key="secret",
        frontend_url="http://front.test",
        state_signing_key=SIGNING_KEY,
    )


def _passkey_config(**overrides) -> PasskeyConfig:
    options = {"rp_id": RP_ID, "rp_name": "Devbout", "origins": [ORIGIN]}
    options.update(overrides)
    return PasskeyConfig(**options)


def _client(storage, user_id="user_42", *, passkeys=None, **kwargs) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_router(
            config=_nango_config(),
            storage=storage,
            get_current_user_id=lambda: user_id,
            prefix="/auth",
            passkeys=_passkey_config() if passkeys is None else passkeys,
            **kwargs,
        )
    )
    return TestClient(app)


def _storage_with_user(user_id="user_42", username="ana@example.com") -> _Storage:
    storage = _Storage()
    storage.users[user_id] = PasskeyUser(user_id=user_id, username=username, display_name="Ana")
    return storage


# ── Authenticator (browser side) ──────────────────────────────────────────────

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _device_options(options: dict) -> dict:
    """
    `SoftWebauthnDevice` works with bytes, wrapped as `{publicKey: …}`; the
    server serves base64url strings flat (the `optionsJSON` that
    @simplewebauthn/browser feeds to `startRegistration`/`startAuthentication`).
    """
    public_key = dict(options)
    public_key["challenge"] = _unb64(public_key["challenge"])
    if "user" in public_key:  # registration only; login has no user entity
        public_key["user"] = {**public_key["user"], "id": _unb64(public_key["user"]["id"])}
    for field in ("excludeCredentials", "allowCredentials"):
        if public_key.get(field):
            public_key[field] = [{**c, "id": _unb64(c["id"])} for c in public_key[field]]
    return {"publicKey": public_key}


def _wire(payload: dict) -> dict:
    """The JSON @simplewebauthn/browser returns to the frontend."""
    response = {
        key: _b64(value)
        for key, value in payload["response"].items()
        if isinstance(value, bytes)
    }
    response["transports"] = ["internal"]
    return {
        "id": _b64(payload["rawId"]),
        "rawId": _b64(payload["rawId"]),
        "response": response,
        "type": "public-key",
        "clientExtensionResults": {},
    }


class _ReusingDevice(SoftWebauthnDevice):
    """
    An authenticator that re-attests the credential it already holds (real ones
    can do this when the RP asks to register again).
    """

    def cred_init(self, rp_id, user_handle):
        if self.credential_id is None:
            super().cred_init(rp_id, user_handle)


def _register(device, client, *, origin=ORIGIN, name="Face ID del iPhone", **post_kwargs) -> dict:
    options = client.post("/auth/passkey/register/options").json()
    credential = _wire(device.create(_device_options(options["options"]), origin))
    response = client.post(
        "/auth/passkey/register/verify",
        json={"credential": credential, "challengeToken": options["challengeToken"], "name": name},
        **post_kwargs,
    )
    return {"response": response, "credential": credential, "options": options}


def _login(device, client, *, username=None, origin=ORIGIN):
    options = client.post("/auth/passkey/login/options", json={"username": username}).json()
    credential = _wire(device.get(_device_options(options["options"]), origin))
    response = client.post(
        "/auth/passkey/login/verify",
        json={"credential": credential, "challengeToken": options["challengeToken"]},
    )
    return {"response": response, "credential": credential, "options": options}


# ── Registration + login ──────────────────────────────────────────────────────

def test_registration_then_login_with_username():
    storage = _storage_with_user()
    client = _client(storage)
    device = SoftWebauthnDevice()

    registered = _register(device, client, name="Huella del Pixel")
    assert registered["response"].status_code == 200, registered["response"].text
    body = registered["response"].json()
    assert body["status"] == "registered"
    assert body["name"] == "Huella del Pixel"
    assert body["deviceType"] in {"single_device", "multi_device"}

    stored = storage.credentials[body["credentialId"]]
    assert stored.user_id == "user_42"
    assert stored.public_key and stored.sign_count == 0
    assert stored.transports == ["internal"]

    options = client.post(
        "/auth/passkey/login/options", json={"username": "ana@example.com"}
    ).json()["options"]
    assert [c["id"] for c in options["allowCredentials"]] == [body["credentialId"]]

    login = _login(device, client, username="ana@example.com")
    assert login["response"].status_code == 200, login["response"].text
    assert login["response"].json() == {
        "token": "test_token_user_42",
        "provider": "passkey",
        "username": "ana@example.com",
        "display_name": "Ana",
    }
    assert storage.credentials[body["credentialId"]].sign_count == 1


def test_login_usernameless_offers_discoverable_credentials():
    storage = _storage_with_user()
    client = _client(storage)
    device = SoftWebauthnDevice()
    assert _register(device, client)["response"].status_code == 200

    options = client.post("/auth/passkey/login/options", json={}).json()["options"]
    assert not options.get("allowCredentials")

    login = _login(device, client)
    assert login["response"].status_code == 200, login["response"].text
    assert login["response"].json()["token"] == "test_token_user_42"


def test_login_options_do_not_reveal_unknown_usernames():
    client = _client(_storage_with_user())
    options = client.post("/auth/passkey/login/options", json={"username": "nadie@x.com"})
    assert options.status_code == 200
    assert not options.json()["options"].get("allowCredentials")


# ── Rejection paths ───────────────────────────────────────────────────────────

def test_login_rejects_unknown_credential():
    client = _client(_storage_with_user())
    options = client.post("/auth/passkey/login/options", json={}).json()
    device = SoftWebauthnDevice()
    device.cred_init(RP_ID, b"user_42")
    credential = _wire(device.get(_device_options(options["options"]), ORIGIN))

    response = client.post(
        "/auth/passkey/login/verify",
        json={"credential": credential, "challengeToken": options["challengeToken"]},
    )
    assert response.status_code == 401


def test_login_rejects_challenge_from_another_ceremony():
    storage = _storage_with_user()
    client = _client(storage)
    device = SoftWebauthnDevice()
    assert _register(device, client)["response"].status_code == 200

    first = client.post("/auth/passkey/login/options", json={}).json()
    second = client.post("/auth/passkey/login/options", json={}).json()
    credential = _wire(device.get(_device_options(first["options"]), ORIGIN))

    response = client.post(
        "/auth/passkey/login/verify",
        json={"credential": credential, "challengeToken": second["challengeToken"]},
    )
    assert response.status_code == 401


def test_login_rejects_replayed_assertion():
    """Same assertion twice: the signature counter didn't advance."""
    storage = _storage_with_user()
    client = _client(storage)
    device = SoftWebauthnDevice()
    assert _register(device, client)["response"].status_code == 200
    assert _login(device, client)["response"].status_code == 200

    options = client.post("/auth/passkey/login/options", json={}).json()
    credential = _wire(device.get(_device_options(options["options"]), ORIGIN))
    body = {"credential": credential, "challengeToken": options["challengeToken"]}
    assert client.post("/auth/passkey/login/verify", json=body).status_code == 200
    replay = client.post("/auth/passkey/login/verify", json=body)
    assert replay.status_code == 401


def test_registration_rejects_other_origin():
    storage = _storage_with_user()
    client = _client(storage)
    outcome = _register(SoftWebauthnDevice(), client, origin="https://evil.example")
    assert outcome["response"].status_code == 400
    assert not storage.credentials


def test_login_rejects_other_origin():
    storage = _storage_with_user()
    client = _client(storage)
    device = SoftWebauthnDevice()
    assert _register(device, client)["response"].status_code == 200
    assert _login(device, client, origin="https://evil.example")["response"].status_code == 401


def test_registration_challenge_cannot_be_reused_for_login():
    storage = _storage_with_user()
    client = _client(storage)
    registered = _register(SoftWebauthnDevice(), client)
    assert registered["response"].status_code == 200

    response = client.post(
        "/auth/passkey/login/verify",
        json={
            "credential": registered["credential"],
            "challengeToken": registered["options"]["challengeToken"],
        },
    )
    assert response.status_code == 400


def test_registration_challenge_bound_to_its_user():
    storage = _storage_with_user(user_id="user_A", username="a@x.com")
    storage.users["user_B"] = PasskeyUser("user_B", "b@x.com", "B")
    device = SoftWebauthnDevice()

    options = _client(storage, "user_A").post("/auth/passkey/register/options").json()
    credential = _wire(device.create(_device_options(options["options"]), ORIGIN))

    response = _client(storage, "user_B").post(
        "/auth/passkey/register/verify",
        json={"credential": credential, "challengeToken": options["challengeToken"]},
    )
    assert response.status_code == 403
    assert not storage.credentials


def test_registration_rejects_credential_already_registered():
    storage = _storage_with_user()
    client = _client(storage)
    device = _ReusingDevice()
    assert _register(device, client)["response"].status_code == 200
    assert len(storage.credentials) == 1

    second = _register(device, client)
    assert second["response"].status_code == 409
    assert len(storage.credentials) == 1


def test_registration_requires_known_user():
    client = _client(_Storage())
    assert client.post("/auth/passkey/register/options").status_code == 404


# ── Credential management ─────────────────────────────────────────────────────

def test_list_and_delete_only_own_credentials():
    storage = _storage_with_user(user_id="user_A", username="a@x.com")
    storage.users["user_B"] = PasskeyUser("user_B", "b@x.com", "B")
    device = SoftWebauthnDevice()
    registered = _register(device, _client(storage, "user_A"))
    credential_id = registered["response"].json()["credentialId"]

    assert _client(storage, "user_A").get("/auth/passkey/credentials").json()["credentials"] == [
        {
            "id": credential_id,
            "name": "Face ID del iPhone",
            "transports": ["internal"],
            "created_at": None,
        }
    ]
    assert _client(storage, "user_B").get("/auth/passkey/credentials").json() == {"credentials": []}

    assert _client(storage, "user_B").delete(f"/auth/passkey/credentials/{credential_id}").status_code == 404
    assert _client(storage, "user_A").delete(f"/auth/passkey/credentials/{credential_id}").status_code == 204
    assert storage.credentials == {}

    assert _login(device, _client(storage, "user_A"))["response"].status_code == 401


def test_passkey_storage_can_be_a_separate_object():
    connections = InMemoryConnectionStorage()
    passkeys = _storage_with_user()
    client = _client(connections, passkey_storage=passkeys)
    assert _register(SoftWebauthnDevice(), client)["response"].status_code == 200
    assert len(passkeys.credentials) == 1


# ── Wiring / configuration ────────────────────────────────────────────────────

def test_passkey_routes_are_opt_in():
    app = FastAPI()
    app.include_router(
        create_router(
            config=_nango_config(),
            storage=_Storage(),
            get_current_user_id=lambda: "user_42",
            prefix="/auth",
        )
    )
    assert TestClient(app).post("/auth/passkey/login/options", json={}).status_code == 404


def test_passkeys_require_passkey_capable_storage():
    with pytest.raises(ValueError, match="PasskeyStorage"):
        create_router(
            config=_nango_config(),
            storage=InMemoryConnectionStorage(),
            get_current_user_id=lambda: "user_42",
            passkeys=_passkey_config(),
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"rp_id": "https://app.example.com"},
        {"rp_id": "app.example.com:8443"},
        {"origins": []},
        {"origins": ["app.example.com"]},
        {"origins": ["https://app.example.com/"]},
        {"user_verification": "siempre"},
        {"resident_key": "quizas"},
        {"challenge_ttl_minutes": 0},
    ],
)
def test_passkey_config_rejects_invalid_values(overrides):
    with pytest.raises(ValueError):
        _passkey_config(**overrides)
