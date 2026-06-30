import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from devbout_oauth import (
    GOOGLE,
    MICROSOFT,
    DevboutAuth,
    EmailSender,
    InMemoryConnectionStorage,
    NangoConfig,
    create_router,
)
from devbout_oauth import identity as identity_mod
from devbout_oauth import router as router_mod
from devbout_oauth.identity import Identity
from devbout_oauth.nango_client import NangoClient
from devbout_oauth.state import verify_login_nonce

SIGNING_KEY = "test-signing-key"


def _config() -> NangoConfig:
    return NangoConfig(
        nango_host="http://nango.test",
        nango_secret_key="secret",
        frontend_url="http://front.test",
        state_signing_key=SIGNING_KEY,
    )


def _app(storage, user_id="user_42"):
    app = FastAPI()
    app.include_router(
        create_router(
            config=_config(),
            storage=storage,
            get_current_user_id=lambda: user_id,
            prefix="/auth",
        )
    )
    return app


@pytest.fixture
def conn_holder():
    """Mutable connection dict the fake NangoClient.get_connection returns."""
    return {}


@pytest.fixture(autouse=True)
def patch_nango(monkeypatch, conn_holder):
    async def fake_session(self, end_user, allowed_integrations, integrations_config_defaults=None):
        conn_holder["last_end_user"] = end_user["id"]
        return "session-token"

    async def fake_get_connection(self, connection_id, provider_config_key, force_refresh=False):
        return conn_holder["connection"]

    async def fake_delete(self, connection_id, provider_config_key):
        conn_holder["deleted"] = connection_id

    monkeypatch.setattr(NangoClient, "create_connect_session", fake_session)
    monkeypatch.setattr(NangoClient, "get_connection", fake_get_connection)
    monkeypatch.setattr(NangoClient, "delete_connection", fake_delete)


def _patch_identity(monkeypatch, ident: Identity):
    async def fake_identity(provider, access_token):
        return ident
    monkeypatch.setattr(router_mod, "fetch_identity", fake_identity)


# ── Login ────────────────────────────────────────────────────────────────────

def test_login_flow(monkeypatch, conn_holder):
    storage = InMemoryConnectionStorage()
    client = TestClient(_app(storage))

    r = client.post("/auth/connect/login/session", json={"provider": GOOGLE})
    assert r.status_code == 200
    body = r.json()
    assert body["sessionToken"] == "session-token"
    nonce_id = verify_login_nonce(body["nonce"], SIGNING_KEY)
    assert conn_holder["last_end_user"] == nonce_id

    # Nango returns a connection whose end_user matches the nonce.
    conn_holder["connection"] = {
        "end_user": {"id": nonce_id},
        "credentials": {"access_token": "at-google"},
    }
    _patch_identity(monkeypatch, Identity(GOOGLE, "gid-1", "ana@x.com", "Ana", "Gomez"))

    r = client.post("/auth/connect/login/finalize", json={
        "connectionId": "conn-1", "provider": GOOGLE, "nonce": body["nonce"],
    })
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["email"] == "ana@x.com"
    assert out["token"].startswith("test_token_")


def test_login_rejects_mismatched_connection(monkeypatch):
    storage = InMemoryConnectionStorage()
    client = TestClient(_app(storage))
    nonce = client.post("/auth/connect/login/session", json={"provider": GOOGLE}).json()["nonce"]

    # Attacker-supplied connection bound to a different end_user.
    conn_holder = {"connection": {"end_user": {"id": "someone_else"}, "credentials": {"access_token": "x"}}}
    monkeypatch.setattr(
        NangoClient, "get_connection",
        lambda self, cid, pck, force_refresh=False: _async(conn_holder["connection"]),
    )
    r = client.post("/auth/connect/login/finalize", json={
        "connectionId": "conn-x", "provider": GOOGLE, "nonce": nonce,
    })
    assert r.status_code == 400


# ── Email connect ──────────────────────────────────────────────────────────────

def test_email_connect_flow(monkeypatch, conn_holder):
    storage = InMemoryConnectionStorage()
    client = TestClient(_app(storage, user_id="user_42"))

    r = client.post("/auth/connect/email/session", json={"provider": MICROSOFT})
    assert r.status_code == 200
    assert conn_holder["last_end_user"] == "user_42"

    conn_holder["connection"] = {
        "end_user": {"id": "user_42"},
        "credentials": {"access_token": "at-ms"},
    }
    _patch_identity(monkeypatch, Identity(MICROSOFT, "mid", "bob@x.com", "Bob", "M"))

    r = client.post("/auth/connect/email/finalize", json={
        "connectionId": "conn-ms", "provider": MICROSOFT,
    })
    assert r.status_code == 200
    record = storage._connections["user_42"]
    assert record == (MICROSOFT, "conn-ms", "bob@x.com")


def test_email_finalize_rejects_other_users_connection(monkeypatch, conn_holder):
    storage = InMemoryConnectionStorage()
    client = TestClient(_app(storage, user_id="user_42"))
    conn_holder["connection"] = {"end_user": {"id": "user_99"}, "credentials": {"access_token": "x"}}
    _patch_identity(monkeypatch, Identity(MICROSOFT, "mid", "bob@x.com", "Bob", "M"))
    r = client.post("/auth/connect/email/finalize", json={
        "connectionId": "conn-ms", "provider": MICROSOFT,
    })
    assert r.status_code == 403


def test_disconnect_revokes_and_clears(conn_holder):
    storage = InMemoryConnectionStorage()
    import asyncio
    asyncio.get_event_loop().run_until_complete(
        storage.save_connection("user_42", GOOGLE, "conn-1", "a@x.com")
    )
    client = TestClient(_app(storage, user_id="user_42"))
    r = client.delete("/auth/disconnect")
    assert r.status_code == 204
    assert conn_holder["deleted"] == "conn-1"
    assert "user_42" not in storage._connections


def test_unsupported_provider_rejected():
    client = TestClient(_app(InMemoryConnectionStorage()))
    r = client.post("/auth/connect/login/session", json={"provider": "facebook"})
    assert r.status_code == 400


# ── Identity mapping ────────────────────────────────────────────────────────────

async def test_identity_google(monkeypatch):
    async def fake_json(url, token):
        return {"sub": "g1", "email": "a@g.com", "given_name": "A", "family_name": "G"}
    monkeypatch.setattr(identity_mod, "_get_json", fake_json)
    ident = await identity_mod.fetch_identity(GOOGLE, "tok")
    assert (ident.provider, ident.provider_user_id, ident.email) == (GOOGLE, "g1", "a@g.com")


async def test_identity_microsoft_falls_back_to_upn(monkeypatch):
    async def fake_json(url, token):
        return {"id": "m1", "mail": None, "userPrincipalName": "b@live.com", "givenName": "B", "surname": "M"}
    monkeypatch.setattr(identity_mod, "_get_json", fake_json)
    ident = await identity_mod.fetch_identity(MICROSOFT, "tok")
    assert ident.email == "b@live.com" and ident.provider_user_id == "m1"


# ── Email sending routes to the right provider ───────────────────────────────────

async def test_email_sender_routing(monkeypatch):
    calls = {}

    async def fake_gmail(cls, access_token, to, subject, body_html, from_address, from_name, cc):
        calls["provider"] = "google"

    async def fake_graph(cls, access_token, to, subject, body_html, cc):
        calls["provider"] = "microsoft"

    monkeypatch.setattr(EmailSender, "_send_gmail", classmethod(fake_gmail))
    monkeypatch.setattr(EmailSender, "_send_graph", classmethod(fake_graph))

    await EmailSender.send(GOOGLE, "at", "x@y.com", "s", "<p>h</p>")
    assert calls["provider"] == "google"
    await EmailSender.send(MICROSOFT, "at", "x@y.com", "s", "<p>h</p>")
    assert calls["provider"] == "microsoft"


async def test_facade_send_email(monkeypatch):
    storage = InMemoryConnectionStorage()
    await storage.save_connection("user_1", GOOGLE, "conn-1", "a@x.com")
    auth = DevboutAuth(_config(), storage)

    async def fake_token(self, connection_id, provider_config_key):
        return "fresh-token"
    sent = {}

    async def fake_send(provider, access_token, to, subject, body_html, **kw):
        sent.update(provider=provider, token=access_token, to=to)

    monkeypatch.setattr(NangoClient, "get_access_token", fake_token)
    monkeypatch.setattr(EmailSender, "send", staticmethod(fake_send))

    await auth.send_email("user_1", to="z@x.com", subject="s", body_html="<p>h</p>")
    assert sent == {"provider": GOOGLE, "token": "fresh-token", "to": "z@x.com"}


# ── helpers ──────────────────────────────────────────────────────────────────

def _async(value):
    async def _coro():
        return value
    return _coro()
