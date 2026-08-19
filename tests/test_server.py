#!/usr/bin/env python3
"""Tests fuer Signierdienst und Client.

Stil wie die uebrigen Suiten: kein Framework, ``check()`` bricht beim ersten
Fehler ab, alles laeuft in einem Temp-Verzeichnis und fasst weder ``~/.ssh-ca``
noch ``~/.ssh-ca-client`` an.

Es wird nichts gemockt: echte Schluessel, echte Zertifikate, echte SSHSIG-
Signaturen und — wenn ``openssl`` vorhanden ist — ein echter TLS-Server auf
127.0.0.1 mit einem Wegwerfzertifikat.

    python3 tests/test_server.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sshca.ca import CertificateAuthority  # noqa: E402
from sshca.config import CaError, Paths  # noqa: E402
from sshca.keygen import Ssh  # noqa: E402
from sshca.protocol import (  # noqa: E402
    ProtocolError,
    canonical_request,
    sign_message,
    verify_message,
)
from sshca.protocol import cap_validity, seconds_to_spec, validity_seconds  # noqa: E402
from sshca.server.api import Api  # noqa: E402
from sshca.server.config import ServerConfig  # noqa: E402
from sshca.server.registry import Registry, parse_duration  # noqa: E402

PASSED = 0


def check(label: str, condition: bool) -> None:
    global PASSED
    if condition:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        print(f"  FEHL {label}")
        raise SystemExit(1)


def expect_error(label: str, fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except (CaError, ProtocolError) as exc:
        check(f"{label} → {type(exc).__name__}", True)
    else:
        check(f"{label} (Fehler erwartet)", False)


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)))


# --------------------------------------------------------------- Grundgerüst
def build_ca(base: Path) -> CertificateAuthority:
    ca = CertificateAuthority(Paths(base))
    ca.init_ca("", comment="test-ca")
    ca.paths.principals_file.write_text(
        "# Test\nadmins\ndevops\nnotfall\n", encoding="utf-8"
    )
    return ca


def build_config(base: Path, state: Path, cert: Path, key: Path) -> ServerConfig:
    return ServerConfig(
        listen="127.0.0.1",
        port=0,
        tls_cert=cert,
        tls_key=key,
        ca_base=base,
        state_dir=state,
        signing="none",
        max_validity="+9h",
    )


def self_signed(directory: Path) -> tuple[Path, Path] | None:
    """Wegwerfzertifikat fuer den TLS-Test. None, wenn openssl fehlt."""
    if shutil.which("openssl") is None:
        return None
    cert = directory / "server.pem"
    key = directory / "server.key"
    config = directory / "openssl.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
        "[dn]\nCN=localhost\n"
        "[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-config", str(config),
        ],
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    key.chmod(0o600)
    return cert, key


# ------------------------------------------------------------------- Protokoll
def test_protocol(tmp: Path, ssh: Ssh) -> None:
    section("Protokoll: SSHSIG über Anfragen")

    key = tmp / "id"
    ssh.run(["-t", "ed25519", "-f", str(key), "-N", "", "-C", "test"])
    pubkey = (tmp / "id.pub").read_text(encoding="utf-8").strip()
    other = tmp / "other"
    ssh.run(["-t", "ed25519", "-f", str(other), "-N", "", "-C", "test2"])
    other_pub = (tmp / "other.pub").read_text(encoding="utf-8").strip()

    body = json.dumps({"pubkey": "x"}).encode()
    stamp = "2026-01-01T00:00:00+00:00"
    message = canonical_request("POST", "/v1/sign", "d@jump", stamp, "abc", body)
    check("Kanonisierung endet mit Zeilenumbruch", message.endswith(b"\n"))
    check("Kanonisierung enthält sechs Felder", message.count(b"\n") == 6)
    check(
        "Kanonisierung ist stabil",
        message == canonical_request(
            "POST", "/v1/sign", "d@jump", "2026-01-01T00:00:00+00:00", "abc", body
        ),
    )
    expect_error(
        "Zeilenumbruch im Feld wird abgewiesen",
        canonical_request, "POST", "/v1/si\ngn", "d", "t", "n", body,
    )

    signature = sign_message(ssh, key, message)
    verify_message(ssh, pubkey, "d@jump", message, signature)
    check("gültige Signatur wird angenommen", True)

    expect_error(
        "fremder Schlüssel wird abgewiesen",
        verify_message, ssh, other_pub, "d@jump", message, signature,
    )
    tampered = canonical_request(
        "POST", "/v1/sign", "d@jump", "2026-01-01T00:00:00+00:00", "abc",
        json.dumps({"pubkey": "y"}).encode(),
    )
    expect_error(
        "veränderter Rumpf wird abgewiesen",
        verify_message, ssh, pubkey, "d@jump", tampered, signature,
    )
    other_path = canonical_request(
        "POST", "/v1/enroll", "d@jump", "2026-01-01T00:00:00+00:00", "abc", body
    )
    expect_error(
        "anderer Endpunkt wird abgewiesen",
        verify_message, ssh, pubkey, "d@jump", other_path, signature,
    )
    # Die Client-ID haengt nicht an allowed_signers — dort ist sie nur der
    # Nachschlagename. Gebunden wird sie ueber die kanonische Nachricht: eine
    # Signatur fuer 'd@jump' passt nicht zu einer Anfrage von 'fremd@jump'.
    foreign = canonical_request(
        "POST", "/v1/sign", "fremd@jump", "2026-01-01T00:00:00+00:00", "abc", body
    )
    expect_error(
        "Signatur eines anderen Clients wird abgewiesen",
        verify_message, ssh, pubkey, "fremd@jump", foreign, signature,
    )
    expect_error(
        "kaputtes Base64 wird abgewiesen",
        verify_message, ssh, pubkey, "d@jump", message, "kein-base64!!",
    )


# -------------------------------------------------------------------- Registry
def test_registry(tmp: Path) -> None:
    section("Registry: Tokens und Clients")

    registry = Registry(tmp / "state")
    registry.ensure_layout()
    check("Zustandsverzeichnis ist 0700",
          (tmp / "state").stat().st_mode & 0o777 == 0o700)

    check("parse_duration 24h", parse_duration("24h") == 86400)
    check("parse_duration 90m", parse_duration("90m") == 5400)
    expect_error("parse_duration lehnt Unsinn ab", parse_duration, "bald")

    token, secret = registry.create_token(
        user="dennis", principals=["dennis", "admins"], lifetime="1h"
    )
    check("Token-Klartext hat die Form <id>.<secret>",
          secret.startswith(token.id + ".") and len(secret) > 20)
    stored = json.loads(
        (registry.enroll_dir / f"{token.id}.json").read_text(encoding="utf-8")
    )
    check("Geheimnis liegt nicht im Klartext auf der Platte",
          secret.split(".", 1)[1] not in json.dumps(stored))
    check("Tokendatei ist 0600",
          (registry.enroll_dir / f"{token.id}.json").stat().st_mode & 0o777 == 0o600)

    expect_error("falsches Geheimnis", registry.consume_token,
                 f"{token.id}.falsch", "dennis@jump")
    expect_error("unbekannte ID", registry.consume_token,
                 "deadbeef.egal", "dennis@jump")
    expect_error("Form ohne Punkt", registry.consume_token, "nurtext", "d@j")

    consumed = registry.consume_token(secret, "dennis@jump")
    check("Token verbraucht sich", consumed.uses_left == 0)
    expect_error("zweite Verwendung schlägt fehl", registry.consume_token,
                 secret, "dennis@jump")

    multi, multi_secret = registry.create_token(user="ansible", uses=2, lifetime="1h")
    registry.consume_token(multi_secret, "ansible@web01")
    left = [t for t in registry.list_tokens() if t.id == multi.id][0]
    check("Mehrfachtoken zählt herunter", left.uses_left == 1)
    registry.consume_token(multi_secret, "ansible@web02")
    expect_error("Mehrfachtoken ist danach leer", registry.consume_token,
                 multi_secret, "ansible@web03")

    old, old_secret = registry.create_token(user="dennis", lifetime="1h")
    path = registry.enroll_dir / f"{old.id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["expires_at"] = (
        datetime.now() - timedelta(hours=1)
    ).strftime("%Y-%m-%d %H:%M:%S")
    path.write_text(json.dumps(payload), encoding="utf-8")
    expect_error("abgelaufenes Token", registry.consume_token, old_secret, "d@j")

    fresh, fresh_secret = registry.create_token(user="dennis", lifetime="1h")
    registry.revoke_token(fresh.id)
    expect_error("zurückgezogenes Token", registry.consume_token, fresh_secret, "d@j")

    reg_token, reg_secret = registry.create_token(
        user="dennis", principals=["dennis"], lifetime="1h"
    )
    used = registry.consume_token(reg_secret, "dennis@jump")
    client = registry.register_client("dennis", "jump", "ssh-ed25519 AAAA test", used)
    check("Client-ID ist benutzer@host", client.client_id == "dennis@jump")
    check("Client wird gefunden",
          registry.get_client("dennis@jump").pubkey.endswith("test"))
    check("unbekannter Client bleibt None", registry.get_client("x@y") is None)
    check("Client-Datei ist 0600",
          registry.client_path("dennis", "jump").stat().st_mode & 0o777 == 0o600)
    check("Richtlinie kommt aus dem Token", client.principals == ["dennis"])

    registry.set_client_disabled("dennis@jump", True)
    check("Sperre wird gespeichert", registry.get_client("dennis@jump").disabled)
    registry.set_client_disabled("dennis@jump", False)
    check("Entsperren wirkt", not registry.get_client("dennis@jump").disabled)

    expect_error("Pfadausbruch im Benutzernamen", registry.create_token, "../etc")


# ------------------------------------------------------------------------- API
def test_api(tmp: Path, ssh: Ssh) -> None:
    section("API: Rechtevergabe ohne HTTP")

    base = tmp / "ca"
    state = tmp / "apistate"
    ca = build_ca(base)
    config = build_config(base, state, tmp / "x.pem", tmp / "x.key")
    api = Api(config, ca=ca)

    check("validity_seconds +9h", validity_seconds("+9h") == 9 * 3600)
    expect_error("absolute Gültigkeit über die API", validity_seconds,
                 "20200101120000:20210101120000")
    expect_error("forever über die API", validity_seconds, "always:forever")

    info = api.info()
    check("info nennt die CA", info["ca_fingerprint"].startswith("SHA256:"))
    check("info liefert den CA-Public-Key",
          info["ca_pubkey"].startswith("ssh-ed25519 "))

    key = tmp / "client_id"
    ssh.run(["-t", "ed25519", "-f", str(key), "-N", "", "-C", "client"])
    pubkey = (tmp / "client_id.pub").read_text(encoding="utf-8").strip()

    _, secret = api.registry.create_token(
        user="dennis", principals=["dennis", "admins"],
        templates=["Kurzlebig (1 Stunde)"], max_validity="+2h", lifetime="1h",
    )
    result = api.enroll({"token": secret, "pubkey": pubkey, "host": "jump"}, "1.2.3.4")
    check("Enrollment liefert die Client-ID", result["client_id"] == "dennis@jump")
    check("Enrollment liefert die erlaubten Prinzipale",
          result["principals"] == ["dennis", "admins"])
    check("Enrollment liefert nur freigegebene Vorlagen",
          result["templates"] == ["Kurzlebig (1 Stunde)"])
    check("Obergrenze kommt aus dem Token",
          result["max_validity_seconds"] == 2 * 3600)

    expect_error("Enrollment ohne Token", api.enroll, {"pubkey": pubkey, "host": "j"})
    expect_error("Enrollment mit privatem Schlüssel", api.enroll,
                 {"token": "a.b", "pubkey": "-----BEGIN OPENSSH PRIVATE KEY-----",
                  "host": "j"})

    client = api.registry.get_client("dennis@jump")
    check("Prinzipalliste ist begrenzt",
          api.allowed_principals(client) == ["dennis", "admins"])
    check("Vorlagenliste ist begrenzt",
          [t.name for t in api.allowed_templates(client)] == ["Kurzlebig (1 Stunde)"])

    cert_key = tmp / "jump_dennis_ed25519"
    ssh.run(["-t", "ed25519", "-f", str(cert_key), "-N", "", "-C", "dennis@jump"])
    cert_pub = Path(str(cert_key) + ".pub").read_text(encoding="utf-8").strip()

    signed = api.sign(client, {
        "pubkey": cert_pub, "template": "Kurzlebig (1 Stunde)",
        "principals": ["dennis"], "validity": "+1h",
    })
    check("Zertifikat kommt zurück",
          signed["certificate"].startswith("ssh-ed25519-cert-v01@openssh.com "))
    check("Prinzipale stimmen", signed["principals"] == ["dennis"])
    check("Dateiname folgt dem Schema",
          signed["filename"] == "jump_dennis_ed25519-cert.pub")
    check("privater Schlüssel entsteht auf der CA nicht",
          not (base / "dennis" / "jump" / "jump_dennis_ed25519").exists())
    check("Public Key liegt beim CA-Bestand",
          (base / "dennis" / "jump" / "jump_dennis_ed25519.pub").is_file())

    expect_error("nicht freigegebener Prinzipal", api.sign, client, {
        "pubkey": cert_pub, "principals": ["root"],
    })
    expect_error("nicht freigegebene Vorlage", api.sign, client, {
        "pubkey": cert_pub, "template": "Notfallzugang", "principals": ["dennis"],
    })
    expect_error("ausdrücklich zu lange Gültigkeit", api.sign, client, {
        "pubkey": cert_pub, "principals": ["dennis"], "validity": "+9h",
    })

    # Ohne eigene Angabe wird die Vorlage gekürzt statt abgewiesen.
    check("seconds_to_spec rechnet grob", seconds_to_spec(7200) == "+2h")
    check("cap_validity kürzt", cap_validity("+9h", 2 * 3600) == "+2h")
    check("cap_validity lässt Kleineres in Ruhe",
          cap_validity("+30m", 2 * 3600) == "+30m")
    _, secret3 = api.registry.create_token(
        user="lang", max_validity="+2h", lifetime="1h"
    )
    ssh.run(["-t", "ed25519", "-f", str(tmp / "lang_id"), "-N", "", "-C", "lang"])
    api.enroll({
        "token": secret3,
        "pubkey": (tmp / "lang_id.pub").read_text(encoding="utf-8").strip(),
        "host": "box",
    }, "1.2.3.6")
    lang = api.registry.get_client("lang@box")
    ssh.run(["-t", "ed25519", "-f", str(tmp / "langkey"), "-N", "", "-C", "l"])
    long_template = api.sign(lang, {
        "pubkey": (tmp / "langkey.pub").read_text(encoding="utf-8").strip(),
        "template": "Arbeitstag (9 Stunden)",
        "principals": ["lang"],
    })
    check("Vorlagenvorgabe wird auf die Obergrenze gekürzt",
          long_template["validity"] == "+2h")
    expect_error("fremder Host", api.sign, client, {
        "pubkey": cert_pub, "principals": ["dennis"], "host": "anderer",
    })
    expect_error("zwei Schlüssel in einer Anfrage", api.sign, client, {
        "pubkey": cert_pub + "\n" + cert_pub, "principals": ["dennis"],
    })

    api.registry.set_client_disabled("dennis@jump", True)
    expect_error("gesperrter Client", api.sign,
                 api.registry.get_client("dennis@jump"),
                 {"pubkey": cert_pub, "principals": ["dennis"]})
    api.registry.set_client_disabled("dennis@jump", False)

    listing = api.certificates(api.registry.get_client("dennis@jump"))
    check("Client sieht sein Zertifikat", len(listing["certificates"]) == 1)
    check("Status ist gültig", listing["certificates"][0]["status"] == "gültig")

    # Ein zweiter Client darf den Benutzernamen nicht selbst bestimmen.
    _, secret2 = api.registry.create_token(user="gast", lifetime="1h")
    other_key = tmp / "gast_id"
    ssh.run(["-t", "ed25519", "-f", str(other_key), "-N", "", "-C", "gast"])
    other_pub = (tmp / "gast_id.pub").read_text(encoding="utf-8").strip()
    api.enroll({"token": secret2, "pubkey": other_pub, "host": "laptop",
                "user": "dennis"}, "1.2.3.5")
    guest = api.registry.get_client("gast@laptop")
    check("Benutzername kommt aus dem Token, nicht aus der Anfrage",
          guest is not None and guest.user == "gast")

    guest_key = tmp / "laptop_gast_ed25519"
    ssh.run(["-t", "ed25519", "-f", str(guest_key), "-N", "", "-C", "gast@laptop"])
    guest_pub = Path(str(guest_key) + ".pub").read_text(encoding="utf-8").strip()
    guest_cert = api.sign(guest, {
        "pubkey": guest_pub, "principals": ["gast"], "validity": "+1h",
    })
    check("Gast bekommt sein eigenes Verzeichnis",
          (base / "gast" / "laptop").is_dir())
    check("Gastzertifikat trägt seinen Prinzipal",
          guest_cert["principals"] == ["gast"])

    # Erneuter Antrag rotiert wie beim lokalen Erneuern nach archive/.
    ssh.run(["-t", "ed25519", "-f", str(tmp / "neu"), "-N", "", "-C", "neu"])
    neu_pub = (tmp / "neu.pub").read_text(encoding="utf-8").strip()
    api.sign(client, {"pubkey": neu_pub, "principals": ["dennis"]})
    check("Vorstand liegt im Archiv",
          any((base / "dennis" / "jump" / "archive").glob("*.pub")))

    ca.log("INFO", "Testende")
    log = ca.read_log(200)
    check("Enrollment steht im Log", "Enrollment: dennis@jump" in log)
    check("Signatur steht im Log", "Signiert für Client dennis@jump" in log)


# ------------------------------------------------------------- Ende zu Ende
def test_end_to_end(tmp: Path, ssh: Ssh) -> None:
    section("Ende zu Ende: echter TLS-Server, echter Client")

    material = self_signed(tmp / "tls")
    if material is None:
        print("  übersprungen — openssl nicht gefunden")
        return
    cert, key = material

    base = tmp / "e2e-ca"
    state = tmp / "e2e-state"
    ca = build_ca(base)
    config = build_config(base, state, cert, key)
    config.port = 18443
    api = Api(config, ca=ca)

    from sshca.client.api import (
        ClientPaths,
        Connection,
        generate_identity,
        generate_key,
    )
    from sshca.server.http import Server, build_ssl_context

    context = build_ssl_context(cert, key)
    server = Server(api, ("127.0.0.1", config.port))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    try:
        url = f"https://localhost:{config.port}"
        paths = ClientPaths(tmp / "clienthome")
        connection = Connection(url, ca_bundle=cert, ssh=ssh)

        info = connection.info()
        check("Client erreicht /v1/info über TLS",
              info["ca_fingerprint"] == ca.ca_fingerprint())

        strict = Connection(url, ca_bundle=None, ssh=ssh)
        try:
            strict.info()
            check("unbekannte CA wird abgelehnt", False)
        except CaError as exc:
            check("unbekannte CA wird abgelehnt", "Zertifikat" in str(exc))

        _, secret = api.registry.create_token(
            user="dennis", principals=["dennis", "admins", "devops"],
            lifetime="1h", max_validity="+9h",
        )
        pubkey = generate_identity(ssh, paths, "ssh-ca-client@jump")
        check("Identitätsschlüssel ist 0600",
              paths.identity.stat().st_mode & 0o777 == 0o600)

        result = connection.enroll(secret, pubkey, "jump")
        check("Enrollment über HTTPS", result["client_id"] == "dennis@jump")
        client_id = result["client_id"]

        templates = connection.templates(paths.identity, client_id)["templates"]
        check("Vorlagen kommen vom Server", len(templates) >= 1)
        principals = connection.principals(paths.identity, client_id)["principals"]
        check("Prinzipalliste kommt vom Server",
              principals == ["dennis", "admins", "devops"])

        key_path = generate_key(ssh, paths, "dennis", "jump", "")
        pub = Path(str(key_path) + ".pub").read_text(encoding="utf-8").strip()
        signed = connection.sign(paths.identity, client_id, {
            "pubkey": pub,
            "template": templates[0]["name"],
            "principals": ["dennis", "admins"],
            "validity": "+1h",
        })
        cert_path = Path(str(key_path) + "-cert.pub")
        cert_path.write_text(signed["certificate"] + "\n", encoding="utf-8")

        listing = ssh.run(["-L", "-f", str(cert_path)]).stdout
        check("Zertifikat ist lesbar", "user certificate" in listing)
        check("Prinzipale stehen im Zertifikat",
              "dennis" in listing and "admins" in listing)
        check("privater Schlüssel blieb beim Client", key_path.is_file())
        check("privater Schlüssel kam nie beim Server an",
              not (base / "dennis" / "jump" / "jump_dennis_ed25519").exists())

        material_result = connection.ca_material(paths.identity, client_id)
        check("CA-Material abrufbar",
              material_result["ca_pubkey"] == ca.ca_public_key())

        # Wiedereinspielung derselben Anfrage muss scheitern (Nonce).
        import urllib.error
        import urllib.request

        from sshca.protocol import (
            HDR_CLIENT, HDR_NONCE, HDR_SIGNATURE, HDR_TIMESTAMP,
            canonical_request, new_nonce, sign_message,
        )

        body = b""
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        nonce = new_nonce()
        message = canonical_request(
            "GET", "/v1/principals", client_id, stamp, nonce, body
        )
        signature = sign_message(ssh, paths.identity, message)

        def replay():
            request = urllib.request.Request(url + "/v1/principals", method="GET")
            request.add_header(HDR_CLIENT, client_id)
            request.add_header(HDR_TIMESTAMP, stamp)
            request.add_header(HDR_NONCE, nonce)
            request.add_header(HDR_SIGNATURE, signature)
            with urllib.request.urlopen(
                request, timeout=10, context=connection.context
            ) as response:
                return response.status

        check("erste Anfrage geht durch", replay() == 200)
        try:
            replay()
            check("Wiederholung wird abgewiesen", False)
        except urllib.error.HTTPError as exc:
            check("Wiederholung wird abgewiesen (401)", exc.code == 401)

        # Alter Zeitstempel.
        old_stamp = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat(timespec="seconds")
        old_nonce = new_nonce()
        old_message = canonical_request(
            "GET", "/v1/principals", client_id, old_stamp, old_nonce, b""
        )
        old_signature = sign_message(ssh, paths.identity, old_message)
        request = urllib.request.Request(url + "/v1/principals", method="GET")
        request.add_header(HDR_CLIENT, client_id)
        request.add_header(HDR_TIMESTAMP, old_stamp)
        request.add_header(HDR_NONCE, old_nonce)
        request.add_header(HDR_SIGNATURE, old_signature)
        try:
            urllib.request.urlopen(request, timeout=10, context=connection.context)
            check("alter Zeitstempel wird abgewiesen", False)
        except urllib.error.HTTPError as exc:
            check("alter Zeitstempel wird abgewiesen (401)", exc.code == 401)

        # Unsignierte Anfrage.
        try:
            urllib.request.urlopen(
                urllib.request.Request(url + "/v1/principals", method="GET"),
                timeout=10, context=connection.context,
            )
            check("unsignierte Anfrage wird abgewiesen", False)
        except urllib.error.HTTPError as exc:
            check("unsignierte Anfrage wird abgewiesen (401)", exc.code == 401)

        # Signatur eines fremden Schlüssels.
        fremd = tmp / "fremd"
        ssh.run(["-t", "ed25519", "-f", str(fremd), "-N", "", "-C", "fremd"])
        stamp2 = datetime.now(timezone.utc).isoformat(timespec="seconds")
        nonce2 = new_nonce()
        message2 = canonical_request(
            "GET", "/v1/principals", client_id, stamp2, nonce2, b""
        )
        request = urllib.request.Request(url + "/v1/principals", method="GET")
        request.add_header(HDR_CLIENT, client_id)
        request.add_header(HDR_TIMESTAMP, stamp2)
        request.add_header(HDR_NONCE, nonce2)
        request.add_header(HDR_SIGNATURE, sign_message(ssh, fremd, message2))
        try:
            urllib.request.urlopen(request, timeout=10, context=connection.context)
            check("fremde Signatur wird abgewiesen", False)
        except urllib.error.HTTPError as exc:
            check("fremde Signatur wird abgewiesen (401)", exc.code == 401)

        # Unbekannter Endpunkt.
        try:
            connection._request("GET", "/v1/gibtesnicht", None,
                                paths.identity, client_id)
            check("unbekannter Endpunkt wird abgewiesen", False)
        except CaError:
            check("unbekannter Endpunkt wird abgewiesen", True)
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------ Konfiguration
def test_config(tmp: Path) -> None:
    section("Konfiguration")

    path = tmp / "server.conf"
    path.write_text(
        "[server]\nlisten = 127.0.0.1\nport = 9443\n"
        f"tls_cert = {tmp}/a.pem\ntls_key = {tmp}/a.key\n"
        f"ca_base = {tmp}/ca\nstate_dir = {tmp}/state\n"
        "signing = none\nmax_validity = +4h\n",
        encoding="utf-8",
    )
    config = ServerConfig.load(path)
    check("Port wird gelesen", config.port == 9443)
    check("max_validity wird gelesen", config.max_validity == "+4h")
    check("fehlende Dateien werden gemeldet", len(config.check_files()) == 2)

    broken = tmp / "broken.conf"
    broken.write_text(
        f"[server]\ntls_cert = {tmp}/a.pem\ntls_key = {tmp}/a.key\n"
        "signing = irgendwie\n", encoding="utf-8",
    )
    expect_error("unbekannter Signierweg", ServerConfig.load, broken)

    no_tls = tmp / "notls.conf"
    no_tls.write_text("[server]\nport = 8443\n", encoding="utf-8")
    expect_error("ohne TLS kein Dienst", ServerConfig.load, no_tls)
    expect_error("fehlende Datei", ServerConfig.load, tmp / "gibtsnicht.conf")


def main() -> int:
    if shutil.which("ssh-keygen") is None:
        print("ssh-keygen wird gebraucht.")
        return 1
    ssh = Ssh()
    print("Tests für Signierdienst und Client")
    with tempfile.TemporaryDirectory(prefix="sshca-server-test-") as raw:
        tmp = Path(raw)
        os.environ["USER"] = os.environ.get("USER", "test")
        for name in ("proto", "reg", "api", "conf", "e2e", "e2e/tls"):
            (tmp / name).mkdir(parents=True, exist_ok=True)
        test_protocol(tmp / "proto", ssh)
        test_registry(tmp / "reg")
        test_api(tmp / "api", ssh)
        test_config(tmp / "conf")
        test_end_to_end(tmp / "e2e", ssh)
    print(f"\n{PASSED} Prüfungen bestanden.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
