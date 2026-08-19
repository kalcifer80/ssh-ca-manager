"""Fachlogik des Signierdienstes.

Diese Schicht kennt kein HTTP: sie nimmt bereits geprüfte Werte entgegen und
liefert Dictionaries zurueck — wie die Kernschicht Werte nimmt und Werte gibt.
Damit ist der Dienst ohne Netz und ohne TLS testbar; ``http.py`` daruber ist
nur noch Zuordnung von Pfaden zu Methoden.

Die Rechtevergabe steht vollstaendig hier und an einer einzigen Stelle je
Frage:

* **Wer bin ich?** — kommt aus der Registrierung, nie aus der Anfrage. Der
  Benutzername eines Zertifikats ist der des Clients; ein Client kann sich
  keinen anderen ausstellen lassen.
* **Was darf ich?** — Prinzipale und Vorlagen sind auf das eingeschraenkt,
  was das Enrollment-Token zugelassen hat; ohne Einschraenkung gilt, was der
  Server anbietet.
* **Wie lange?** — die Gueltigkeit wird auf das Minimum aus Serverobergrenze
  und Token-Obergrenze gekuerzt.
"""

from __future__ import annotations

import threading

from ..ca import CertificateAuthority, CertRequest
from ..config import CaError, Paths, RESERVED_NAMES, validate_name
from ..protocol import ProtocolError, cap_validity, validity_seconds
from ..templates import TemplateStore
from .config import ServerConfig
from .registry import Client, Registry


def _seconds(spec: str) -> int:
    """Wie :func:`sshca.protocol.validity_seconds`, aber mit ``CaError``.

    Die Oberflaechen zeigen ``CaError`` unveraendert an; ein ProtocolError
    waere hier ein Fremdkoerper.
    """
    try:
        return validity_seconds(spec)
    except ProtocolError as exc:
        raise CaError(str(exc)) from exc


class Api:
    """Die Vorgaenge des Dienstes."""

    def __init__(
        self,
        config: ServerConfig,
        ca: CertificateAuthority | None = None,
        registry: Registry | None = None,
    ) -> None:
        self.config = config
        self.ca = ca or CertificateAuthority(Paths(config.ca_base))
        self.registry = registry or Registry(config.state_dir)
        self.registry.ensure_layout()
        self.templates = TemplateStore(self.ca.paths.templates_file)
        self._ca_passphrase = config.read_ca_passphrase()
        # Signieren wird serialisiert: der Seriennummernzaehler ist eine
        # Datei, und zwei gleichzeitige Ausstellungen wuerden dieselbe Nummer
        # ziehen. Der Aufruf dauert Millisekunden — ein Engpass ist das nicht.
        self._sign_lock = threading.Lock()

    # ------------------------------------------------------------ Selbsttest
    def startup_check(self) -> list[str]:
        """Befunde, die den Start verhindern sollten. Leer heisst: bereit."""
        problems = list(self.config.check_files())
        if not self.ca.exists():
            problems.append(
                f"Keine CA unter {self.ca.paths.base} — zuerst "
                "'ssh-ca-manager init' als Dienstbenutzer ausführen."
            )
        elif self.config.signing == "agent" and not self.ca.ca_in_agent():
            problems.append(
                "signing = agent, aber der CA-Schlüssel liegt nicht im "
                "ssh-agent (SSH_AUTH_SOCK im Unit-Environment prüfen)."
            )
        try:
            _seconds(self.config.max_validity)
        except CaError as exc:
            problems.append(f"max_validity: {exc}")
        return problems

    # ------------------------------------------------------------ Signierweg
    def _signing_arguments(self) -> tuple[bool, str]:
        if self.config.signing == "agent":
            return True, ""
        return False, self._ca_passphrase

    # -------------------------------------------------------------- Richtlinie
    def allowed_principals(self, client: Client) -> list[str]:
        """Was dieser Client als Prinzipal verlangen darf.

        Grundmenge ist ``principals.conf`` der CA, ergaenzt um den
        Benutzernamen selbst und ``<user>@<host>`` — sonst koennte ein Client
        sich nicht einmal das ausstellen lassen, was die lokale Oberflaeche
        vorschlaegt. Hat das Token eine Liste gesetzt, gilt deren Schnittmenge
        mit dieser Grundmenge nicht: die Token-Liste ist dann massgeblich, denn
        sie ist die bewusste Entscheidung des Administrators.
        """
        if client.principals:
            return list(dict.fromkeys(client.principals))
        base = [client.user, f"{client.user}@{client.host}"]
        base += self.ca.paths.read_principals_conf()
        return list(dict.fromkeys(p for p in base if p))

    def allowed_templates(self, client: Client) -> list:
        available = self.templates.load()
        if not client.templates:
            return available
        wanted = {name.lower() for name in client.templates}
        return [t for t in available if t.name.lower() in wanted]

    def effective_max_validity(self, client: Client) -> int:
        limit = _seconds(self.config.max_validity)
        if client.max_validity:
            limit = min(limit, _seconds(client.max_validity))
        return limit

    # ------------------------------------------------------------- Vorgaenge
    def info(self) -> dict:
        """Unauthentisierte Auskunft — genug, um sich zu verbinden."""
        from ..config import APP_VERSION

        return {
            "application": "ssh-ca-manager",
            "version": APP_VERSION,
            "ca_fingerprint": self.ca.ca_fingerprint(),
            "ca_pubkey": self.ca.ca_public_key(),
        }

    def enroll(self, payload: dict, peer: str = "") -> dict:
        """Erste Kontaktaufnahme: Token gegen Registrierung.

        Der Benutzername stammt aus dem Token, nicht aus der Anfrage. Der
        Hostname kommt vom Client, es sei denn, das Token schreibt ihn vor.
        """
        token_text = str(payload.get("token", "")).strip()
        pubkey = str(payload.get("pubkey", "")).strip()
        wanted_host = str(payload.get("host", "")).strip()
        if not token_text or not pubkey:
            raise CaError("Enrollment braucht 'token' und 'pubkey'.")
        if len(pubkey.splitlines()) != 1:
            raise CaError("'pubkey' muss genau eine Zeile enthalten.")
        if "PRIVATE KEY" in pubkey:
            raise CaError(
                "Das ist ein privater Schlüssel — bitte nur den .pub-Teil."
            )

        client_hint = wanted_host or "?"
        token = self.registry.consume_token(token_text, client_hint)

        host = token.host or wanted_host
        if not host:
            raise CaError(
                "Das Token schreibt keinen Hostnamen vor, die Anfrage nennt "
                "auch keinen."
            )
        if token.host and wanted_host and token.host != wanted_host:
            raise CaError(
                f"Das Token gilt für den Host '{token.host}', die Anfrage "
                f"nennt '{wanted_host}'."
            )
        validate_name("Benutzername", token.user)
        validate_name("Hostname", host)
        if token.user in RESERVED_NAMES:
            raise CaError(f"Der Benutzername '{token.user}' ist reserviert.")

        client = self.registry.register_client(
            token.user, host, pubkey, token, peer=peer
        )
        self.ca.log(
            "OK",
            f"Enrollment: {client.client_id} über Token {token.id} von {peer}",
        )
        return {
            "client_id": client.client_id,
            "user": client.user,
            "host": client.host,
            "ca_pubkey": self.ca.ca_public_key(),
            "ca_fingerprint": self.ca.ca_fingerprint(),
            "principals": self.allowed_principals(client),
            "templates": [t.name for t in self.allowed_templates(client)],
            "max_validity_seconds": self.effective_max_validity(client),
        }

    def principals(self, client: Client) -> dict:
        return {
            "principals": self.allowed_principals(client),
            "restricted": bool(client.principals),
        }

    def template_list(self, client: Client) -> dict:
        return {
            "templates": [
                {
                    "name": t.name,
                    "validity": t.validity,
                    "principal_patterns": list(t.principal_patterns),
                    "extensions": list(t.extensions),
                    "critical_options": dict(t.critical_options),
                    "description": t.description,
                }
                for t in self.allowed_templates(client)
            ],
            "max_validity_seconds": self.effective_max_validity(client),
        }

    def ca_material(self) -> dict:
        """CA-Public-Key und KRL — damit Zielsysteme versorgt werden koennen."""
        krl = ""
        if self.ca.paths.krl.is_file():
            import base64

            krl = base64.b64encode(self.ca.paths.krl.read_bytes()).decode("ascii")
        return {
            "ca_pubkey": self.ca.ca_public_key(),
            "ca_fingerprint": self.ca.ca_fingerprint(),
            "krl_base64": krl,
        }

    def sign(self, client: Client, payload: dict) -> dict:
        """Signiert einen vom Client erzeugten Public Key.

        Der private Schluessel entsteht auf dem Client und bleibt dort — hier
        kommt ausschliesslich der oeffentliche Teil an. Intern laeuft der
        Vorgang ueber ``import_and_sign_pubkey``, dieselbe Funktion, die auch
        die Oberflaechen fuer eingereichte Schluessel benutzen. Damit gilt
        automatisch die bestehende Regel: ein erneuter Antrag rotiert den
        bisherigen Stand nach ``archive/``, und ein lokal verwalteter
        Schluessel wird nicht ueberschrieben.
        """
        if client.disabled:
            raise CaError(f"Der Client '{client.client_id}' ist gesperrt.")

        pubkey = str(payload.get("pubkey", "")).strip()
        if not pubkey or len(pubkey.splitlines()) != 1:
            raise CaError("'pubkey' muss genau eine Zeile enthalten.")

        host = str(payload.get("host", "")).strip() or client.host
        if host != client.host:
            raise CaError(
                f"Dieser Client ist für '{client.host}' registriert, "
                f"angefragt wurde '{host}'."
            )

        templates = self.allowed_templates(client)
        wanted = str(payload.get("template", "")).strip()
        if wanted:
            matches = [t for t in templates if t.name.lower() == wanted.lower()]
            if not matches:
                raise CaError(
                    f"Vorlage '{wanted}' ist für diesen Client nicht "
                    "freigegeben."
                )
            template = matches[0]
        elif templates:
            template = templates[0]
        else:
            raise CaError("Für diesen Client ist keine Vorlage freigegeben.")

        allowed = self.allowed_principals(client)
        requested = payload.get("principals") or []
        if not isinstance(requested, list):
            raise CaError("'principals' muss eine Liste sein.")
        principals = [str(p).strip() for p in requested if str(p).strip()]
        if not principals:
            principals = template.principals_for(client.user, client.host)
            principals = [p for p in principals if p in allowed] or allowed[:1]
        unknown = [p for p in principals if p not in allowed]
        if unknown:
            raise CaError(
                "Nicht freigegebene Prinzipale: " + ", ".join(unknown)
            )
        principals = list(dict.fromkeys(principals))
        if not principals:
            raise CaError("Mindestens ein Prinzipal ist erforderlich.")

        limit = self.effective_max_validity(client)
        wanted_validity = str(payload.get("validity", "")).strip()
        if wanted_validity:
            # Ausdrücklich angefordert: zu viel ist ein Fehler. Still etwas
            # anderes auszustellen als verlangt wäre die schlechtere Antwort.
            if _seconds(wanted_validity) > limit:
                raise CaError(
                    f"Die angeforderte Gültigkeit '{wanted_validity}' "
                    "überschreitet die Obergrenze für diesen Client "
                    f"({limit // 3600} h)."
                )
            validity = wanted_validity
        else:
            # Aus der Vorlage übernommen: dann ist Kürzen richtig — der Client
            # hat sich die Dauer nicht ausgesucht.
            validity = cap_validity(template.validity, limit)

        use_agent, ca_passphrase = self._signing_arguments()
        request = CertRequest(
            user=client.user,
            host=client.host,
            principals=principals,
            validity=validity,
            extensions=list(template.extensions),
            critical_options=dict(template.critical_options),
            ca_passphrase=ca_passphrase,
            use_agent=use_agent,
        )
        with self._sign_lock:
            info = self.ca.import_and_sign_pubkey(pubkey, request)
        self.ca.log(
            "OK",
            f"Signiert für Client {client.client_id}: Vorlage '{template.name}' "
            f"serial={info.serial}",
        )
        return {
            "certificate": info.cert_path.read_text(encoding="utf-8").strip(),
            "filename": info.cert_path.name,
            "serial": info.serial,
            "key_id": info.key_id,
            "principals": info.principals,
            "valid_from": info.valid_from.isoformat() if info.valid_from else "",
            "valid_to": info.valid_to.isoformat() if info.valid_to else "",
            "template": template.name,
            "validity": validity,
            "extensions": sorted(info.extensions),
            "critical_options": info.critical_options,
        }

    def certificates(self, client: Client) -> dict:
        """Die Zertifikate dieses Clients — nur die eigenen."""
        host_dir = self.ca.paths.host_dir(client.user, client.host)
        entries = []
        if host_dir.is_dir():
            for cert_path in sorted(host_dir.glob("*-cert.pub")):
                info = self.ca.load_certificate(cert_path)
                entries.append(
                    {
                        "filename": cert_path.name,
                        "serial": info.serial,
                        "key_id": info.key_id,
                        "principals": info.principals,
                        "valid_to": (
                            info.valid_to.isoformat() if info.valid_to else ""
                        ),
                        "status": info.status().value,
                        "revoked": info.revoked,
                    }
                )
        return {"certificates": entries}
