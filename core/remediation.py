"""Erklaerungen und Behebungshinweise je Test.

Zentrale Wissensbasis, aus der sowohl die Oberflaeche (Live-Konsole am Ende des
Audits) als auch der Reporter (TXT/JSON/HTML) schoepfen. Pro Test-ID ein kurzer
Erklaerungstext (was ist das Problem) und ein konkreter Behebungshinweis.
"""

ADVICE = {
    # --- Header --------------------------------------------------------
    "HDR-01": {
        "explanation": "Ohne HSTS kann ein Angreifer die Verbindung auf unverschluesseltes HTTP herabstufen (SSL-Stripping).",
        "remediation": "Header setzen: Strict-Transport-Security: max-age=31536000; includeSubDomains (nach Test ggf. preload).",
    },
    "HDR-02": {
        "explanation": "Ohne oder mit schwacher Content-Security-Policy sind XSS-Angriffe deutlich leichter; 'unsafe-inline'/'unsafe-eval' und Wildcards heben den Schutz weitgehend auf.",
        "remediation": "Restriktive CSP definieren (z. B. default-src 'self'); Inline-Skripte per Nonce/Hash statt 'unsafe-inline' erlauben.",
    },
    "HDR-03": {
        "explanation": "Ohne X-Frame-Options bzw. frame-ancestors kann die Seite in einen fremden Rahmen eingebettet und fuer Clickjacking missbraucht werden.",
        "remediation": "X-Frame-Options: DENY setzen oder in der CSP frame-ancestors 'none' (bzw. 'self').",
    },
    "HDR-04": {
        "explanation": "Ohne nosniff kann der Browser den MIME-Typ erraten und Inhalte falsch interpretieren (MIME-Confusion, XSS).",
        "remediation": "Header setzen: X-Content-Type-Options: nosniff.",
    },
    "HDR-05": {
        "explanation": "Ohne restriktive Referrer-Policy koennen vollstaendige URLs (inkl. sensibler Parameter) an Drittseiten lecken.",
        "remediation": "Header setzen: Referrer-Policy: strict-origin-when-cross-origin (oder strenger, z. B. no-referrer).",
    },
    "HDR-06": {
        "explanation": "Versions- und Technologie-Header erleichtern Angreifern das gezielte Ausnutzen bekannter Schwachstellen.",
        "remediation": "Server-, X-Powered-By- und X-AspNet-Version-Header entfernen oder anonymisieren.",
    },
    # --- Cookies -------------------------------------------------------
    "CKE-01": {
        "explanation": "Cookies ohne Secure-Flag werden auch ueber unverschluesseltes HTTP uebertragen und koennen abgegriffen werden.",
        "remediation": "Allen Cookies das Attribut Secure geben, damit sie nur ueber HTTPS gesendet werden.",
    },
    "CKE-02": {
        "explanation": "Ohne HttpOnly kann JavaScript (etwa ueber eine XSS-Luecke) Session-Cookies auslesen.",
        "remediation": "Session- und Auth-Cookies mit HttpOnly kennzeichnen.",
    },
    "CKE-03": {
        "explanation": "Ohne wirksames SameSite werden Cookies auch bei Cross-Site-Anfragen gesendet, was CSRF erleichtert.",
        "remediation": "SameSite=Lax (Standard) oder SameSite=Strict setzen; SameSite=None nur zusammen mit Secure und bewusst.",
    },
    # --- Transport -----------------------------------------------------
    "TLS-01": {
        "explanation": "Liefert HTTP Inhalte ohne Weiterleitung, sind Klartext-Verbindungen und damit Man-in-the-Middle moeglich.",
        "remediation": "Alle HTTP-Anfragen per 301 dauerhaft auf HTTPS umleiten und zusaetzlich HSTS aktivieren.",
    },
    "TLS-02": {
        "explanation": "Ueber HTTP eingebundene Ressourcen auf einer HTTPS-Seite koennen unterwegs manipuliert werden und untergraben die Verschluesselung.",
        "remediation": "Alle Skripte, Stile, Bilder und iframes ausschliesslich ueber HTTPS laden.",
    },
    # --- Informationspreisgabe ----------------------------------------
    "INF-01": {
        "explanation": "Disallow-Eintraege in robots.txt verraten haeufig interne oder sensible Pfade.",
        "remediation": "Keine sensiblen Pfade in robots.txt auflisten; schuetzenswerte Bereiche per Zugriffskontrolle absichern statt zu verstecken.",
    },
    "INF-02": {
        "explanation": "Aktives Directory Listing legt Dateinamen und Verzeichnisstruktur offen.",
        "remediation": "Verzeichnisauflistung im Webserver deaktivieren (z. B. Options -Indexes / autoindex off).",
    },
    "INF-03": {
        "explanation": "Ein oeffentlich erreichbares .git-Verzeichnis erlaubt das Rekonstruieren des Quellcodes inklusive moeglicher Secrets.",
        "remediation": ".git aus dem Webroot entfernen oder den Zugriff serverseitig sperren.",
    },
    "INF-04": {
        "explanation": "Konfigurations- und Umgebungsdateien enthalten oft Zugangsdaten, Schluessel und Verbindungszeichenfolgen.",
        "remediation": "Solche Dateien ausserhalb des Webroots ablegen oder sperren; bereits exponierte Secrets umgehend rotieren.",
    },
    "INF-05": {
        "explanation": "Stacktraces auf Fehlerseiten verraten interne Pfade, eingesetzte Frameworks und Programmlogik.",
        "remediation": "Generische Fehlerseiten ausliefern und den Debug-Modus in der Produktion abschalten.",
    },
    "INF-06": {
        "explanation": "Oeffentliche Source Maps geben den originalen, oft kommentierten Quellcode preis.",
        "remediation": "Source Maps in der Produktion nicht ausliefern oder nur intern bereitstellen.",
    },
    "INF-07": {
        "explanation": "Eine fehlende security.txt erschwert Sicherheitsforschern die verantwortungsvolle Meldung von Luecken (Empfehlung, kein Fehler).",
        "remediation": "Unter /.well-known/security.txt eine Kontaktadresse (Contact) und ein Ablaufdatum (Expires) hinterlegen.",
    },
    # --- Injektion -----------------------------------------------------
    "INJ-01": {
        "explanation": "SQL-Injection erlaubt Angreifern das Auslesen und Veraendern der Datenbank bis hin zur vollstaendigen Uebernahme.",
        "remediation": "Ausschliesslich parametrisierte Abfragen / Prepared Statements verwenden, Eingaben validieren, Rechte der DB-Kennung minimieren.",
    },
    "INJ-02": {
        "explanation": "Reflektiertes XSS schleust Skripte in den Browser des Opfers ein (Session-Diebstahl, Aktionen im Namen des Nutzers).",
        "remediation": "Ausgaben kontextgerecht kodieren (HTML/Attribut/JS), Eingaben validieren und eine restriktive CSP einsetzen.",
    },
    "INJ-03": {
        "explanation": "Offene Weiterleitungen ermoeglichen Phishing ueber die vertrauenswuerdige Domain der Anwendung.",
        "remediation": "Weiterleitungsziele gegen eine feste Allowlist pruefen oder nur relative Pfade zulassen.",
    },
    "INJ-04": {
        "explanation": "Path Traversal / LFI erlaubt das Lesen beliebiger Serverdateien (z. B. /etc/passwd, Konfigurationen).",
        "remediation": "Dateinamen strikt validieren, Pfade normalisieren und auf ein festes Basisverzeichnis beschraenken (keine '..').",
    },
    "INJ-05": {
        "explanation": "Command Injection erlaubt die Ausfuehrung beliebiger Systembefehle auf dem Server.",
        "remediation": "Keine Shell-Aufrufe mit Nutzereingaben; sichere APIs statt Shell nutzen, Eingaben per Allowlist einschraenken.",
    },
    "INJ-06": {
        "explanation": "Server-Side Template Injection kann bis zur Codeausfuehrung auf dem Server fuehren.",
        "remediation": "Nutzereingaben nie als Template rendern; Logik und Daten trennen, sandboxed / auto-escapende Templates verwenden.",
    },
    # --- Zugriffskontrolle ---------------------------------------------
    "RBAC-01": {
        "explanation": "Geschuetzte Bereiche sind ohne Anmeldung erreichbar — die Zugriffskontrolle greift nicht.",
        "remediation": "Fuer jede geschuetzte Route serverseitig Authentifizierung und Autorisierung erzwingen (nicht nur im Frontend ausblenden).",
    },
    "API-01": {
        "explanation": "Die API liefert Daten ohne Autorisierungspruefung.",
        "remediation": "Auf allen Endpunkten Authentifizierung und Autorisierung pruefen; standardmaessig ablehnen (deny by default).",
    },
    "API-02": {
        "explanation": "Fortlaufende Objekt-IDs sind frei abrufbar (IDOR/BOLA) — fremde Datensaetze werden einsehbar.",
        "remediation": "Objektbezogene Zugriffspruefung (gehoert das Objekt dem Aufrufer?); schwer erratbare IDs (UUID) verwenden.",
    },
    "API-03": {
        "explanation": "Der Server uebernimmt clientseitig gesetzte Felder (z. B. Rolle/Rechte) ungeprueft — Rechteausweitung moeglich.",
        "remediation": "Eingaben per Whitelist / DTO auf erlaubte Felder begrenzen; sensible Felder ausschliesslich serverseitig setzen.",
    },
    # --- CORS / Methoden / Abhaengigkeiten -----------------------------
    "CORS-01": {
        "explanation": "Wird die Origin reflektiert und sind Credentials erlaubt, koennen fremde Seiten authentifizierte Anfragen im Namen des Nutzers stellen.",
        "remediation": "Feste Origin-Allowlist statt Reflektion; Access-Control-Allow-Credentials niemals mit Wildcard-Origin kombinieren.",
    },
    "MTH-01": {
        "explanation": "Aktive Methoden wie TRACE, PUT oder DELETE koennen missbraucht werden (u. a. Cross-Site Tracing).",
        "remediation": "Nicht benoetigte HTTP-Methoden am Webserver deaktivieren; nur die tatsaechlich genutzten zulassen.",
    },
    "DEP-01": {
        "explanation": "Veraltete Frontend-Bibliotheken mit oeffentlich bekannten CVEs sind ein leichtes und beliebtes Angriffsziel.",
        "remediation": "Bibliotheken auf gepatchte Versionen aktualisieren und ein regelmaessiges Dependency-Scanning etablieren.",
    },
    # --- Erweiterte Header / Cookies / Integritaet ---------------------
    "HDR-07": {
        "explanation": "Ohne Permissions-Policy sind Browser-Funktionen (Kamera, Mikrofon, Geolocation, …) nicht eingeschraenkt.",
        "remediation": "Permissions-Policy setzen und nicht benoetigte Funktionen deaktivieren, z. B. geolocation=(), camera=().",
    },
    "HDR-08": {
        "explanation": "Ohne Cross-Origin-Opener-/Resource-Policy ist die Seite schwaecher gegen Cross-Origin-Angriffe (u. a. Spectre, Ressourcen-Diebstahl) geschuetzt.",
        "remediation": "Cross-Origin-Opener-Policy: same-origin und Cross-Origin-Resource-Policy: same-origin setzen.",
    },
    "HDR-09": {
        "explanation": "Antworten aus geschuetzten Bereichen ohne no-store koennen von Browsern oder Proxys zwischengespeichert werden.",
        "remediation": "Fuer authentifizierte/dynamische Antworten Cache-Control: no-store (oder private) setzen.",
    },
    "CKE-04": {
        "explanation": "Ohne __Host-/__Secure-Praefix fehlen Cookies zusaetzliche, vom Browser erzwungene Schutzgarantien (nur HTTPS, fester Pfad).",
        "remediation": "Session-Cookies mit dem Praefix __Host- (Secure, Path=/, ohne Domain) oder mindestens __Secure- benennen.",
    },
    "SRI-01": {
        "explanation": "Extern eingebundene Skripte ohne Integritaetspruefung koennen beim Anbieter manipuliert werden und Schadcode ausliefern.",
        "remediation": "Externe Skripte/Stile mit integrity-Attribut (Subresource Integrity) und crossorigin einbinden.",
    },
    "CSRF-01": {
        "explanation": "POST-Formulare ohne CSRF-Token koennen von fremden Seiten im Namen des angemeldeten Nutzers ausgeloest werden.",
        "remediation": "Pro Formular ein unvorhersehbares CSRF-Token einbauen und serverseitig pruefen; zusaetzlich SameSite-Cookies nutzen.",
    },
    # --- Content-Discovery ---------------------------------------------
    "DISC-01": {
        "explanation": "Oeffentlich erreichbare Admin-Oberflaechen, Backups, Test-/Dev-Pfade oder API-Dokumentationen vergroessern die Angriffsflaeche erheblich.",
        "remediation": "Solche Pfade entfernen oder per Authentifizierung/IP-Beschraenkung schuetzen; keine Backups im Webroot ablegen.",
    },
    # --- Authentifizierung ---------------------------------------------
    "AUTH-01": {
        "explanation": "Ohne Rate-Limiting am Login sind automatisierte Brute-Force- und Credential-Stuffing-Angriffe leicht durchfuehrbar.",
        "remediation": "Fehlversuche pro Konto/IP drosseln (429/Retry-After), Verzoegerungen, Sperren und ggf. CAPTCHA/MFA einsetzen.",
    },
    "AUTH-02": {
        "explanation": "Schwache JWT-Konfiguration (alg=none, fehlende Ablaufzeit) erlaubt das Faelschen oder unbegrenzte Weiterverwenden von Tokens.",
        "remediation": "Nur starke signierende Verfahren zulassen (alg=none ablehnen), 'exp' setzen, Signatur serverseitig strikt pruefen.",
    },
    # --- TLS-Tiefe -----------------------------------------------------
    "TLS-03": {
        "explanation": "Ein abgelaufenes oder bald ablaufendes Zertifikat fuehrt zu Browserwarnungen und unterbricht die vertrauenswuerdige Verbindung.",
        "remediation": "Zertifikat rechtzeitig erneuern und die Erneuerung automatisieren (z. B. ACME/Let's Encrypt).",
    },
    "TLS-04": {
        "explanation": "Veraltete Protokolle (TLS 1.0/1.1) enthalten bekannte Schwaechen und gelten als unsicher.",
        "remediation": "Am Server nur TLS 1.2 und 1.3 zulassen; TLS 1.0/1.1 (und SSLv3) deaktivieren.",
    },
    "TLS-05": {
        "explanation": "Eine schwache ausgehandelte Verbindung (altes Protokoll oder schwache Cipher-Suite) untergraebt die Vertraulichkeit.",
        "remediation": "Moderne Cipher-Suiten bevorzugen, veraltete deaktivieren und TLS 1.3 aktivieren.",
    },
}

_FALLBACK = {
    "explanation": "Sicherheitsrelevanter Befund — bitte im Kontext der Anwendung bewerten.",
    "remediation": "Betroffene Komponente pruefen und nach gaengiger Sicherheitspraxis (OWASP) haerten.",
}


def advice_for(test_id):
    """Erklaerung und Behebungshinweis zu einer Test-ID (mit Fallback)."""
    return ADVICE.get(test_id, _FALLBACK)


def iter_findings(results, statuses=("FAIL", "WARN")):
    """Liefert die erklaerungswuerdigen Befunde in Ergebnisreihenfolge.

    Standardmaessig FAIL und WARN (die eigentlichen Sicherheitsbefunde). Jeder
    Eintrag ergaenzt das Ergebnis um explanation und remediation.
    """
    for r in results:
        if r.get("status") in statuses:
            a = advice_for(r.get("test_id"))
            yield {
                "test_id": r.get("test_id", ""),
                "title": r.get("title", ""),
                "status": r.get("status", ""),
                "severity": r.get("severity", ""),
                "message": r.get("message", ""),
                "explanation": a["explanation"],
                "remediation": a["remediation"],
            }
