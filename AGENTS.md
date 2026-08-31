# Security Audit Suite — Arbeitsregeln

## Release und Deploy

- Produktive Releases laufen **ausschließlich über die Develop Zentrale**
  (Deployment-Controller, `DEPLOY-RICHTLINIE.md` dort). Kein `git tag`-Push von
  Hand, kein manuelles `gh workflow run`, kein `gh release create`.
- Einzige Versionsquelle ist `version.json` (SemVer). Vor jedem Release die
  Version bewusst erhöhen und auf `main` pushen; gleiche Version zweimal
  releasen scheitert an der Tag-Kollision.
- Der Release-Workflow `.github/workflows/release.yml` akzeptiert nur
  HMAC-signierte Zentrale-Dispatches und setzt den Tag `sat-v<Version>` selbst —
  nach grünem Build, nie vorher.
- Der In-App-Autoupdater (`core/updater.py`) sucht Releases mit dem Präfix
  `sat-v` in diesem Repository. Releases nie löschen oder überschreiben;
  Rollback = vorheriges Release.

## Arbeiten am Code

- `packaging/build.ps1` stempelt `version.json` beim lokalen Bauen um — diese
  Änderung nicht committen, außer sie ist der beabsichtigte Versions-Bump.
- Die 46 Selbsttests laufen lokal (siehe README); vor einem Release müssen sie
  grün sein.
