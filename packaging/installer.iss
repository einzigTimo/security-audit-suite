; Inno Setup Script — Security Audit Suite
; Erzeugt ein Windows-Setup aus dem PyInstaller-Ausgabeordner.
; Aufruf: iscc /DAppVersion=2026.08.27 packaging\installer.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\SecurityAuditSuite"
#endif

[Setup]
AppId={{15FAB029-B282-59F3-8379-3C0BA62D2AF4}}
AppName=Security Audit Suite
AppVersion={#AppVersion}
AppPublisher=Security Audit Suite
DefaultDirName={autopf}\Security Audit Suite
DefaultGroupName=Security Audit Suite
UninstallDisplayIcon={app}\SecurityAuditSuite.exe
OutputDir=..\dist
OutputBaseFilename=SecurityAuditSuite-{#AppVersion}-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
PrivilegesRequired=lowest
; Warnhinweis, den der Nutzer vor der Installation lesen und bestaetigen muss.
InfoBeforeFile=DISCLAIMER.txt

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "Desktop-Verknuepfung erstellen"; GroupDescription: "Zusaetzliche Symbole:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\Security Audit Suite"; Filename: "{app}\SecurityAuditSuite.exe"
Name: "{group}\Security Audit Suite deinstallieren"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Security Audit Suite"; Filename: "{app}\SecurityAuditSuite.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SecurityAuditSuite.exe"; Description: "Security Audit Suite starten"; Flags: nowait postinstall skipifsilent
