#define MyAppName "Red Night"
#ifndef MyAppVersion
  #define MyAppVersion "0.46.7"
#endif
#ifndef SourceDir
  #error SourceDir must point at the prepared Red Night bundle.
#endif
// Managed Nmap is optional and intentionally omitted by default.
// Only supply ManagedNmapDir for a separately verified, redistribution-cleared
// release payload. Npcap and other licensing/dependency work is independent.
#ifndef SourceCommit
  #define SourceCommit "unknown"
#endif

[Setup]
AppId={{6F45CC2B-3F5E-4B3D-BC5C-57EF164E8E81}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=NightRecon
VersionInfoVersion=0.46.7.0
VersionInfoDescription=Red Night authorized assessment platform
VersionInfoProductName=Red Night
VersionInfoProductVersion={#MyAppVersion}
DefaultDirName={localappdata}\Programs\Red Night
DefaultGroupName=Red Night
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DisableProgramGroupPage=yes
DisableWelcomePage=no
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
SetupLogging=yes
UninstallDisplayIcon={app}\RedNight.exe
OutputDir=..\..\artifacts\windows-installer
OutputBaseFilename=RedNight-{#MyAppVersion}-Windows-x64-Setup
ChangesEnvironment=no
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

#ifdef ManagedNmapDir
// Build coordinator must preflight this directory, its components.json,
// trusted SHA-256 source, licensing notices and platform dependencies.
Source: "{#ManagedNmapDir}\\*"; DestDir: "{app}\\managed-tools\\nmap"; Flags: ignoreversion recursesubdirs createallsubdirs
#endif

[Dirs]
Name: "{localappdata}\NightRecon\RedNight"; Flags: uninsneveruninstall
Name: "{localappdata}\NightRecon\RedNight\workspaces"; Flags: uninsneveruninstall
Name: "{localappdata}\NightRecon\RedNight\backups"; Flags: uninsneveruninstall
Name: "{localappdata}\NightRecon\RedNight\logs"; Flags: uninsneveruninstall

[Icons]
Name: "{autoprograms}\Red Night"; Filename: "{app}\RedNight.exe"; WorkingDir: "{localappdata}\NightRecon\RedNight"
Name: "{autodesktop}\Red Night"; Filename: "{app}\RedNight.exe"; WorkingDir: "{localappdata}\NightRecon\RedNight"; Tasks: desktopicon

Name: "{autoprograms}\Red Night Qt Preview"; Filename: "{app}\RedNightQtPreview.exe"; WorkingDir: "{localappdata}\NightRecon\RedNight"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  Log('Red Night source commit: {#SourceCommit}');
end;
