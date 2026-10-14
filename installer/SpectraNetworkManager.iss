; SpectraNetworkManager Inno Setup Script
; Production installer packaging for Windows 10 & 11 (x64)
; Biohazard Corp / Creator-NL

#define MyAppName "SpectraNetworkManager"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Biohazard Corp / Creator-NL"
#define MyAppURL "https://github.com/Creator-NL/SpectraNetworkManager"
#define MyAppExeName "SpectraNetworkManager.exe"
#define MyEngineExeName "SpectraNetworkManager.Engine.exe"

[Setup]
AppId={{8B849E72-5202-4A73-A340-96A125EFA5F8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\SpectraNetworkManager
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=output
OutputBaseFilename=SpectraNetworkManager-Setup-v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UsedUserAreasWarning=no
CloseApplications=force
RestartApplications=no
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "runonstartup"; Description: "Start SpectraNetworkManager GUI automatically when you sign in to Windows"; GroupDescription: "Startup Options:"; Flags: unchecked

[Files]
; GUI Application published binaries
Source: "..\publish\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Background Engine Service binaries
Source: "..\publish\engine\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Standard application shortcut
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
; Safe Recovery Mode shortcut (disarms rules, restores DNS & firewall defaults)
Name: "{group}\{#MyAppName} (Safe Recovery Mode)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--safe"; IconFilename: "{app}\{#MyAppExeName}"
; Uninstaller shortcut
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; Optional Desktop shortcut
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Optional autorun entry if user selects task
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: runonstartup

[Run]
; 1. Register SpectraNetworkManager.Engine as a Windows Service
Filename: "{app}\{#MyEngineExeName}"; Parameters: "--install"; StatusMsg: "Registering SpectraNetworkManager Engine service..."; Flags: runhidden
; 2. Start the Engine service
Filename: "net.exe"; Parameters: "start SpectraNetworkManager.Engine"; StatusMsg: "Starting SpectraNetworkManager Engine service..."; Flags: runhidden
; 3. Optionally launch the GUI front-end
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; 1. Safety First: Revert all SpectraNetworkManager firewall rules, strict mode, and DNS settings back to Windows defaults before removing files
Filename: "{app}\{#MyAppExeName}"; Parameters: "--safe"; RunOnceId: "SpectraNetworkManagerSafeRevert"; StatusMsg: "Restoring Windows Firewall rules and system DNS settings to defaults..."; Flags: runhidden
; 2. Stop and unregister SpectraNetworkManager.Engine service
Filename: "{app}\{#MyEngineExeName}"; Parameters: "--uninstall"; RunOnceId: "SpectraNetworkManagerEngineUninstall"; StatusMsg: "Stopping and unregistering SpectraNetworkManager Engine service..."; Flags: runhidden

[Code]
// After file removal, prompt user whether to clean up data in ProgramData
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProgramDataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    ProgramDataDir := ExpandConstant('{commonappdata}\SpectraNetworkManager');
    if DirExists(ProgramDataDir) then
    begin
      if MsgBox('Would you like to remove your custom SpectraNetworkManager firewall rules, DNS sinkhole history, and diagnostic logs in ' + ProgramDataDir + '?' + #13#10#13#10 + 'Click No to preserve your rule choices for future reinstallation.', mbConfirmation, MB_YESNO) = IDYES then
      begin
        DelTree(ProgramDataDir, True, True, True);
      end;
    end;
  end;
end;
