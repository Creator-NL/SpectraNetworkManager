; SpectraNetworkManager Inno Setup Script
; Production installer packaging for Windows 10 & 11 (x64)
; Biohazard Corp / Creator-NL

#define MyAppName "SpectraNetworkManager"
#define MyAppVersion "2.0.0"
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
OutputBaseFilename=SpectraNetworkManager-v{#MyAppVersion}-Setup
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
SetupIconFile=app.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "runonstartup"; Description: "Start SpectraNetworkManager GUI automatically when you sign in to Windows"; GroupDescription: "Startup Options:"; Flags: unchecked

[Files]
; GUI Application published binaries
Source: "..\publish\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Background Engine Service binaries
Source: "..\publish\engine\*"; DestDir: "{app}\engine"; Flags: ignoreversion recursesubdirs createallsubdirs

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
Filename: "{app}\engine\{#MyEngineExeName}"; Parameters: "--install"; StatusMsg: "Registering SpectraNetworkManager Engine service..."; Flags: runhidden
; 2. Start the Engine service
Filename: "net.exe"; Parameters: "start SpectraNetworkManager.Engine"; StatusMsg: "Starting SpectraNetworkManager Engine service..."; Flags: runhidden
; 3. Clean up any legacy HTTP.SYS reservation so port 8765 is directly handled by Spectra's TCP engine
Filename: "netsh.exe"; Parameters: "http delete urlacl url=http://+:8765/"; Flags: runhidden
; 4. Optionally launch the GUI front-end
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; 1. Safety First: Revert all SpectraNetworkManager firewall rules, strict mode, and DNS settings back to Windows defaults before removing files
Filename: "{app}\{#MyAppExeName}"; Parameters: "--safe"; RunOnceId: "SpectraNetworkManagerSafeRevert"; StatusMsg: "Restoring Windows Firewall rules and system DNS settings to defaults..."; Flags: runhidden
; 2. Stop and unregister SpectraNetworkManager.Engine service
Filename: "{app}\engine\{#MyEngineExeName}"; Parameters: "--uninstall"; RunOnceId: "SpectraNetworkManagerEngineUninstall"; StatusMsg: "Stopping and unregistering SpectraNetworkManager Engine service..."; Flags: runhidden
; 3. Remove HTTP.SYS URL reservation
Filename: "netsh.exe"; Parameters: "http delete urlacl url=http://+:8765/"; RunOnceId: "SpectraNetworkManagerUrlAclDelete"; Flags: runhidden

[Code]
var
  UpgradePage: TInputOptionWizardPage;
  HasExistingInstall: Boolean;
  PrevInstallDir: String;
  PrevVersion: String;

function DetectExistingInstallation(): Boolean;
var
  KeyName: String;
begin
  KeyName := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8B849E72-5202-4A73-A340-96A125EFA5F8}_is1';
  Result := False;
  PrevInstallDir := '';
  PrevVersion := '';

  // Check 64-bit and 32-bit registry in HKLM and HKCU
  if RegQueryStringValue(HKLM64, KeyName, 'InstallLocation', PrevInstallDir) or
     RegQueryStringValue(HKLM, KeyName, 'InstallLocation', PrevInstallDir) or
     RegQueryStringValue(HKCU64, KeyName, 'InstallLocation', PrevInstallDir) or
     RegQueryStringValue(HKCU, KeyName, 'InstallLocation', PrevInstallDir) then
  begin
    if (PrevInstallDir <> '') and DirExists(PrevInstallDir) then
      Result := True;
  end;

  if not Result then
  begin
    if RegQueryStringValue(HKLM64, KeyName, 'Inno Setup: App Path', PrevInstallDir) or
       RegQueryStringValue(HKLM, KeyName, 'Inno Setup: App Path', PrevInstallDir) then
    begin
      if (PrevInstallDir <> '') and DirExists(PrevInstallDir) then
        Result := True;
    end;
  end;

  if not Result then
  begin
    // Check default program files path
    if FileExists(ExpandConstant('{autopf}\SpectraNetworkManager\SpectraNetworkManager.exe')) then
    begin
      PrevInstallDir := ExpandConstant('{autopf}\SpectraNetworkManager');
      Result := True;
    end;
  end;

  if Result then
  begin
    if not (RegQueryStringValue(HKLM64, KeyName, 'DisplayVersion', PrevVersion) or
            RegQueryStringValue(HKLM, KeyName, 'DisplayVersion', PrevVersion)) then
      PrevVersion := 'existing';
  end;
end;

procedure InitializeWizard;
var
  InfoText: String;
begin
  HasExistingInstall := DetectExistingInstallation();

  if HasExistingInstall then
    InfoText := 'SpectraNetworkManager detected version ' + PrevVersion + ' already installed at:' + #13#10 + PrevInstallDir + #13#10#13#10 + 'Please choose an installation method:'
  else
    InfoText := 'Please choose an installation method:';

  UpgradePage := CreateInputOptionPage(
    wpLicense,
    'Existing Installation Detected',
    'Choose how you would like to proceed with the installation',
    InfoText,
    True, False);

  UpgradePage.Add('⚡ Easy Upgrade (Recommended)' + #13#10 + '   Automatically upgrade using your existing folder and settings with one click.');
  UpgradePage.Add('🛠️ Custom Install' + #13#10 + '   Customize installation directory, shortcuts, and review all setup steps.');
  UpgradePage.SelectedValueIndex := 0;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if not HasExistingInstall then
  begin
    if (UpgradePage <> nil) and (PageID = UpgradePage.ID) then
      Result := True;
  end
  else
  begin
    // If existing install detected and user chose Easy Upgrade, skip directory and tasks pages
    if (UpgradePage <> nil) and (UpgradePage.SelectedValueIndex = 0) then
    begin
      if (PageID = wpSelectDir) or (PageID = wpSelectTasks) then
        Result := True;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (UpgradePage <> nil) and (CurPageID = UpgradePage.ID) then
  begin
    if (UpgradePage.SelectedValueIndex = 0) and (PrevInstallDir <> '') then
    begin
      WizardForm.DirEdit.Text := PrevInstallDir;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    // Safely stop background engine and GUI if running to avoid locked file errors
    Exec('net.exe', 'stop SpectraNetworkManager.Engine', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/F /IM SpectraNetworkManager.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/F /IM SpectraNetworkManager.Engine.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/F /IM SpectraNetworkManager.BrowserHost.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CleanIfeoRoot(RootKey: Integer; BaseKey: String);
var
  Names: TArrayOfString;
  I: Integer;
  SubKey: String;
  DbgVal: String;
begin
  if RegGetSubkeyNames(RootKey, BaseKey, Names) then
  begin
    for I := 0 to GetArrayLength(Names) - 1 do
    begin
      SubKey := BaseKey + '\' + Names[I];
      if RegQueryStringValue(RootKey, SubKey, 'Debugger', DbgVal) then
      begin
        if Pos('systray.exe', Lowercase(DbgVal)) > 0 then
        begin
          RegDeleteValue(RootKey, SubKey, 'Debugger');
          RegDeleteKeyIfEmpty(RootKey, SubKey);
        end;
      end;
    end;
  end;
end;

procedure CleanAllIfeoQuarantineLockouts();
begin
  CleanIfeoRoot(HKLM64, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options');
  CleanIfeoRoot(HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options');
  CleanIfeoRoot(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options');
end;

// After file removal, prompt user whether to clean up data in ProgramData
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProgramDataDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    CleanAllIfeoQuarantineLockouts();
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    CleanAllIfeoQuarantineLockouts();
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
