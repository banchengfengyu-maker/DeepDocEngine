#ifndef DistDir
  #define DistDir "..\dist"
#endif
#ifndef OutputSetupDir
  #define OutputSetupDir "..\dist_installer"
#endif
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{D9C64A72-5E19-4C8F-A761-9B42E1032F10}
AppName=DeepDocEngine
AppVerName=DeepDocEngine v{#AppVersion}
AppVersion={#AppVersion}
AppPublisher=DeepDocEngine
DefaultDirName={autopf}\DeepDocEngine
DefaultGroupName=DeepDocEngine
AllowNoIcons=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
DisableProgramGroupPage=yes
ShowLanguageDialog=no
OutputDir={#OutputSetupDir}
OutputBaseFilename=DeepDocEngine_Setup_v{#AppVersion}_win64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.LaunchApp=立即启动 DeepDocEngine
english.CreateDesktopIcon=创建桌面快捷方式 (&D)
english.AdditionalIcons=附加快捷方式:

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb,createdump.exe"

[Icons]
Name: "{group}\DeepDocEngine"; Filename: "{app}\App.UI.exe"; WorkingDir: "{app}"
Name: "{group}\卸载 DeepDocEngine"; Filename: "{uninstallexe}"
Name: "{autodesktop}\DeepDocEngine"; Filename: "{app}\App.UI.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\App.UI.exe"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[Code]
procedure StopDeepDocProcesses();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM App.UI.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM engine-daemon.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM parser-worker.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM ext-worker.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    StopDeepDocProcesses();
  end;
end;

function InitializeUninstall(): Boolean;
begin
  StopDeepDocProcesses();
  Result := True;
end;
