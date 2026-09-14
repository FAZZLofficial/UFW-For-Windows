; Script generated for UFW for Windows Server
; Compatible with Windows Server 2019, 2022, 2025 and Windows 10/11

#define MyAppName "UFW for Windows Server"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "FAZZL"
#define MyAppURL "https://github.com/FAZZLofficial/UFW-For-Windows"
#define MyAppExeName "ufw.cmd"

[Setup]
AppId={{E68BC201-9F24-4B2E-8E1A-8519B53EFA32}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\UFW-Windows
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=UFW-Windows-Setup-v{#MyAppVersion}
OutputDir=dist
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ChangesEnvironment=yes

; --- Branding & Icons ---
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\icon.ico
WizardImageFile=WizardImage.bmp
WizardSmallImageFile=WizardSmall.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Files]
Source: "ufw.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "ufw.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "logo.jpg"; DestDir: "{app}"; Flags: ignoreversion

[Code]
const
    EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

procedure AddToSystemPath(PathToAdd: string);
var
    CurrentPath: string;
begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', CurrentPath) then
    begin
        if Pos(';' + Uppercase(PathToAdd) + ';', ';' + Uppercase(CurrentPath) + ';') = 0 then
        begin
            if (CurrentPath <> '') and (CurrentPath[Length(CurrentPath)] <> ';') then
                CurrentPath := CurrentPath + ';';
            CurrentPath := CurrentPath + PathToAdd;
            RegWriteStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', CurrentPath);
        end;
    end;
end;

procedure RemoveFromSystemPath(PathToRemove: string);
var
    CurrentPath: string;
    P: Integer;
begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', CurrentPath) then
    begin
        P := Pos(';' + Uppercase(PathToRemove) + ';', ';' + Uppercase(CurrentPath) + ';');
        if P > 0 then
        begin
            if P = 1 then
                Delete(CurrentPath, 1, Length(PathToRemove) + 1)
            else
                Delete(CurrentPath, P, Length(PathToRemove) + 1);
            RegWriteStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', CurrentPath);
        end;
    end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
    if CurStep = ssPostInstall then
    begin
        AddToSystemPath(ExpandConstant('{app}'));
    end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
    ResultCode: Integer;
    MsgResponse: Integer;
begin
    if CurUninstallStep = usUninstall then
    begin
        MsgResponse := MsgBox(
            'Möchten Sie auch alle durch UFW erstellten Firewall-Regeln löschen (Regeln mit Präfix "UFW-")?' + #13#10 +
            'Klicken Sie auf "Ja", um sie zu löschen, oder auf "Nein", um die Regeln beizubehalten.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2
        );

        if MsgResponse = IDYES then
        begin
            Exec('powershell.exe', '-NoProfile -NonInteractive -Command "Get-NetFirewallRule -Name ''UFW-*'' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        end;

        RemoveFromSystemPath(ExpandConstant('{app}'));
    end;
end;
