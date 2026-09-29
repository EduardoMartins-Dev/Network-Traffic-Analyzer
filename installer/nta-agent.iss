; ============================================================================
; Instalador do agente NTA para Windows (Inno Setup 6).
;
;   iscc /DAppVersion=1.2.3 installer\nta-agent.iss
;   (espera build\NetworkTrafficAnalyzer.exe — build estático MSYS2/UCRT64)
;
; O que faz:
;   - exige o Npcap instalado em modo compatível com WinPcap (wpcap.dll);
;   - pergunta servidor/porta/usuário/token e a interface de captura;
;   - grava C:\ProgramData\NTA\agent.conf legível só por SYSTEM/Administradores
;     (guarda o token); numa atualização o agent.conf existente é mantido;
;   - registra e inicia o serviço NTAAgent; a desinstalação o remove.
;
; Instalação silenciosa (implantação em massa):
;   NTA-Agent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /SERVER=10.0.0.5
;     /PORT=5674 /USER=agente-01 /TOKEN=segredo /IFACE=\Device\NPF_{GUID}
; ============================================================================

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#define ExeName  "NetworkTrafficAnalyzer.exe"
#define BuildDir "..\build"

[Setup]
AppId={{B7C4E2A1-5F3D-4E8A-9C21-7D6A3E0F9B42}
AppName=Network Traffic Analyzer Agent
AppVersion={#AppVersion}
AppPublisher=EduardoMartins-Dev
AppPublisherURL=https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer
DefaultDirName={autopf}\NTA Agent
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=..\LICENSE
OutputDir={#BuildDir}\installer
OutputBaseFilename=NTA-Agent-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayIcon={app}\{#ExeName}

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#BuildDir}\{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\deploy\agent.env.example"; DestDir: "{app}"; DestName: "agent.conf.example"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\{#ExeName}"; Parameters: "--install-service --config ""{commonappdata}\NTA\agent.conf"""; Flags: runhidden waituntilterminated; StatusMsg: "Registrando o serviço NTAAgent..."
Filename: "{sys}\sc.exe"; Parameters: "start NTAAgent"; Flags: runhidden waituntilterminated; StatusMsg: "Iniciando o serviço NTAAgent..."

[UninstallRun]
Filename: "{app}\{#ExeName}"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
var
  ServerPage: TInputQueryWizardPage;
  IfacePage: TInputOptionWizardPage;
  IfaceNames: TArrayOfString;

function ConfigPath: String;
begin
  Result := ExpandConstant('{commonappdata}\NTA\agent.conf');
end;

{ Upgrade: config já existe -> mantém e não pergunta de novo. }
function IsUpgrade: Boolean;
begin
  Result := FileExists(ConfigPath);
end;

{ O .exe importa wpcap.dll do System32: exige o modo compatível com WinPcap. }
function NpcapReady: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap') and
            FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

function InitializeSetup: Boolean;
var
  ErrCode: Integer;
begin
  Result := True;
  if not NpcapReady then
  begin
    if SuppressibleMsgBox('O Npcap não foi encontrado, ou foi instalado sem a opção ' +
        '"Install Npcap in WinPcap API-compatible Mode".' + #13#10#13#10 +
        'Instale o Npcap marcando essa opção e execute este instalador novamente.' + #13#10#13#10 +
        'Abrir a página de download do Npcap agora?',
        mbError, MB_YESNO, IDNO) = IDYES then
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ErrCode);
    Result := False;
  end;
end;

procedure AddIface(const Name, Desc, Ip: String);
var
  Lbl: String;
  N: Integer;
begin
  if Name = '' then Exit;
  Lbl := Desc;
  if Lbl = '' then Lbl := Name;
  if Ip <> '' then Lbl := Lbl + '  (' + Ip + ')';
  IfacePage.Add(Lbl);
  N := GetArrayLength(IfaceNames);
  SetArrayLength(IfaceNames, N + 1);
  IfaceNames[N] := Name;
  { Pré-seleciona a primeira interface com IP "de verdade". }
  if (IfacePage.SelectedValueIndex < 0) and (Ip <> '') and
     (Pos('169.254.', Ip) <> 1) and (Pos('127.', Ip) <> 1) then
    IfacePage.SelectedValueIndex := N;
end;

{ Roda "--list-interfaces" e popula a página: linha sem recuo = nome
  (\Device\NPF_...), linhas com recuo = descrição e "IPv4 x.x.x.x". }
procedure LoadInterfaces;
var
  OutFile, Line, T, Name, Desc, Ip: String;
  Lines: TArrayOfString;
  I, RC: Integer;
begin
  ExtractTemporaryFile('{#ExeName}');
  OutFile := ExpandConstant('{tmp}\ifaces.txt');
  Exec(ExpandConstant('{cmd}'), '/C ""' + ExpandConstant('{tmp}\{#ExeName}') +
       '" --list-interfaces > "' + OutFile + '""', '', SW_HIDE, ewWaitUntilTerminated, RC);
  if not LoadStringsFromFile(OutFile, Lines) then Exit;

  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    Line := Lines[I];
    if Line = '' then Continue;
    if Line[1] <> ' ' then
    begin
      AddIface(Name, Desc, Ip);
      Name := Trim(Line); Desc := ''; Ip := '';
    end else begin
      T := Trim(Line);
      if Pos('IPv4 ', T) = 1 then
      begin
        if Ip = '' then Ip := Copy(T, 6, 64);
      end else if Desc = '' then
        Desc := T;
    end;
  end;
  AddIface(Name, Desc, Ip);
  if (IfacePage.SelectedValueIndex < 0) and (GetArrayLength(IfaceNames) > 0) then
    IfacePage.SelectedValueIndex := 0;
end;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Servidor NTA', 'Para onde o agente envia os eventos',
    'Informe o RabbitMQ do servidor central e as credenciais deste agente ' +
    '(RABBITMQ_USER/RABBITMQ_PASS do servidor, ou um usuário dedicado por agente).');
  ServerPage.Add('Servidor (host ou IP):', False);
  ServerPage.Add('Porta AMQP:', False);
  ServerPage.Add('Usuário (AGENT_ID):', False);
  ServerPage.Add('Senha / token (AGENT_TOKEN):', True);
  ServerPage.Values[0] := ExpandConstant('{param:SERVER|localhost}');
  ServerPage.Values[1] := ExpandConstant('{param:PORT|5674}');
  ServerPage.Values[2] := ExpandConstant('{param:USER|}');
  ServerPage.Values[3] := ExpandConstant('{param:TOKEN|}');

  IfacePage := CreateInputOptionPage(ServerPage.ID,
    'Interface de captura', 'Qual placa de rede o agente deve monitorar?',
    'Escolha a interface pela qual passa o tráfego que você quer analisar.',
    True, True);
  LoadInterfaces;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := IsUpgrade and ((PageID = ServerPage.ID) or (PageID = IfacePage.ID));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    if (Trim(ServerPage.Values[0]) = '') or (Trim(ServerPage.Values[2]) = '') then
    begin
      MsgBox('Informe o servidor e o usuário.', mbError, MB_OK);
      Result := False;
    end else if StrToIntDef(Trim(ServerPage.Values[1]), 0) <= 0 then
    begin
      MsgBox('Porta inválida.', mbError, MB_OK);
      Result := False;
    end;
  end else if (CurPageID = IfacePage.ID) and (GetArrayLength(IfaceNames) = 0) then
  begin
    MsgBox('Nenhuma interface de captura encontrada. Verifique a instalação do Npcap.',
           mbError, MB_OK);
    Result := False;
  end;
end;

function SelectedIface: String;
begin
  Result := ExpandConstant('{param:IFACE|}');
  if (Result = '') and (IfacePage.SelectedValueIndex >= 0) then
    Result := IfaceNames[IfacePage.SelectedValueIndex];
end;

{ Grava agent.conf e restringe o acesso: só SYSTEM (S-1-5-18) e
  Administradores (S-1-5-32-544) — o arquivo guarda o token. }
procedure WriteConfig;
var
  Lines: TArrayOfString;
  RC: Integer;
begin
  ForceDirectories(ExpandConstant('{commonappdata}\NTA'));
  SetArrayLength(Lines, 8);
  Lines[0] := '# Gerado pelo instalador do NTA Agent {#AppVersion}. Chaves: agent.conf.example';
  Lines[1] := '# Após editar: sc.exe stop NTAAgent  e  sc.exe start NTAAgent';
  Lines[2] := 'AGENT_SERVER_HOST=' + Trim(ServerPage.Values[0]);
  Lines[3] := 'AGENT_SERVER_PORT=' + Trim(ServerPage.Values[1]);
  Lines[4] := 'AGENT_ID=' + Trim(ServerPage.Values[2]);
  Lines[5] := 'AGENT_TOKEN=' + ServerPage.Values[3];
  Lines[6] := 'AGENT_IFACE=' + SelectedIface;
  Lines[7] := 'AGENT_LOG_FILE=' + ExpandConstant('{commonappdata}\NTA\agent.log');
  SaveStringsToUTF8File(ConfigPath, Lines, False);
  Exec(ExpandConstant('{sys}\icacls.exe'), '"' + ConfigPath +
       '" /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F',
       '', SW_HIDE, ewWaitUntilTerminated, RC);
end;

{ Atualização: para e remove o serviço antigo antes de trocar o .exe
  (arquivo em uso) — o [Run] recria o serviço no fim. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  Result := '';
  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\NTAAgent') then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop NTAAgent', '', SW_HIDE, ewWaitUntilTerminated, RC);
    Sleep(3000);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete NTAAgent', '', SW_HIDE, ewWaitUntilTerminated, RC);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssInstall) and not IsUpgrade then
    WriteConfig;
end;
