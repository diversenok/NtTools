program RunAsS4U;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  Ntapi.WinNt,
  Ntapi.ntstatus,
  Ntapi.ntseapi,
  Ntapi.WinUser,
  Ntapi.ProcessThreadsApi,
  NtUtils,
  NtUtils.Tokens,
  NtUtils.Tokens.Info,
  NtUtils.Tokens.Impersonate,
  NtUtils.Tokens.Logon,
  NtUtils.Threads,
  NtUtils.Profiles,
  NtUtils.Security.Sid,
  NtUtils.Security.Acl,
  NtUtils.Processes.Snapshots,
  NtUtils.Processes.Create,
  NtUtils.Processes.Create.Win32,
  NtUtils.Environment.User,
  NtUtils.Lsa.Sid,
  NtUtils.WinUser,
  NtUtils.Console,
  NtUiLib.Errors;

function Main: TNtxStatus;
var
  hxSystemProcess: IHandle;
  hxToken: IHandle;
  hxProfileKey: IHandle;
  AccountName: TTranslatedName;
  Sid: ISid;
  MakeAdmin: Boolean;
  DefaultDacl: IAcl;
  AdditionalGroups: TArray<TGroup>;
  ProcessOptions: TCreateProcessOptions;
  ProcessInfo: TProcessInfo;
begin
  writeln('RunAsS4U: run programs as other users without knowing passwords. ' +
    '(c) diversenok'#$D#$A);

  // Using S4U requires the TCB privilege; try enabling it
  Result := NtxAdjustPrivilege(NtxCurrentProcessToken, SE_TCB_PRIVILEGE,
    SE_PRIVILEGE_ENABLED, True);

  if not Result.IsSuccess then
    Exit;

  if Result.Status = STATUS_NOT_ALL_ASSIGNED then
  begin
    // TCB is not available; we need to impersonate a SYSTEM token
    Result := NtxAdjustPrivilege(NtxCurrentProcessToken,
      SE_IMPERSONATE_PRIVILEGE, SE_PRIVILEGE_ENABLED);

    if not Result.IsSuccess then
      Exit;

    // Winlogon is a good candidate for getting a SYSTEM token
    Result := NtxOpenProcessByName(hxSystemProcess, 'winlogon.exe',
      PROCESS_QUERY_LIMITED_INFORMATION, [pnCurrentSessionOnly]);

    if not Result.IsSuccess then
      Exit;

    // Open the primary token for duplication
    Result := NtxOpenProcessToken(hxToken, hxSystemProcess.Handle,
      TOKEN_DUPLICATE);

    if not Result.IsSuccess then
      Exit;

    // Convert the token into an impersonation one
    Result := NtxDuplicateTokenLocal(hxToken, TokenImpersonation,
      SecurityImpersonation);

    if not Result.IsSuccess then
      Exit;

    // Impersonate it
    Result := NtxSafeSetThreadToken(NtxCurrentThread, hxToken,
      [siSkipLevelCheck]);

    if not Result.IsSuccess then
      Exit;
  end;

  write('Account name: ');

  // Lookup the username and split it into domain + user
  Result := LsaxCanonicalizeName(ReadString(False), AccountName);

  if not Result.IsSuccess then
    Exit;

  // Make sure to include the current window stations's logon SID into the token
  Result := UsrxQuerySid(GetProcessWindowStation, Sid);

  if not Result.IsSuccess then
    Exit;

  if Assigned(Sid) then
    AdditionalGroups := [TGroup.From(Sid,
      SE_GROUP_ENABLED_BY_DEFAULT or SE_GROUP_ENABLED or SE_GROUP_LOGON_ID
    )]
  else
    // As a fallback, use NT AUTHORITY\RESTRICTED instead
    AdditionalGroups := [TGroup.From(
      RtlxMakeSid(SECURITY_NT_AUTHORITY, [SECURITY_RESTRICTED_CODE_RID]),
      SE_GROUP_ENABLED_BY_DEFAULT or SE_GROUP_ENABLED
    )];

  write('Should the new process have administrative privileges? [y/n]: ');
  MakeAdmin := ReadBoolean;
  writeln;

  if MakeAdmin then
    AdditionalGroups := AdditionalGroups + [
      // Add NT AUTHORITY\Local account and member of Administrators
      TGroup.From(RtlxMakeSid(SECURITY_NT_AUTHORITY, [
        SECURITY_LOCAL_ACCOUNT_AND_ADMIN_RID
      ]), SE_GROUP_ENABLED_BY_DEFAULT or SE_GROUP_ENABLED),

      // Add BUILTIN\Administrators
      TGroup.From(RtlxMakeSid(SECURITY_NT_AUTHORITY, [
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS
      ]), SE_GROUP_ENABLED_BY_DEFAULT or SE_GROUP_ENABLED or SE_GROUP_OWNER)
    ];

  // Always include NT AUTHORITY\INTERACTIVE
  AdditionalGroups := AdditionalGroups + [TGroup.From(RtlxMakeSid(
    SECURITY_NT_AUTHORITY, [SECURITY_INTERACTIVE_RID]),
    SE_GROUP_ENABLED_BY_DEFAULT or SE_GROUP_ENABLED)];

  // Logon the user via S4U
  Result := LsaxLogonS4U(hxToken, AccountName.DomainName, AccountName.UserName,
    TTokenSource.New('RunAsS4U'), AdditionalGroups);

  if not Result.IsSuccess then
    Exit;

  if not MakeAdmin then
  begin
    // Filter the token to strip admin groups and privileges
    Result := NtxFilterTokenInline(hxToken, LUA_TOKEN);

    if not Result.IsSuccess then
      Exit;

    // Lower its integrity
    Result := NtxSetIntegrityToken(hxToken, SECURITY_MANDATORY_MEDIUM_RID);

    if not Result.IsSuccess then
      Exit;

    // We also need to correct the default DACL after filtration;
    // construct it based on the new owner and logon SID from the token
    Result := NtxMakeDefaultDaclToken(hxToken, DefaultDacl);

    if not Result.IsSuccess then
      Exit;

    // Adjust the default DACL
    Result := NtxSetDefaultDaclToken(hxToken, DefaultDacl);

    if not Result.IsSuccess then
      Exit;
  end;

  // Load the profile for the user
  Result := UnvxLoadProfile(hxProfileKey, hxToken);

  if not Result.IsSuccess then
    Exit;

  ProcessOptions := Default(TCreateProcessOptions);
  ProcessOptions.Application := USER_SHARED_DATA.NtSystemRoot +
    '\system32\cmd.exe';
  ProcessOptions.Flags := [poNewConsole];
  ProcessOptions.hxToken := hxToken;

  // Prepare the correct environment for the user
  Result := UnvxCreateUserEnvironment(ProcessOptions.Environment, hxToken,
    False, False);

  if not Result.IsSuccess then
    Exit;

  // Spawn CMD using the token
  Result := AdvxCreateProcess(ProcessOptions, ProcessInfo);
end;

procedure RunMain;
var
  Result: TNtxStatus;
  Completed: Boolean;
begin
  Completed := False;

  try
    Result := Main;

    if Result.IsSuccess then
      writeln('Success.')
    else
      writeln(Result.ToString);

    Completed := True;
  finally
    if not Completed then
      writeln('An exception occured :(');
  end;
end;

begin
  RunMain;
end.

