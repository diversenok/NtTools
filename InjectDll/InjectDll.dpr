program InjectDll;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  Ntapi.WinNt,
  NtUtils,
  NtUtils.Console,
  NtUtils.Files,
  NtUtils.SysUtils,
  NtUtils.Processes.Snapshots,
  NtUtils.Shellcode.Dll,
  NtUiLib.Errors;

function Main: TNtxStatus;
var
  hxProcess: IHandle;
  DllBase: Pointer;
begin
  writeln('DLL Injection Tool by diversenok.');
  writeln;

  write('Process name or PID: ');
  Result := NtxOpenProcessByName(hxProcess, ReadString(False),
    PROCESS_INJECT_DLL, [pnAllowShortNames, pnAllowPIDs]);

  if Result.IsSuccess then
  begin
    write('File name: ');
    Result := RtlxInjectDllProcess(hxProcess, RtlxGetFullDosPath(
      ReadString(False)), NT_INFINITE, @DllBase);
  end;

  writeln;

  if Result.IsSuccess then
    writeln('Successfully loaded DLL at address ', RtlxPtrToStr(DllBase))
  else
    writeln(Result.ToString);
end;

begin
  Main;
end.

