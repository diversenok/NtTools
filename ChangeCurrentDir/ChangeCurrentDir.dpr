program ChangeCurrentDir;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  NtUtils,
  NtUtils.Files,
  NtUiLib.Errors,
  NtUtils.Processes.Info,
  NtUtils.Processes.Snapshots,
  NtUtils.Environment.Remote,
  NtUtils.Console;

function Main: TNtxStatus;
var
  hxProcess: IHandle;
  CurrentDirectory, ExpandedCurrentDirectory: String;
begin
  writeln('Current directory changer by diversenok.');
  writeln;

  write('Process name or PID: ');
  Result := NtxOpenProcessByName(hxProcess, ReadString(False),
    PROCESS_READ_PEB or PROCESS_SET_DIRECTORY, [pnAllowShortNames, pnAllowPIDs]);

  if not Result.IsSuccess then
    Exit;

  Result := NtxReadPebStringProcess(hxProcess.Handle, PebStringCurrentDirectory,
    CurrentDirectory);

  if not Result.IsSuccess then
    CurrentDirectory := '(Unknown)';

  writeln('Old: ', CurrentDirectory);

  write('New: ');
  CurrentDirectory := ReadString(False);
  ExpandedCurrentDirectory := RtlxGetFullDosPath(CurrentDirectory);

  if CurrentDirectory <> ExpandedCurrentDirectory then
    writeln('New (expanded): ', ExpandedCurrentDirectory);

  Result := RtlxSetDirectoryProcess(hxProcess, ExpandedCurrentDirectory);
end;

procedure RunMain;
var
  Status: TNtxStatus;
begin
  Status := Main;
  writeln;

  if Status.IsSuccess then
    writeln('Success.')
  else
    writeln(Status.ToString);
end;

begin
  RunMain;
end.
