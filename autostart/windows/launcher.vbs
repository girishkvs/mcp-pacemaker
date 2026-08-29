' Launches the mcp-pacemaker supervisor hidden (no console window).
' Invoked by the "McpPacemaker" scheduled task. Arg 0 = port (optional, default 8791).
Dim shell, fso, here, root, ps1, port
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)                 ' autostart\windows
root = fso.GetParentFolderName(fso.GetParentFolderName(here))          ' repo root
ps1 = fso.BuildPath(root, "supervisor\supervise.ps1")
port = "8791"
If WScript.Arguments.Count > 0 Then port = WScript.Arguments(0)
shell.Run "pwsh.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """ -Port " & port, 0, False
