<#
.SYNOPSIS  Registers the "McpPacemaker" per-user scheduled task (Windows), no admin required.
.DESCRIPTION
  Uses the Task Scheduler COM API (works even where the ScheduledTasks PS module reports
  "Invalid namespace" and schtasks.exe /Create needs elevation). Starts the supervisor at
  logon AND on workstation unlock (unlock covers sleep/wake, where logon never fires).
.PARAMETER Port  Port to pass through to the supervisor (default 8791).
#>
[CmdletBinding()]
param([int]$Port = 8791, [string]$TaskName = "McpPacemaker-$Port")

$ErrorActionPreference = 'Stop'
try {
  $vbs  = Join-Path $PSScriptRoot 'launcher.vbs'
  $user = "$env:USERDOMAIN\$env:USERNAME"

  $svc = New-Object -ComObject Schedule.Service
  $svc.Connect()
  $folder = $svc.GetFolder('\')

  $def = $svc.NewTask(0)
  $def.RegistrationInfo.Description = "Starts the mcp-pacemaker bridge supervisor (port $Port) at logon and on workstation unlock."
  $def.RegistrationInfo.Author = $user

  $def.Settings.Enabled = $true
  $def.Settings.StartWhenAvailable = $true
  $def.Settings.DisallowStartIfOnBatteries = $false
  $def.Settings.StopIfGoingOnBatteries = $false
  $def.Settings.ExecutionTimeLimit = 'PT0S'
  $def.Settings.RestartCount = 3
  $def.Settings.RestartInterval = 'PT1M'
  $def.Settings.MultipleInstances = 2            # IgnoreNew

  $logon = $def.Triggers.Create(9)               # TASK_TRIGGER_LOGON
  $logon.UserId = $user
  $unlock = $def.Triggers.Create(11)             # TASK_TRIGGER_SESSION_STATE_CHANGE
  $unlock.StateChange = 8                         # TASK_SESSION_UNLOCK
  $unlock.UserId = $user

  $action = $def.Actions.Create(0)               # TASK_ACTION_EXEC
  $action.Path = 'wscript.exe'
  $action.Arguments = "`"$vbs`" $Port"

  $def.Principal.UserId = $user
  $def.Principal.LogonType = 3                    # interactive token (no stored password)
  $def.Principal.RunLevel = 0                     # least privilege (so user CLI auth context works)

  $folder.RegisterTaskDefinition($TaskName, $def, 6, $user, $null, 3) | Out-Null
  Write-Output "OK: registered '$TaskName' (logon + unlock; $user; port $Port)"
}
catch {
  Write-Output "FAIL: $($_.Exception.Message)"
  exit 1
}
