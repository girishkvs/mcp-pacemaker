<#
.SYNOPSIS
Reads the selected per-user Pacemaker task and its legacy task identity.
.DESCRIPTION
Returns task actions and principal data without changing tasks or processes.
.PARAMETER Port
Selected service port.
.OUTPUTS
JSON array of existing task identities.
.EXAMPLE
.\inspect-task.ps1 -Port 8791
#>
[CmdletBinding()]
param([ValidateRange(1, 65535)][int]$Port)

$ErrorActionPreference = 'Stop'
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $service.GetFolder('\')
$names = @("McpPacemaker-$Port", 'McpPacemaker')
$records = @()
foreach ($task in $folder.GetTasks(1)) {
  if ($task.Name -notin $names) { continue }
  $actions = @()
  foreach ($action in $task.Definition.Actions) {
    $actions += @{
      type = $action.Type
      path = $action.Path
      arguments = $action.Arguments
      workingDirectory = $action.WorkingDirectory
    }
  }
  $records += @{
    name = $task.Name
    enabled = $task.Enabled
    user = $task.Definition.Principal.UserId
    logonType = $task.Definition.Principal.LogonType
    runLevel = $task.Definition.Principal.RunLevel
    actions = $actions
  }
}
ConvertTo-Json -InputObject $records -Depth 5 -Compress
