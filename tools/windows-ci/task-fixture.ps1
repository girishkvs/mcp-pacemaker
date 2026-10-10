<#
.SYNOPSIS
Creates or removes one bound CI task collision/mismatch fixture.
.DESCRIPTION
Only operates on the current test's recorded task name and exact definition hash.
Never runs an action or changes task ACLs.
.PARAMETER InputDirectory
Owned ordinary launcher test directory.
.PARAMETER Mode
Collision creates one no-trigger fixture; Mismatch changes only its owned marker;
Cleanup deletes only the exact fixture definition recorded by this script.
.OUTPUTS
A private hash receipt for the owned fixture.
.EXAMPLE
.\task-fixture.ps1 -InputDirectory C:\private\run -Mode Cleanup
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputDirectory,
    [Parameter(Mandatory)][ValidateSet('Collision', 'Mismatch', 'Cleanup')][string]$Mode
)
$ErrorActionPreference = 'Stop'
$inputRecord = Get-Content -LiteralPath (Join-Path $InputDirectory 'task-request.json') -Raw | ConvertFrom-Json
$name = "mcp-pacemaker-ci-$($inputRecord.runId)"
if ($name -cne $inputRecord.taskName) { throw 'Invalid fixture task name.' }
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $service.GetFolder('\')
function Get-DefinitionHash {
    param([string]$Xml)
    $document = [xml]$Xml
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($document.OuterXml))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
$receiptPath = Join-Path $InputDirectory 'fixture-task.json'
if ($Mode -eq 'Cleanup') {
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    $task = $folder.GetTask($name)
    if ($receipt.runId -cne $inputRecord.runId -or
        $task.Path -cne "\$name" -or
        (Get-DefinitionHash -Xml $task.Definition.XmlText) -cne $receipt.sha256 -or
        $task.GetInstances(0).Count -ne 0) { throw 'Owned fixture cleanup binding differs.' }
    $folder.DeleteTask($name, 0)
    return
}
if (Test-Path -LiteralPath $receiptPath) { throw 'Fixture receipt already exists.' }
if ($Mode -eq 'Collision') {
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description = "Owned collision fixture $($inputRecord.runId)"
    $definition.Principal.UserId = $inputRecord.expectedSid
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 0
    $action = $definition.Actions.Create(0)
    $action.Path = $inputRecord.node
    $action.Arguments = '--version'
    $action.WorkingDirectory = $inputRecord.cwd
    $task = $folder.RegisterTaskDefinition($name, $definition, 18, $inputRecord.expectedSid, $null, 3, $null)
} else {
    $binding = Get-Content -LiteralPath (Join-Path $InputDirectory 'task-binding.json') -Raw | ConvertFrom-Json
    $task = $folder.GetTask($name)
    if ((Get-DefinitionHash -Xml $task.Definition.XmlText) -cne $binding.definitionSha256 -or
        $task.GetInstances(0).Count -ne 0) { throw 'Cannot alter an unverified fixture.' }
    $definition = $task.Definition
    $definition.RegistrationInfo.Description = "Owned mismatch fixture $($inputRecord.runId)"
    $task = $folder.RegisterTaskDefinition($name, $definition, 20, $inputRecord.expectedSid, $null, 3, $null)
}
$receipt = @{ runId = $inputRecord.runId; sha256 = Get-DefinitionHash -Xml $task.Definition.XmlText }
[IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
