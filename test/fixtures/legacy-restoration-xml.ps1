param(
    [ValidateSet('normalized','action','principal','logon','runlevel','enabled','trigger','settings','metadata',
        'malformed','duplicate','duplicate-registration','wrong-namespace','nested','dtd')][string]$Case = 'normalized',
    [switch]$UseInputRecord
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\autostart\windows\legacy-task.ps1') -Operation inspect -Port 1 -FunctionsOnly
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$definition = $service.NewTask(0)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = "O:${sid}G:${sid}D:P(A;;FA;;;$sid)S:(ML;;NW;;;ME)"
$definition.RegistrationInfo.Description = 'Owned parser-only restoration model; never registered'
$definition.Principal.UserId = $sid
$definition.Principal.LogonType = 3
$definition.Principal.RunLevel = 0
$definition.Settings.Enabled = $true
$action = $definition.Actions.Create(0)
$action.Path = 'wscript.exe'
$action.Arguments = '"C:\owned\never-run.vbs"'
$trigger = $definition.Triggers.Create(9)
$trigger.UserId = $sid
$trigger.Enabled = $false
if ($UseInputRecord) {
    $record = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $sid = $record.userSid
    $sddl = $record.security.sddl
    $definition.Principal.UserId = $sid
    $definition.Principal.LogonType = $record.logonType
    $definition.Principal.RunLevel = $record.runLevel
    $definition.Settings.Enabled = $record.enabled
    $action.Path = $record.actions[0].path
    $action.Arguments = $record.actions[0].arguments
    $action.WorkingDirectory = $record.actions[0].workingDirectory
    $definition.Triggers.Clear()
    foreach ($entry in $record.triggers) {
        $item = $definition.Triggers.Create($entry.type)
        $item.UserId = $entry.userSid
        $item.Enabled = $entry.enabled
        if ($entry.type -eq 11) { $item.StateChange = $entry.stateChange }
    }
    $definition.Settings.MultipleInstances = $record.settings.multipleInstances
    $definition.Settings.RestartCount = $record.settings.restartCount
    $definition.Settings.RestartInterval = $record.settings.restartInterval
    $definition.Settings.ExecutionTimeLimit = $record.settings.executionTimeLimit
    $definition.Settings.StartWhenAvailable = $record.settings.startWhenAvailable
    $definition.Settings.DisallowStartIfOnBatteries = $record.settings.disallowStartIfOnBatteries
    $definition.Settings.StopIfGoingOnBatteries = $record.settings.stopIfGoingOnBatteries
}
$definition.RegistrationInfo.SecurityDescriptor = $sddl
$originalXml = $definition.XmlText
$actual = $service.NewTask(0)
$actual.XmlText = $originalXml
$actual.RegistrationInfo.SecurityDescriptor = ''
switch ($Case) {
    'action' { $actual.Actions.Item(1).Arguments += ' --changed' }
    'principal' { $actual.Principal.UserId = 'S-1-5-18' }
    'logon' { $actual.Principal.LogonType = 1 }
    'runlevel' { $actual.Principal.RunLevel = 1 }
    'enabled' { $actual.Settings.Enabled = -not $actual.Settings.Enabled }
    'trigger' { $actual.Triggers.Item(1).Enabled = -not $actual.Triggers.Item(1).Enabled }
    'settings' { $actual.Settings.Priority = 8 }
    'metadata' { $actual.RegistrationInfo.Description += ' changed' }
}
$actualXml = $actual.XmlText
if ($Case -in @('duplicate','duplicate-registration','wrong-namespace','nested')) {
    $document = [xml]$actualXml
    $namespace = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    $embedded = $document.GetElementsByTagName('SecurityDescriptor', $namespace).Item(0)
    switch ($Case) {
        'duplicate' { $null = $embedded.ParentNode.AppendChild($embedded.CloneNode($true)) }
        'duplicate-registration' { $null = $document.DocumentElement.AppendChild($embedded.ParentNode.CloneNode($true)) }
        'wrong-namespace' { $null = $embedded.ParentNode.ReplaceChild($document.CreateElement('SecurityDescriptor', 'urn:wrong'), $embedded) }
        'nested' { $null = $document.GetElementsByTagName('Actions', $namespace).Item(0).AppendChild($embedded) }
    }
    $actualXml = $document.OuterXml
}
if ($Case -eq 'malformed') { $actualXml = '<Task' }
if ($Case -eq 'dtd') { $actualXml = '<!DOCTYPE Task [<!ENTITY owned "unused">]>' + ($actualXml -replace '^<\?xml[^?]*\?>\s*', '') }
@{ qualification = 'real Task Scheduler XML parser with synthetic records, no registered task or resource-security mutation'
    originalXml = $originalXml; actualXml = $actualXml; sid = $sid; security = (ConvertTo-TaskSecurity -Sddl $sddl)
} | ConvertTo-Json -Depth 6 -Compress
