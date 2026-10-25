# Creates a Windows Desktop shortcut with icon for ThreatWeaver
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$ShortcutPath = Join-Path $DesktopPath "ThreatWeaver.lnk"
$TargetDir = Resolve-Path (Join-Path $PSScriptRoot "..")

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "wscript.exe"
$Shortcut.Arguments = "`"$TargetDir\ThreatWeaver.vbs`""
$Shortcut.WorkingDirectory = "$TargetDir"
$Shortcut.IconLocation = "$TargetDir\assets\threatweaver.ico, 0"
$Shortcut.Description = "ThreatWeaver — Static PE Security Platform"
$Shortcut.Save()

Write-Host "Created Desktop Shortcut at: $ShortcutPath"
