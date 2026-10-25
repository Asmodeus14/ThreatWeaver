' ThreatWeaver Silent Desktop Launcher (No flashing command prompt)
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
ScriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = ScriptDir

PythonwPath = ScriptDir & "\.venv\Scripts\pythonw.exe"
If Not FSO.FileExists(PythonwPath) Then
    PythonwPath = "pythonw.exe"
End If

WshShell.Run """" & PythonwPath & """ """ & ScriptDir & "\ThreatWeaver.py""", 0, False
Set WshShell = Nothing
Set FSO = Nothing
