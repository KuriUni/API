Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptPath = fso.GetParentFolderName(WScript.ScriptFullName) & "\operations\Xrea\Deploy-Xrea.ps1"
If Not fso.FileExists(scriptPath) Then
    MsgBox "Deploy-Xrea.ps1 not found:" & vbCrLf & scriptPath, vbCritical, "XREA Deploy"
    WScript.Quit 1
End If
powershellPath = shell.ExpandEnvironmentStrings("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")
q = Chr(34)
command = q & powershellPath & q & " -NoProfile -ExecutionPolicy Bypass -STA -File " & q & scriptPath & q
shell.Run command, 0, False
