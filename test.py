import re

powershell_logs = [
    r"Copy-Item ('C:\Windows\NTDS\nt' + 'ds.dit') -Destination 'C:\exfil\data.bin'",
    r"New-Item -ItemType SymbolicLink -Path C:\temp\vss_link -Target \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
    r"Invoke-WmiMethod -Class ('Win32_Shad' + 'owCopy') -Name ('Cre' + 'ate') -ArgumentList 'C:\'",
    r"Get-Process | Where-Object { $_.Modules.ModuleName -contains 'rdpcorets.dll' }",
    r"Get-Item -Path 'HKCU:\Software' | Export-Clixml -Path 'C:\temp\export.xml'",
    r"Set-Clipboard -Value 'Write-Host test'; Invoke-Expression (Get-Clipboard)"
]

pattern = r"(?i)\b([a-z]+(?:-[a-z0-9]+)+)\b([^;|]*)"

for log in powershell_logs:
    print(f"\n--- Analyzing Log: {log[:30]}... ---")
    
    # finditer allows us to catch multiple cmdlets in a single line
    matches = re.finditer(pattern, log)
    
    for match in matches:
        cmdlet = match.group(1).strip()
        args = match.group(2).strip()
        print(f"Cmdlet: {cmdlet.ljust(20)} | Args: {args}")