$counter_objects = "\Netlogon(_Total)\*","\Security System-Wide Statistics\NTLM Authentications","\Security System-Wide Statistics\Kerberos Authentications", `
    "\DirectoryServices(*)\*","\Database(lsass)\*","\NTDS\*","\Memory\*","\PhysicalDisk(*)\*","\Process(*)\*","\Processor(*)\*","\TCPv4\*","\DNS\*","\ADWS\*"
get-counter -Counter $counter_objects -pv c -MaxSamples 5 | select -ExpandProperty countersamples | select `
    @{N="Timestamp";E={$c.Timestamp}}, `
    @{N="Computer";E={($_.path -split "\\")[2]}}, `
    @{N="Object";E={((($_.path -split "\\")[3]).split("("))[0]}}, `
    @{N="Counter";E={($_.path -split "\\")[4]}}, `
    instancename, cookedvalue | where cookedvalue -gt 0 | export-csv "$($ENV:Userprofile)\Documents\$($env:computername)_perf.csv" -NoTypeInformation

"Application", "System", "Directory Service", "DFS Replication", "DNS Server","Windows PowerShell","Active Directory Web Services","Microsoft-Windows-GroupPolicy/Operational" | foreach{
Get-WinEvent -FilterHashTable @{LogName=$_; StartTime=$((Get-Date).AddDays(-2))} -ErrorAction SilentlyContinue | `
    Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | `
        export-csv "$($ENV:Userprofile)\Documents\$($env:computername)_$(($_ -replace(" ","_")).replace("/","_"))" -NoTypeInformation
}
Compress-Archive -path "$($ENV:Userprofile)\Documents\$($env:computername)*" -DestinationPath "$($ENV:Userprofile)\Documents\$($env:computername)_logs_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
