#retrieve domain services logs for last two days
Get-WinEvent -FilterHashTable @{LogName='Directory Service'; StartTime=$((Get-Date).AddDays(-2))} -ErrorAction SilentlyContinue | `
  Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n"," ").Trim() }} | `
    Export-Csv "$($ENV:Userprofile)\Documents\$($env:computername)_ds.csv" -NoTypeInformation

#retrieve system Logs for last two days
Get-WinEvent -FilterHashTable @{LogName='Directory Service'; StartTime=$((Get-Date).AddDays(-2))} -ErrorAction SilentlyContinue | `
  Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n"," ").Trim() }} | `
    Export-Csv "$($ENV:Userprofile)\Documents\$($env:computername)_system.csv" -NoTypeInformation
    
#port Exhaustion
Get-NetTCPConnection | Group-Object -Property State, OwningProcess | `
  Select -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | `
    Sort Count -Descending | Export-Csv "$($ENV:Userprofile)\Documents\$($env:computername)_portExhaustion.csv" -NoTypeInformation
    
#
