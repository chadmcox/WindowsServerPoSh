#Require -runasadministrator
<#PSScriptInfo

.VERSION 2019.8.5

.GUID 1b77c367-a9b9-4182-b671-1ca70b9f95e1

.AUTHOR Chad.Cox@microsoft.com
    https://blogs.technet.microsoft.com/chadcox/
    https://github.com/chadmcox

.COMPANYNAME 

.COPYRIGHT This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys` fees, that arise or result
from the use or distribution of the Sample Code..

.TAGS Windows Hello for Business

.DESCRIPTION 

#> 

#Check Temp Path, create a folder in temp just in case
$temp_location = "$env:TEMP\WH4BTS"
if(!(test-path $temp_location)){
    md $temp_location
}
set-location $temp_location

#functions
function archiveresults{
    [cmdletbinding()]
    param($source,$destination)
    Process{
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($source, $destination) 
    }
}
function CollectEventLogs{
    [cmdletbinding()]
    param($eventLogName)

    write-host "collect Event logs $eventLogName"
    Get-WinEvent -FilterHashTable @{LogName=$eventLogName} `
        -ErrorAction SilentlyContinue | Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName, `
            @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} 
}

#region gather Logs

$File = "$temp_location\$($env:computername)_logs_HelloForBusiness_$(get-date -f yyyy-MM-dd-HH-mm).csv"
CollectEventLogs -eventLogName "Microsoft-Windows-HelloForBusiness/Operational" | Export-Csv $File -NoTypeInformation

$File = "$temp_location\$($env:computername)_logs_System_$(get-date -f yyyy-MM-dd-HH-mm).csv"
CollectEventLogs -eventLogName "System" | Export-Csv $File -NoTypeInformation

$File = "$temp_location\$($env:computername)_logs_AAD_$(get-date -f yyyy-MM-dd-HH-mm).csv"
CollectEventLogs -eventLogName "Microsoft-Windows-AAD/Operational" | Export-Csv $File -NoTypeInformation

#endregion

#region gather certs
write-host "collect certinfo"
$File = "$temp_location\$($env:computername)_certs_currentuser_$(get-date -f yyyy-MM-dd-HH-mm).txt"
dir Cert:\CurrentUser\My | select * | out-file $File

$File = "$temp_location\$($env:computername)_certs_LocalMachine_$(get-date -f yyyy-MM-dd-HH-mm).txt"
dir Cert:\LocalMachine\My | select * | out-file $File

#endregion
#region gather dsregcmd
write-host "collect dsregcmd"
$File = "$temp_location\$($env:computername)_dsregcmd_$(get-date -f yyyy-MM-dd-HH-mm).txt"
dsregcmd /status | out-file $File

#endregion

#region gather computer info
write-host "collect computer info"
$File = "$temp_location\$($env:computername)_getcomputerinfo_$(get-date -f yyyy-MM-dd-HH-mm).txt"
Get-ComputerInfo | out-file $File

$File = "$temp_location\$($env:computername)_systeminfo_$(get-date -f yyyy-MM-dd-HH-mm).txt"
systeminfo | out-file $File

$File = "$temp_location\$($env:computername)_gpresult_$(get-date -f yyyy-MM-dd-HH-mm).txt"
gpresult /V | out-file $File

$File = "$temp_location\$($env:computername)_gettpm_$(get-date -f yyyy-MM-dd-HH-mm).txt"
Get-Tpm | select * | out-file $File

$archive_location = "$($ENV:USERPROFILE)\Documents\$($env:computername)_WH4B_Logs_Archive_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
archiveresults -source $temp_location -destination $archive_location
write-host "FINSIHED: Collect and Send this file - $archive_location" -ForegroundColor Yellow

