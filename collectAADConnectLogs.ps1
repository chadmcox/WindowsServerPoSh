#Require -runasadministrator
<#PSScriptInfo

.VERSION 2021.10.3

.GUID f35dc756-c311-4d8b-8217-70edce08ac59

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

.TAGS Azure AD Connect

.DESCRIPTION 

#> 

#Check Temp Path, create a folder in temp just in case
$temp_location = "$env:TEMP\AAD"
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

$File = "$temp_location\$($env:computername)_logs_Application_$(get-date -f yyyy-MM-dd-HH-mm).csv"
CollectEventLogs -eventLogName "Application" | Export-Csv $File -NoTypeInformation

$File = "$temp_location\$($env:computername)_logs_System_$(get-date -f yyyy-MM-dd-HH-mm).csv"
CollectEventLogs -eventLogName "System" | Export-Csv $File -NoTypeInformation

#region gather computer info
$File = "$temp_location\$($env:computername)_gpresult_$(get-date -f yyyy-MM-dd-HH-mm).txt"
gpresult /V | out-file $File

write-host "collect computer info"
$File = "$temp_location\$($env:computername)_getcomputerinfo_$(get-date -f yyyy-MM-dd-HH-mm).txt"
Get-ComputerInfo | out-file $File

$File = "$temp_location\$($env:computername)_systeminfo_$(get-date -f yyyy-MM-dd-HH-mm).txt"
systeminfo | out-file $File

$File = "$temp_location\$($env:computername)_gpresult_$(get-date -f yyyy-MM-dd-HH-mm).txt"
gpresult /V | out-file $File


$File = "$temp_location\$($env:computername)_aadserviceaccountprems_$(get-date -f yyyy-MM-dd-HH-mm).txt"
Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1" 
Get-ADSyncADConnectorAccount | add-content -Path $File
Show-ADSyncADObjectPermissions -ADobjectDN (get-aduser -ldapfilter "(&(!(admincount=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" | select -first 1 ).DistinguishedName |  add-content -Path $File

dir "$env:ProgramData\AADConnect"  | where {$_.LastWriteTime -gt (get-date).AddDays(-15)} | foreach{
    copy-item -Container $_.FullName  -Destination "C:\Data" -Force
}

$archive_location = "$($ENV:USERPROFILE)\Documents\$($env:computername)_AADC_Logs_Archive_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
archiveresults -source $temp_location -destination $archive_location
write-host "FINSIHED: Collect and Send this file - $archive_location" -ForegroundColor Yellow
