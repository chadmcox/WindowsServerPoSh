
<#PSScriptInfo

.VERSION 0.1

.GUID 7e3e6d92-fcba-4f46-ab1c-41d2d3e6b004

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

.TAGS Active Directory PowerShell Get-addomaincontroller

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory
#Requires -version 4.0
<# 

.DESCRIPTION 
 This script gathers every dc in the forest and list all of the network shares. 

#> 
Param($default_path = "$($env:userprofile)\Documents")

$default_log = $default_path + '\report_DomainControllerSMBShares.csv'
$results = @()
$domain_controllers = ((get-adforest).domains | foreach{Get-ADDomainController -filter * -server $_}).hostname
$results = $domain_controllers | foreach{$dc = $_; Get-SmbShare -CimSession $dc} 
$results | export-csv $default_log -NoTypeInformation

write-host "Here is the share count for each DC"
$results | group PSComputerName | select name, count
write-host -foregroundcolor yellow "To view results run: import-csv $default_log | out-gridview"
