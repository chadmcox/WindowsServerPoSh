
#Requires -version 3.0
#Requires -RunAsAdministrator

<#PSScriptInfo

.VERSION 0.1

.GUID 5f7bfd30-88b8-4f4d-99fd-c4ffbfcf5be6

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

.RELEASENOTES

.DESCRIPTION 
 

#> 

Param($reportpath = "$env:userprofile\Documents")

Get-WinEvent -FilterHashtable @{"ProviderName"="AD FS Auditing";Id=1210} -PipelineVariable event | foreach{
$eventXML = [xml]$Event.ToXml()
$eventdata = $eventXML.Event.EventData.Data
$eventstuff = [xml]$eventdata[1]
$event | select TimeCreated, `
    @{Name ='UserID';expression={$eventstuff.auditbase.ContextComponents.component[0].UserId}}, `
    @{Name ='AuthProtocol';expression={$eventstuff.auditbase.ContextComponents.component[1].AuthProtocol}}, `
    @{Name ='IP';expression={$eventstuff.auditbase.ContextComponents.component[1].IpAddress}}, `
    @{Name ='ForwardedIP';expression={$eventstuff.auditbase.ContextComponents.component[1].ForwardedIpAddress}}, `
    @{Name ='ProxyIP';expression={$eventstuff.auditbase.ContextComponents.component[1].ProxyIpAddress}}, `
    @{Name ='ProxyServer';expression={$eventstuff.auditbase.ContextComponents.component[1].ProxyServer}}, `
    @{Name ='UserAgentString';expression={$eventstuff.auditbase.ContextComponents.component[1].UserAgentString}}, `
    @{Name ='type' ;expression={$eventstuff.auditbase.ContextComponents.component[2].type}}, `
    @{Name ='CurrentBadPasswordCount';expression={$eventstuff.auditbase.ContextComponents.component[2].CurrentBadPasswordCount}}, `
    @{Name ='LastBadAttempt';expression={$eventstuff.auditbase.ContextComponents.component[2].LastBadAttempt}}
} | export-csv "$reportpath\event1210.csv" -notypeinformation
