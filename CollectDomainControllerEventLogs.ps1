#requires -version 3
#requires -RunAsAdministrator
<#PSScriptInfo

.VERSION 0.1

.GUID f47652d9-7695-4ee2-9776-f6acfda0d956

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

.TAGS AD Domain Controllers Windows

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.PRIVATEDATA 

#>
#requires -version 3
<# 

.DESCRIPTION 
 This script will collect important logs off of a domain controller, store them in a csv format and archive into a zip. 

#> 
Param()

#region functions
function ArchiveResults{
    [cmdletbinding()]
    param($source,$destination)
    Process{
        $source
        $destination
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($source, $destination) 
    }
}
function CollectDirectoryServiceEventLogs1644{
    [cmdletbinding()]
    param()
    
    write-host "1644 Events looking for poor ldap queries if enabled"
    #borrowed from https://gallery.technet.microsoft.com/scriptcenter/Event-1644-reader-Export-45205268

    $_default_log = $_default_report_path + "\" + $env:computername + "_evt_1644_from Directory_services.csv"
    Get-WinEvent -FilterHashtable @{LogName="Directory Service";ID=1644} -ErrorAction SilentlyContinue | select `
        @{Name="LDAPServer";Expression={$_.MachineName}},`
        @{Name="TimeGenerated";Expression={$_.TimeCreated}},`
        @{Name="Client";Expression={$_.Properties[4].value.split(':')[0]}},` 
        @{Name="StartingNode";Expression={$_.Properties[0].Value}},`
        @{Name="Filter";Expression={$_.Properties[1].Value}},`
        @{Name="SearchScope ";Expression={$_.Properties[5].Value}},`
        @{Name="AttributeSelection ";Expression={$_.Properties[6].Value}},`
        @{Name="ServerControls";Expression={$_.Properties[7].Value}},`
        @{Name="VisitedEntries ";Expression={$_.Properties[2].Value}},`
        @{Name="ReturnedEntries ";Expression={$_.Properties[3].Value}},`
        @{Name="UsedIndexes";Expression={$_.Properties[8].Value}},` # KB 2800945 or later has extra data fields. 
        @{Name="PagesReferenced";Expression={$_.Properties[9].Value}},` 
        @{Name="PagesReadFromDisk ";Expression={$_.Properties[10].Value}},` 
        @{Name="PagesPreReadFromDisk";Expression={$_.Properties[11].Value}},` 
        @{Name="CleanPagesModified";Expression={$_.Properties[12].Value}},` 
        @{Name="DirtyPagesModified";Expression={$_.Properties[13].Value }},`
        @{Name="SearchTimeMS";Expression={$_.Properties[14].Value}},` 
        @{Name="AttributesPreventingOptimization";Expression={$_.Properties[15].Value}} | export-csv $_default_log -NoTypeInformation
}
function CollectSecurityEventLogsNTLM{
    [cmdletbinding()]
    param()
    process{
        #https://blogs.technet.microsoft.com/ashleymcglone/2015/08/31/forensics-automating-active-directory-account-lockout-search-with-powershell-an-example-of-deep-xml-filtering-of-event-logs-across-multiple-servers-in-parallel/
        write-Host "Collect NTLM V1 from Security"
    
        $filterxml = 	'<QueryList>
                            <Query Id="0" Path="Security"><Select Path="Security">*[System[Provider[@Name="Microsoft-Windows-Security-Auditing"]
                             and (EventID=4624)]] and *[EventData[Data[@Name="LogonType"]="3"]] and *[EventData[Data[@Name="LmPackageName"] and (Data="NTLM V1")]]</Select></Query>
                        </QueryList>'

        $_default_log = $_default_report_path + "\" + $env:computername + "_evt_ntlmv1_from_security.csv"
        $events = Get-WinEvent -ea SilentlyContinue -Filterxml $filterXml 

        ForEach ($Event in $Events) {            
                    # Convert the event to XML            
                    $eventXML = [xml]$Event.ToXml()            
                    # Iterate through each one of the XML message properties            
                    For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                        # Append these as object properties            
                        Add-Member -InputObject $Event -MemberType NoteProperty -Force `
                            -Name  $eventXML.Event.EventData.Data[$i].name `
                            -Value $eventXML.Event.EventData.Data[$i].'#text'            
                    }            
                }    
        $Events | Select-Object *  -ExcludeProperty Qualifiers,Properties,Message,Bookmark,KeywordsDisplayNames,`
            MatchedQueryIds,LogonGuid,TransmittedServices,Opcode,Keywords,RecordId,ProviderId,ActivityId,RelatedActivityId  |`
                 Export-Csv $_default_log -NoTypeInformation 
    }
}
function CollectEventLogs{
    [cmdletbinding()]
    param()
    process{
    
        foreach ($eventLogName in $eventLogNames)
        {
            write-host "Collect Event logs $eventLogName"
            $_event_log_from = (Get-Date) - (New-TimeSpan -Day 60)
            $_default_log = $_default_report_path + "\" + $env:computername + "_evt_" + $($eventLogName -replace "/","_") + ".csv"
             
            Get-WinEvent -FilterHashTable @{LogName=$eventLogName; StartTime=$_event_log_from} -ErrorAction SilentlyContinue | `
                Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName,`
                @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | Export-Csv $_default_log -NoTypeInformation 
        }
    }
}

#endregion functions

$eventLogNames = "Application", "System", "Directory Service", "DFS Replication",`
    "DNS Server","Windows PowerShell",`
    "Microsoft-Windows-CAPI2/Operational","Active Directory Web Services"

write-debug "Creating folder structure"

$_root_report_path = $env:userprofile + '\Documents\Collection'
If (!($(Try { Test-Path $_root_report_path } Catch { $true }))){
    new-Item $_root_report_path -ItemType "directory"  -force
} 

$_default_report_path = $_root_report_path + '\' + "$($env:computername)-EventLogs"
If (!($(Try { Test-Path $_default_report_path } Catch { $true }))){
    new-Item $_default_report_path -ItemType "directory"  -force
}
cls
CollectDirectoryServiceEventLogs1644
CollectSecurityEventLogsNTLM
CollectEventLogs

$_archive = $_root_report_path + "\" + $env:computername + "-ARCHIVE-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
ArchiveResults -source $_default_report_path -destination $_archive

write-host "Report Can be found here $_archive"
