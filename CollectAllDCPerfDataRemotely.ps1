
<#PSScriptInfo

.VERSION 0.1

.GUID 31ab0e7c-ffd3-48e1-87fb-91a2427ffb6f

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

.TAGS AD GPO Unused gplink GroupPolicy

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
    0.1 First go around of the script

.PRIVATEDATA 

#>

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 Collects Perf Counter Values from domain controllers 

#> 
Param($reportpath = "$env:userprofile\Documents")

$default_log = "$reportpath\alldcperfdata.csv"
$MaxThreads = 10
$SleepTimer = 1000

#Perf Counters
$counter_list = '\database(lsass)\Version buckets allocated',`
'\database(lsass)\Database Cache Misses/sec',`
'\database(lsass)\Database Cache % Hit',`
'\database(lsass)\Database Cache Size (MB)',`
'\database(lsass)\Sessions In Use',`
'\DirectoryServices(*)\ATQ Outstanding Queued Requests',`
'\DirectoryServices(*)\ATQ Threads LDAP',`
'\DirectoryServices(*)\ATQ Threads Other',`
'\DirectoryServices(*)\ATQ Threads Total',`
'\DirectoryServices(*)\DS Threads in Use',`
'\DirectoryServices(*)\LDAP Client Sessions',`
'\DirectoryServices(*)\LDAP Searches/sec',`
'\directoryServices(*)\NTLM Binds/sec',`
'\directoryServices(*)\Negotiated Binds/sec',`
'\directoryServices(*)\Digest Binds/sec',`
'\directoryServices(*)\Simple Binds/sec',`
'\directoryServices(*)\External Binds/sec',`
'\directoryServices(*)\Fast Binds/sec',`
'\directoryServices(*)\DRA Pending Replication Operations',`
'\Memory\Available MBytes',`
'\Memory\Pages/sec',`
'\Memory\Pool Nonpaged Bytes',`
'\Memory\Pool Paged Bytes',`
'\Netlogon(_Total)\*',`
'\PhysicalDisk(*)\Current Disk Queue Length',`
'\PhysicalDisk(*)\Avg. Disk sec/Read',`
'\PhysicalDisk(*)\Avg. Disk sec/Write',`
'\PhysicalDisk(*)\Disk Transfers/sec',`
'\Processor(_Total)\% Processor Time',`
'\Processor(_Total)\% User Time',`
'\Processor(_Total)\% Privileged Time',`
'\Security System-Wide Statistics\Kerberos Authentications',`
'\Security System-Wide Statistics\NTLM Authentications',`
'\TCPv4\Connection Failures',`
'\TCPv4\Connections Established',`
'\Network Interface(*)\Bytes Total/sec',`
'\Server\Server Sessions',`
'\Event Tracing for Windows Session(Eventlog-Security)\Events Logged per sec',`
'\Process(lsass)\% Processor Time',`
'\DNS\Total Query Received/sec',`
'\DNS\Total Response Sent/sec'


#get all domain controllers
$domain_controllers = ((get-adforest).domains | foreach{Get-ADDomainController -filter * -server $_}).hostname

#logic

$domain_controllers | foreach{
    While (@(Get-Job -state running).count -ge $MaxThreads){      
        Start-Sleep -Milliseconds $SleepTimer
    }
        
    Start-Job -scriptblock {
        $arrCounters = $args[1]
        $machine = $args[0]
        $results_log = $args[2]
        
        #function
        Function CounterPathToObject{
            $pattern = '(?<srv>\\\\[^\\]*)?\\(?<obj>[^\(^\)]*)(\((?<inst>.*(\(.*\))?)\))?\\(?<ctr>.*\s?(\(.*\))?)'
            If ($countResults.path -match $pattern){
                $strCounter = "\" + $matches["obj"] + "\" + $matches["ctr"]
                $oCtr = New-Object psobject
                $oCtr | add-member -membertype NoteProperty -name 'TimeStamp' -Value $countResults.timestamp
                $oCtr | Add-Member -MemberType NoteProperty -Name 'Computer' -Value ($matches["srv"] -replace "\\","")
                $oCtr | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $matches["inst"]
                $oCtr | Add-Member -MemberType NoteProperty -Name 'Counter' -Value $strCounter
                $oCtr | Add-Member -MemberType NoteProperty -Name 'Value' -Value $countResults.cookedvalue

                if($countResults.cookedvalue -gt 0){
                    $oCtr | select TimeStamp,Computer,Counter,InstanceName,Value | export-csv $results_log -Append -NoTypeInformation
                }
            }Else{Return $null}
        } 
        #main part of the script
        #check to see if the computer is online first
        if(Test-Connection -ComputerName $machine -count 1 -Quiet){
            try{
                foreach($countResults in ($arrCounters | Get-Counter -ComputerName $machine).countersamples |`
                    select-object -Property timestamp, Path, InstanceName, CookedValue){
                    CounterPathToObject 
                 }
            }catch{}
        }
    } -ArgumentList $_,$counter_list,$default_log -Name "$($_)job" | Out-Null
}

While (@(Get-Job -State Running).count -gt 0){
    Start-Sleep -Milliseconds $SleepTimer
}

get-job | Remove-Job -Force
