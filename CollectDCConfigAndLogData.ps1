
<#PSScriptInfo

.VERSION 0.1

.GUID 026c13e6-d082-49c0-839a-cdb78077e0af

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

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 This script generates a list of membership from a csv file. 

#> 
Param()

#region functions

function CollectEventLogs{
    [cmdletbinding()]
    param()
    process{
    
        foreach ($eventLogName in $eventLogNames)
        {
            write-debug "collect Event logs $eventLogName"
            $_event_log_from = (Get-Date) - (New-TimeSpan -Day 60)
            $_default_log = $_default_report_path + "\" + $env:computername + "_evt_" + $($eventLogName -replace "/","_") + ".csv"
            #Get-EventLog $eventLogName -After ((Get-Date).date).addDays(-60) | Select-Object TimeGenerated, MachineName, EventID, Source, EntryType, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | Export-Csv $_default_log -NoTypeInformation 
            Get-WinEvent -FilterHashTable @{LogName=$eventLogName; StartTime=$_event_log_from} -ErrorAction SilentlyContinue | Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | Export-Csv $_default_log -NoTypeInformation 
        }
    }
}
function CollectRegistryValues{
    [cmdletbinding()]
    param()

    write-debug "Gathering registry data"
    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_policies.txt"
    reg export HKEY_LOCAL_MACHINE\Software\Policies $_default_log
    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_schannel_protocols.txt"
    reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols $_default_log
    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_tcpip.txt"
    reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip $_default_log
    
    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_symantec.txt"
    reg export HKEY_LOCAL_MACHINE\SOFTWARE\Symantec $_default_log
    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_windows_defender.txt"
    reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions $_default_log

    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_system_currentcontrolset_services.txt"
    reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AFD /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBt /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP /s | out-file $_default_log -append

    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_Image_File_Execution_Options.txt"
    reg query 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' /s | out-file $_default_log -append

    $_default_log = $_default_report_path +  "\" + $env:computername + "_reg_run.txt"
    reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /s | out-file $_default_log
    reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /s | out-file $_default_log -append
    reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | out-file $_default_log -append
    reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | out-file $_default_log -append
}
function CopyNetlogonLog{
    [cmdletbinding()]
    param()
    $netlogonlocation = $env:SystemRoot + "\debug\netlogon.log"
    $_default_log = $_default_report_path + "\" + $env:computername + "_netlogon.log"
    copy-Item -Path $netlogonlocation -Destination $_default_log -ErrorAction SilentlyContinue
}
function CollectADReplication{
    [cmdletbinding()]
    param()
    write-debug "Gathering Replication info"
    $_default_log = $_default_report_path +  "\" + $env:computername + "_replication_failure.csv"
    $_default_log_app = $_default_report_path +  "\" + $env:computername + "_app_replication_failure.csv"

    If ($(Try{get-command -name Get-ADReplicationFailure -ErrorAction SilentlyContinue}Catch{$false})){
        Get-ADReplicationPartnerMetadata -Target * -Partition * | Select-Object Server,Partition,Partner,ConsecutiveReplicationFailures,LastReplicationSuccess,LastRepicationResult | export-csv $_default_log_app
        Get-ADReplicationFailure -target * | FT Server, FirstFailureTime, FailureClount, LastError, Partner | export-csv $_default_log -NoTypeInformation
    }else{
        repadmin /showrepl * /csv | ConvertFrom-Csv | export-csv $_default_log -NoTypeInformation
    }
}
function CollectDCDiag{
    [cmdletbinding()]
    param()
    write-debug "Gathering dcdiag results"
    $_default_log = $_default_report_path +  "\" + $env:computername + "_dcdiag_results.txt"
    dcdiag | out-file $_default_log
}
Function CollectADForestDetails{
    [cmdletbinding()]
    param()
    write-debug "get Additional info"
    $_default_log = $_default_report_path +  "\" + $env:computername + "_general_ad_info.txt"
    "--AD Optional Features--" | out-file $_default_log
    Get-ADOptionalFeature -Filter * | out-file $_default_log -Append
    "--Domain Controller--" | out-file $_default_log -append
    Get-ADDomaincontroller | out-file $_default_log -Append
    "--Domain--" | out-file $_default_log -Append
    get-addomain | out-file $_default_log -Append
    "--Forest--" | out-file $_default_log -Append
    get-adforest | out-file $_default_log -Append
    "--Other--" | out-file $_default_log -Append
    Get-ADObject -Identity “CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)” `
        -Partition $( (Get-ADRootDSE).configurationNamingContext) -Properties * | out-file $_default_log -Append
    "--ldap query policy--" | out-file $_default_log -Append
    (get-adobject -filter {objectclass -eq "queryPolicy"} -searchbase $(get-adrootdse).configurationnamingcontext -properties *).lDAPAdminLimits | `
        out-file $_default_log -Append
}
Function CollectDFSRAdmin{
    [cmdletbinding()]
    param()
    $_default_log = $_default_report_path +  "\" + $env:computername + "_dfsradmin_health"
    DfsrAdmin.exe Health New /RgName:`"Domain System Volume`" /RefMemName:$env:computername /RepName:$_default_log /FsCount:true 
}
Function CollectDNSDetails{
    [cmdletbinding()]
    param()
    write-debug "gathering DNS info"
    $_default_log = $_default_report_path +  "\" + $env:computername + "_dns_server.txt"
    "DNS Info" | out-file $_default_log

    if($(try{get-module dnsserver}catch{$false})){
        write-debug "get dns server info" 
        Get-DnsServer | out-file $_default_log
        Get-DnsServerStatistics | out-file $_default_log -append
        Get-DnsServerDirectoryPartition | out-file $_default_log -append
    }
    $_default_log = $_default_report_path +  "\" + $env:computername + "_dns_server_zone_partition.csv"
    (get-adforest).domains | foreach {get-addomaincontroller -filter * -server $_ -PipelineVariable dc | foreach {
        Get-DnsServerzone -computername $($dc.hostname) | select @{Name="DC";Expression={$dc.hostname}},`
        ZoneName,zonetype,DirectoryPartitionName | export-csv $_default_log -append -notypeinformation
    }}  

    GET-WMIobject -Computername $env:computername -Namespace "Root\MicrosoftDNS" -Class "MicrosoftDNS_server" | out-file $_default_log -append
    dnscmd $env:computername /info | out-file $_default_log -append
}
function CollectDirectoryServiceEventLogs1644{
    [cmdletbinding()]
    param()
    
    write-debug "1644 Events looking for poor ldap queries if enabled"
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
        write-debug "Collect NTLM V1 from Security"
    
        $filterxml = 	'<QueryList>
                            <Query Id="0" Path="Security"><Select Path="Security">*[System[Provider[@Name="Microsoft-Windows-Security-Auditing"] and (EventID=4624)]] and *[EventData[Data[@Name="LogonType"]="3"]] and *[EventData[Data[@Name="LmPackageName"] and (Data="NTLM V1")]]</Select></Query>
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
            MatchedQueryIds,LogonGuid,TransmittedServices,Opcode,Keywords,RecordId,ProviderId,ActivityId,RelatedActivityId  | Export-Csv $_default_log -NoTypeInformation 
    }
}
function CollectWindowsServerDetails{
    [cmdletbinding()]
    param()
    process{
        write-debug "collect patches"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_hotfix.csv"
        get-hotfix | select PSComputerName,InstalledOn,Description,HotFixID,InstalledBy | sort InstalledOn | export-csv $_default_log -NoTypeInformation

        write-debug "Collect gpresult"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_gpresult.htm"
        gpresult /h $_default_log
        $_default_log = $_default_report_path +  "\" + $env:computername + "_gpresult.txt"
        gpresult /V | out-file $_default_log

        write-debug "gather services"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_services_results.csv"
        #get-service | select name, displayname, status | export-csv $_default_log -NoTypeInformation
        Get-WmiObject win32_service | select name, displayname, description, startname, startmode, state | export-csv $_default_log -NoTypeInformation

        write-debug "gather drivers"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_windows_drivers.csv"
        Get-WindowsDriver -Online -All | export-csv $_default_log -NoTypeInformation

        write-debug "get netstat info"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_netstat.csv"
        If ($(Try{get-command -name Get-NetTCPConnection -ErrorAction SilentlyContinue}Catch{$false})){
            Get-NetTCPConnection | Group-Object -Property State, OwningProcess | Select `
                -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}} | Sort Count -Descending | export-csv $_default_log -NoTypeInformation 
        }else{
            get-netstat
        }

        write-debug "System Info"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_systeminfo.txt"
        systeminfo | out-file $_default_log

        write-debug "whoami"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_whoami.txt"
        whoami /all | out-file $_default_log


        write-debug "time data"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_time.txt"
        w32tm /query /configuration | out-file $_default_log

        write-debug "gatheering processes"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_process.csv"
        get-process -includeusername | select name,description,Id,path,ProcessName,fileversion,Handles,NPM,PM,WS,VM,CPU | export-csv $_default_log -NoTypeInformation 
        
        write-debug "gathering file versions"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_file_dll.csv"
        get-childitem C:\windows\system32 -recurse |  where {$_.extension -eq ".dll"} | `
            select Directory,name,extension, @{name='fileversion';expression={($_.versioninfo).fileversion}},`
                @{name='productversion';expression={($_.versioninfo).productversion}} | export-csv $_default_log -NoTypeInformation
        $_default_log = $_default_report_path +  "\" + $env:computername + "_file_sys.csv"
        get-childitem C:\windows\system32 -recurse |  where {$_.extension -eq ".sys"} |`
             select Directory,name,extension, @{name='fileversion';expression={($_.versioninfo).fileversion}},`
                @{name='productversion';expression={($_.versioninfo).productversion}} | export-csv $_default_log -NoTypeInformation

        write-debug "gathering filter drivers"  
        $_default_log = $_default_report_path +  "\" + $env:computername + "_filter_drivers.txt"
        Fltmc instances | out-file $_default_log
    
        write-debug "gathering Power Scheme"  
        $_default_log = $_default_report_path +  "\" + $env:computername + "_Power_Schemes.txt"
        Powercfg /list | out-file $_default_log

        write-debug "gathering Schedule Task"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_Schedule_Task.csv"
        Get-Scheduledtask | select taskpath,taskname,state,actions,execute, arguments, workingdirectory | export-csv $_default_log

        write-debug "gathering drive data"
        $_default_log = $_default_report_path +  "\" + $env:computername + "_Drive.csv"
        GET-WMIOBJECT –query “SELECT * from win32_logicaldisk” | export-csv $_default_log
        $_default_log = $_default_report_path +  "\" + $env:computername + "_disk.csv"
        Get-PhysicalDisk | export-csv $_default_log
        $_default_log = $_default_report_path +  "\" + $env:computername + "_disk_reliability_counter.csv"
        Get-PhysicalDisk | Get-StorageReliabilityCounter | export-csv $_default_log
    }
}
function CollectServerPerformance{
    write-debug "gathering performance data"
    ($_perf_counters | Get-Counter -MaxSamples 5 -ErrorAction SilentlyContinue).countersamples | `
        select-object -Property timestamp, Path, InstanceName, CookedValue | foreach{
    ##this calls to a custom function
    format-perf -countersample $_
    
}
}
function MaxNumOfTcpPorts  #helper function to retrive number of ports per address
{
param 
    (
        [parameter(Mandatory=$true)]
         $tcpParams
    )
    #  Returns the maximum number of ports per TCP address
    #  Check for Windows Vista and later
    $IsVistaOrLater = Get-WmiObject -Class Win32_OperatingSystem | %{($_.Version -match "6\.\d+")}
    if($isVistaOrLater)
    {
        # Use netsh to retrieve the number of ports and parse out the string of numbers after "Number of Ports : "
        $maxPorts = netsh int ip show dynamicport tcp |
            Select-String -Pattern "Number of Ports : (\d*)"|
            %{$_.matches[0].Groups[1].Value}
        # Convert string to integer
        $maxPorts = [int32]::Parse($maxPorts)
        #  modify the PSCustomObject to simulate the MaxUserPort value for printout
        Add-Member -InputObject $tcpParams -MemberType NoteProperty -Name MaxUserPort -Value $maxPorts 
    }
    else  # this is Windows XP or older
    {
        # check of emphermal ports modified in registry
        $maxPorts = $($tcpParams | Select-Object MaxUserPort).MaxUserPort
        if($maxPorts -eq $null)
        {
            $maxPorts = 5000 - 1kb    #Windows Default range is from 1025 to 5000 inclusive
            Add-Member -InputObject $tcpParams -MemberType NoteProperty -Name MaxUserPort -Value $maxPorts
        }
    }
    return $maxPorts
}
function New-Port  # helper function to track number of ports per IP address
{
    Param
    (
        [string] $IPAddress = [String]::EmptyString,
        [int32] $PortsWaiting = 0,
        [int32] $MaxUserPort = 3976
    )

    $newPort = New-Object PSObject

    Add-Member -InputObject $newPort -MemberType NoteProperty -Name IPAddress -Value $IPAddress
    Add-Member -InputObject $newPort -MemberType NoteProperty -Name PortsUsed -Value 1
    Add-Member -InputObject $newPort -MemberType ScriptProperty -Name PercentUsed -Value {$this.PortsUsed / $this.MaxUserPort}
    Add-Member -InputObject $newPort -MemberType NoteProperty -Name PortsWaiting -Value $portsWaiting
    Add-Member -InputObject $newPort -MemberType ScriptProperty -Name PercentWaiting -Value {$this.PortsWaiting / [Math]::Max(1,$this.PortsUsed)}
    Add-Member -InputObject $newPort -MemberType NoteProperty -Name MaxUserPort -Value $maxUserPort
    return $newPort
}
Function get-netstat{

    $_default_log = $_default_report_path +  "\" + $env:computername + "_netstat.csv"
        ######################### Beginning of the main routine ##########################

    # Store MaxUserPort for percentage used calculations
    $tcpParams = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters
    $maxPorts = MaxNumOfTcpPorts($tcpParams)   # call function to return max # ports as per OS version
    $tcpTimedWaitDelay = $($tcpParams | Select-Object TcpTimedWaitDelay).TcpTimedWaitDelay

    if($tcpTimedWaitDelay -eq $Null)           #Value wasn't configured in registry
    {
        $tcpTimedWaitDelay = 240               #Default Value if registry value doesn't exist
        Add-Member -InputObject $tcpParams -MemberType NoteProperty -Name TcpTimedWaitDelay -Value $tcpTimedWaitDelay  #fake reg value for output
    }
    # display current date and time
    #Write-Host -Object $(Get-Date)

    # Display the MaxUserPort and TcpTimedWaitDelay settings in the registry if available
    #$tcpParams | Format-List MaxUserPort,TcpTimedWaitDelay

    # collection of IP Address and port counts
    [System.Collections.HashTable] $ports = New-Object System.Collections.HashTable

    [int32] $intWait = 0

    netstat -an | 
    Select-String "TCP\s+.+\:.+\s+(.+)\:(\d+)\s+(\w+)" | 
    ForEach-Object {
        $key = $_.matches[0].Groups[1].value      # use the IP address as hash key
        $Status = $_.matches[0].Groups[3].value   # Last group contains port status
        if("TIME_WAIT" -like $Status)
        {
            $intWait = 1                          # incr count
        }
        else
        {
            $intWait = 0                          # don't incr count
        }
        if(-not $ports.ContainsKey($key))         #IP Address not yet counted
        {
            $port = New-Port -IPAddress $key -PortsWaiting $intWait -MaxUserPort $maxPorts    #intialize new tracking object
            $ports.Add($key,$port)                #Add the tracking object to hashtable
        }
        else                                      #otherwise a tracking object exists for this IP
        {
            $port = $ports[$key]                  #retrieve the tracking object
            $port.PortsUsed ++                    # increment the port count (PortsUsed)
            $port.PortsWaiting += $intWait        # increment PortsWaiting if status is TIME_WAIT
        }
    }

    $ports | Select -expand Values | Sort-Object -Property PortsUsed, PortsWaiting -Descending | select -Property IPAddress,PortsWaiting,
        @{Name='%Waiting';Expression ={"{0:P}" -f $_.PercentWaiting}},
        PortsUsed,
        @{Name='%Used';Expression ={"{0:P}" -f $_.PercentUsed}} | Export-Csv -path $_default_log

}
Function format-perf{
    [cmdletbinding()]
    param($countersample)
    $pattern = '(?<srv>\\\\[^\\]*)?\\(?<obj>[^\(^\)]*)(\((?<inst>.*(\(.*\))?)\))?\\(?<ctr>.*\s?(\(.*\))?)'
    $_default_log = $_default_report_path + "\" + $env:computername + "_perf_counter.csv"
                
    If ($Countersample.path -match $pattern)
    {         
        $oCtr = New-Object psobject
        $oCtr | add-member -membertype NoteProperty -name 'TimeStamp' -Value $Countersample.timestamp
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Computer' -Value $($matches["srv"] -replace "\\","")
        $oCtr | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $matches["inst"]
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Counter' -Value $matches["ctr"]
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Object' -Value $matches["obj"]
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Value' -Value $Countersample.cookedvalue
        if($Countersample.cookedvalue -gt 0){
            $oCtr | select-object -Property TimeStamp,Computer,object,counter,InstanceName,Value | export-csv $_default_log -append -NoTypeInformation 
        }
    }Else{
        Return $null
    }
}
function archive_results{
    [cmdletbinding()]
    param($source,$destination)
    Process{
        $source
        $destination
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($source, $destination) 
    }
}
#endregion


$_perf_counters = "\Netlogon(_Total)\*","\Security System-Wide Statistics\NTLM Authentications","\Security System-Wide Statistics\Kerberos Authentications","\DirectoryServices(*)\*","\Database(lsass)\*","\NTDS\*","\Memory\*","\PhysicalDisk(*)\*","\Process(*)\*","\Processor(*)\*","\TCPv4\*","\DNS\*"
$eventLogNames = "Application", "System", "Directory Service", "DFS Replication", "DNS Server","Windows PowerShell","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-CAPI2/Operational","Active Directory Web Services"

write-debug "Creating folder structure"

$_root_report_path = $env:userprofile + '\Documents\Collection'
If (!($(Try { Test-Path $_root_report_path } Catch { $true }))){
    new-Item $_root_report_path -ItemType "directory"  -force
} 

$_default_report_path = $_root_report_path + '\' + $env:computername
If (!($(Try { Test-Path $_default_report_path } Catch { $true }))){
    new-Item $_default_report_path -ItemType "directory"  -force
}

$DebugPreference = "Continue"

if($(try{(Get-WindowsFeature -Name AD-Domain-Services).installed -eq $true}catch{$false})){
    write-debug "Directory Services Found"
    CollectEventLogs
    CollectRegistryValues
    CopyNetlogonLog
    CollectADReplication
    CollectDCDiag
    CollectADForestDetails
    CollectDFSRAdmin
    CollectDNSDetails
    CollectDirectoryServiceEventLogs1644
    CollectSecurityEventLogsNTLM
    CollectWindowsServerDetails
    CollectServerPerformance

    $_archive = $_root_report_path + "\" + $env:computername + "-ARCHIVE-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
    archive_results -source $_default_report_path -destination $_archive

    write-host "Report Can be found here $_archive"
}
