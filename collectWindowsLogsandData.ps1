<#PSScriptInfo

.VERSION 0.1

.GUID 026c13f7-d082-49c0-839a-cdb78077e0af

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


.DESCRIPTION 
 This collects data about a desktop. 

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
            $_event_log_from = (Get-Date) - (New-TimeSpan -Day 120)
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
function CopyCBSLog{
    [cmdletbinding()]
    param()
    $cbslocation = $env:SystemRoot + "\logs\CBS\CBS.log"
    $_default_log = $_default_report_path + "\" + $env:computername + "_cbs.log"
    copy-Item -Path $cbslocation -Destination $_default_log -ErrorAction SilentlyContinue
}

function CollectWindowsDetails{
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
        $_default_log = $_default_report_path +  "\" + $env:computername + "_Secure_Channel.csv"
        Test-ComputerSecureChannel -verbose | Add-Content $_default_log
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
Function collectCheflogs{
    $defaultFile = "$reportpath\$($env:computername)_chef-client.log"
    Get-ChildItem -Path c:\ -Filter chef-client.log -Recurse -ErrorAction SilentlyContinue -Force | Copy-Item -Destination  -ErrorAction SilentlyContinue
}
function collect-retoredata{
    $_default_log = $_default_report_path +  "\" + $env:computername + "_regidlebackup_schedule_task.csv"
    Get-ScheduledTask -TaskName RegIdleBackup | Get-ScheduledTaskInfo | export-csv $_default_log -NoTypeInformation
     $_default_log = $_default_report_path +  "\" + $env:computername + "_check_point_schedule.csv"
   Get-ComputerRestorePoint | export-csv $_default_log -NoTypeInformation
}
#endregion


$_perf_counters = "\Memory\*","\PhysicalDisk(*)\*","\Process(*)\*","\Processor(*)\*","\TCPv4\*"
$eventLogNames = "Application", "System", "Microsoft-Windows-CAPI2/Operational","Microsoft-Windows-NlaSvc/Operational"

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



CopyNetlogonLog
CopyCBSLog
CollectWindowsDetails
CollectServerPerformance
CollectEventLogs
collect-retoredata
CollectRegistryValues

$_archive = $_root_report_path + "\" + $env:computername + "-ARCHIVE-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
archive_results -source $_default_report_path -destination $_archive

write-host "Report Can be found here $_archive"
