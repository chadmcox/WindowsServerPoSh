#Requires -version 4.0
#Requires –Modules nettcpip

<#-----------------------------------------------------------------------------
Example code for

Chad Cox, Microsoft Premier Field Engineer
https://blogs.technet.microsoft.com/chadcox/

LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
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
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
-----------------------------------------------------------------------------#>

function grab-portdata{
    #https://gallery.technet.microsoft.com/scriptcenter/DetectMonitor-TCP-Port-0ac9dff1
    #region ::Format the log file 
 
    If (Test-Path C:\Temp) {} Else { New-Item C:\Temp -ItemType Directory } 
        Get-ChildItem "C:\Temp\$($env:COMPUTERNAME)_PortExhaustion*.txt" | Sort-Object CreationTime -Descending | Select -Skip 32 | Remove-Item -Force 
        $Date = Get-Date -Format g 
        $DateLog = Get-Date -Format MMddyyyy\THHmmss 
        $LogName = "$($env:COMPUTERNAME)_PortExhaustion_$DateLog.txt" 
    "============================================================================================================================" | Out-File C:\Temp\$LogName 
    "                                             PORT EXHAUSTION TOOL ($Date)                                                   " | Out-File C:\Temp\$LogName -Append 
    "============================================================================================================================" | Out-File C:\Temp\$LogName -Append 
    #endregion 
    #region ::Retrieve all the TCP Connections (equivalent to netstat, sorted by LocalPort) 
    "----------------------------------------------------------------------------------------------------------------------------" | Out-File C:\Temp\$LogName -Append 
    "                                                    TCP CONNECTIONS                                                         " | Out-File C:\Temp\$LogName -Append 
    Get-NetTCPConnection | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{l="ProcessID";e={$_.Owningprocess}}, @{l="ProcessName";e={(get-process -ID $_.Owningprocess).processname}} | Sort LocalPort, ProcessID | ft -AutoSize | Out-File C:\Temp\$LogName -Append 
    #endregion 
 
 
    #region ::Count TCP Connections per Process Name 
    "----------------------------------------------------------------------------------------------------------------------------" | Out-File C:\Temp\$LogName -Append 
    "                                               TCP CONNECTIONS/PROCESS NAME                                                 " | Out-File C:\Temp\$LogName -Append 
    Get-NetTCPConnection | Select @{l="ProcessName";e={(get-process -ID $_.Owningprocess).processname}} | Group-Object ProcessName -NoElement | sort -descending Count | ft -AutoSize | Out-File C:\Temp\$LogName -Append 
    #endregion 
 
 
    #region ::Retrieve all the TCP connections for the top 5 Processes 
    "----------------------------------------------------------------------------------------------------------------------------" | Out-File C:\Temp\$LogName -Append 
    "                                              TCP CONNECTIONS/TOP 5 PROCESSES                                               " | Out-File C:\Temp\$LogName -Append 
    $top5process = Get-NetTCPConnection | Select @{l="ProcessName";e={(get-process -ID $_.Owningprocess).processname}} | Group-Object ProcessName -NoElement | sort -descending Count | select -first 5 
    Get-NetTCPConnection | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{l="ProcessID";e={$_.Owningprocess}}, @{l="ProcessName";e={(get-process -ID $_.Owningprocess).processname}} | ? {$_.Processname -in (($top5process).name)} | sort ProcessName | ft -GroupBy ProcessName -AutoSize  | Out-File C:\Temp\$LogName -Append 
    #endregion 

    #region ::Retrieve Perf Data 
    "----------------------------------------------------------------------------------------------------------------------------" | Out-File C:\Temp\$LogName -Append 
    "                                              Perf Counters                                              " | Out-File C:\Temp\$LogName -Append 
    $counters = @("\Processor(_total)\% Processor Time","\Memory\Available MBytes","\AD FS\*","\LogicalDisk(*)\*","Netlogon(*)\*","\TCPv4\*","\VM Processor(*)\*","\VM Memory(*)\*")
    ($counters | get-counter -ErrorAction SilentlyContinue).countersamples | where cookedvalue -ne 0 | select `
        @{n='Object';e={($_.path.split("\"))[3]}}, @{n='Counter';e={($_.path.split("\"))[4]}}, InstanceName, cookedvalue  | `
            ft Counter,InstanceName,CookedValue -GroupBy Object | Out-File C:\Temp\$LogName -Append

}


#Create the Event Provider
if(!(Get-EventLog –LogName Application –Source "TCPPorts")){
    new-eventlog –LogName Application –Source "TCPPorts"
}

$bound_count_error = 2000
$tcp_connections = Get-NetTCPConnection | Group-Object -Property State | Sort Count | select count, name  
if($tcp_connections | where {$_.count -gt $bound_count_error}){
    write-EventLog –LogName Application –Source "TCPPorts" –EntryType Warning –EventID 1 –Message "$($tcp_connections | out-string)"
    grab-portdata
}
else{
    write-EventLog –LogName Application –Source "TCPPorts" –EntryType Information –EventID 1 –Message "$($tcp_connections | out-string)"
}
