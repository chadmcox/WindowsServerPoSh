#Requires -modules ActiveDirectory

<#
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
there is a problem where ADWS uses high resources when cache file is out dated.
Used this script top determine cache file date that ADWS uses.  if older than previous 
schema change should consider renaming the file and allowing new file to be created.
#>
param($reportpath = "$env:userprofile\Documents")

$results = @()
foreach($domain in (get-adforest).domains){
    write-host "Looking at DC's in $domain"
    get-addomaincontroller -filter * -server $domain -PipelineVariable DC | foreach{
        write-host "Collecting File info for $($DC.hostname)"
        $results += invoke-command -ComputerName $DC.hostname `
            -ScriptBlock {Get-ChildItem -path 'c:\windows\system32\%localappdata%\microsoft\windows\schcache' | select name, lastwritetime} | select  `
                PSComputerName,Name,LastWriteTime
    }
}

$results | export-csv "$reportpath\dcschemadate.csv" -NoTypeInformation
$results | Out-GridView
