#if you need a list of pc's that run just windows 10 or 11 you can use the following
write-host  "generating list of windows 10 and 11 PC's..." -ForegroundColor Green
Get-ADComputer -Filter { OperatingSystem -like 'Windows 10*' -or OperatingSystem -like 'Windows 11*'} -Properties OperatingSystem | Select-Object Name | Export-Csv -path C:\scripts\PClist.csv
write-host  "list generated and saved here C:\scripts\PClist.csv..." -ForegroundColor Green
#populate complist with a  list of computers outreport is where it will save the csv file
#$complist = "C:\scripts\list.txt"
$complist = Import-Csv -Path "C:\scripts\PClist.csv"
$outreport = "C:\temp\workstation_Inventory_" + $((Get-Date).ToString('MM-dd-yyyy')) + ".csv"

#ignores errors since it's usually an offline computer or a computer that doesn't have winrm turned on
$ErrorActionPreference= 'silentlycontinue'


write-host  "enabling winRM on listed computers..." -ForegroundColor Yellow

ForEach ($comp in $complist.Name ) {
	write-host $cred
    Start-Process -Filepath "C:\Scripts\Pstools\psexec.exe" -Argumentlist "\\$comp -h -d winrm.cmd quickconfig -q" 
    Start-Process -Filepath "C:\Scripts\Pstools\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe enable-psremoting -force" 
    Start-Process -Filepath "C:\Scripts\Pstools\psexec.exe" -Argumentlist "\\$comp -h -d powershell.exe set-executionpolicy RemoteSigned -force"
	$test = Test-Wsman -ComputerName $comp
	if ($test -ne $null){
		write-host $comp " winRM enabled..." -ForegroundColor Green
	}
	else{
		write-host $comp " either wasn't on or something else went wrong..." -ForegroundColor Red
	}
}

write-host  "inventory scan has started this can take some time..." -ForegroundColor Yellow

#start psremote
Invoke-Command -ComputerName ($complist.Name) -scriptblock {
#cpu
$CPUInfo = Get-WmiObject Win32_Processor
#os
$OSInfo = Get-WmiObject Win32_OperatingSystem
#memory
$PhysicalMemory = Get-WmiObject CIM_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[math]::round(($_.sum / 1GB),2)}
#storage
$StorageMedia = Get-PhysicalDisk | Select-Object MediaType
#ip
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"'
#localadmins
$localadmins = Get-CimInstance -ClassName win32_group -Filter "name = 'administrators'" | Get-CimAssociatedInstance -Association win32_groupuser
#open Shares
$Shares = Get-WmiObject Win32_share | Where {$_.name -NotLike "*$"}

#object to add data too
$infoObject = New-Object PSObject

#add data to the infoObjects
Add-Member -inputObject $infoObject -memberType NoteProperty -name "ServerName" -value $CPUInfo.SystemName
Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_Name" -value $CPUInfo.Name
Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalMemory_GB" -value $PhysicalMemory
Add-Member -inputObject $infoObject -memberType NoteProperty -name "Storage" -value $StorageMedia
Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Name" -value $OSInfo.Caption
Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Version" -value $OSInfo.Version
Add-Member -inputObject $infoObject -memberType NoteProperty -name "IP Address" -value $Network.IPAddress
Add-Member -inputObject $infoObject -memberType NoteProperty -name "LocalAdmins" -value $localadmins.Caption
Add-Member -inputObject $infoObject -memberType NoteProperty -name "SharesName" -value $Shares.Name
Add-Member -inputObject $infoObject -memberType NoteProperty -name "SharesPath" -value $Shares.Path

$infoObject
} | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | Export-Csv -path $outreport -NoTypeInformation

write-host  "finished, the inventory scan is saved here C:\temp\..." -ForegroundColor Green
cmd /c pause
