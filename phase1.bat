mkdir .\phase1
echo %date% %time% > .\phase1\%COMPUTERNAME%__currenttime.txt
netstat -ano > .\phase1\%COMPUTERNAME%__netstat.csv
tasklist /m /FO csv > .\phase1\%COMPUTERNAME%__tasklist_modules.csv
tasklist /svc /FO csv > .\phase1\%COMPUTERNAME%__tasklist_service.csv
tasklist /v /FO csv > .\phase1\%COMPUTERNAME%__tasklist_verbose.csv
wmic process get ProcessID, CreationDate, ExecutablePath /FORMAT:CSV > .\phase1\%COMPUTERNAME%__imagepaths.csv
wmic nic where NetEnabled='TRUE' get DeviceID, MACAddress, Name, NetConnectionID /FORMAT:CSV > .\phase1\%COMPUTERNAME%__netadapters.csv
wmic nicconfig where IPEnabled='TRUE' get Caption, Description, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, DNSDomain, DNSHostName, DNSServerSearchOrder, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires /FORMAT:CSV > .\v2\%COMPUTERNAME%__netconfig.csv
wmic startup list full /FORMAT:CSV > .\phase1\%COMPUTERNAME%__startuplist.csv