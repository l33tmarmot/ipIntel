del .\v2\TAU-ZERO*.csv
del .\netdata\TAU-ZERO*.csv
del .\v2\TAU-ZERO*.txt
mkdir .\netdata
mkdir .\v2
echo %date% %time% > .\v2\%COMPUTERNAME%__currenttime.txt
netstat -ano > .\v2\%COMPUTERNAME%__netstat.csv
tasklist /m /FO csv > .\v2\%COMPUTERNAME%__tasklist_modules.csv
tasklist /svc /FO csv > .\v2\%COMPUTERNAME%__tasklist_service.csv
tasklist /v /FO csv > .\v2\%COMPUTERNAME%__tasklist_verbose.csv
wmic process get ProcessID, CreationDate, ExecutablePath /FORMAT:CSV > .\v2\%COMPUTERNAME%__imagepaths.csv
wmic nic where NetEnabled='TRUE' get DeviceID, MACAddress, Name, NetConnectionID /FORMAT:CSV > .\v2\%COMPUTERNAME%__netadapters.csv
wmic nicconfig where IPEnabled='TRUE' get Caption, Description, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, DNSDomain, DNSHostName, DNSServerSearchOrder, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires /FORMAT:CSV > .\v2\%COMPUTERNAME%__netconfig.csv
wmic startup list full /FORMAT:CSV > .\v2\%COMPUTERNAME%__startuplist.csv