del .\netstat\*.csv
del .\tasklist\*.csv
del .\wmic\*.csv
netstat -ano > .\netstat\%COMPUTERNAME%_netstat.csv
tasklist /m /FO csv > .\tasklist\%COMPUTERNAME%_tasklist_modules.csv
tasklist /svc /FO csv > .\tasklist\%COMPUTERNAME%_tasklist_service.csv
tasklist /v /FO csv > .\tasklist\%COMPUTERNAME%_tasklist_verbose.csv
wmic process get ProcessID,ExecutablePath /FORMAT:CSV > .\wmic\%COMPUTERNAME%_imagepaths.csv
