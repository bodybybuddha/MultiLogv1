# Versions #

## v1.05 ##
-  Fixed issue with circular logging returning visual cues to the console


## v1.04 ##
- Added Log Level feature.  LogObject now has a new member: LogLevel.  This is an integer that is set to 0 by default.
- Log-Write event has a new option -LogLevel parameter.  If the -LogLevel is less than or equal to the LogObject.LogLevel, the message will be written.

## v1.03 ##
- Change all Write-Output to Write-host - makes tool a little bit more useful in certain situations where the output is meant to return data.


## v1.02 ##
 - Fixed a typo that caused an issue with creating LOGFILE type logs

## v1.01 ##

 - Added default settings for Circular logging. Parameters to change the default added when Initialize-log is executed.
 - Added default settings the size of the event log.  Parameters to change the default added when Initialize-log is executed. 
 - Cleaned up Exported functions to only show the needed functions

## v1  ##

- Initial Commit
- Code from other sources:
	- **PSLogging** from Luca Sturlese @ [http://9to5IT.com](http://9to5IT.com) & [https://github.com/9to5IT/PSLogging](https://github.com/9to5IT/PSLogging)
	- **PSLogging (Write-LogEntry)** from Wojciech Sciesinski @ [https://github.com/it-praktyk/PSLogging](https://github.com/it-praktyk/PSLogging)
	- **PSLog (Reset-Log)** from Thom Schumacher @ [https://github.com/crshnbrn66/PSLog/blob/master/PSLog.psm1](https://github.com/crshnbrn66/PSLog/blob/master/PSLog.psm1)
