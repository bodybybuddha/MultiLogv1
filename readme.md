# Multilogv1 #

Library to allow PowerShell scripts to write a log to an ASCII log file, a set of circular ASCII log files, or to the Event Log, or all three!

## Features: ##

- **ASCII File**: Create a log file to an ASCII file.  This is meant for scripts that do not execute on scheduled basis.
- **Circular Log File**: Create a series of ASCII log files with a set number in the series and size per file.  This will allow you to keep a limited number of logs on disk and the script will clean up after itself. 
- **Windows Event Logging**: The module will allow you to write to the Windows Event log as well.  It will create a new Event Log (default 'Multilogv1') and a new source with a custom name.  
- **Log Levels** The module will allow you set a certain log level for a particular log.  In conjunction with a -LogLevel parameter in the Write event, will give developers the ability to set different levels of logging.


## Design Overview / How to use ##
This module can be imported at the script, user, or machine level.  I purposely left the version in the name of the module itself.  Having written applications on an enterprise level, I know that once a fundamental tool like this module is changed, it could cause many hours of re-coding. I plan on only making changes to the code that will be backwards compatible all the way back to 1.0.  I'll create a whole new repo for v2 if there is a change that isn't backward compatible.

The module will force you to create a PowerShell custom object in memory that you'll use to pass to all exposed functions.  This Log object contains basic information that will be needed for all the functions.  For instance, if you opt for a ASCII file log, the object will contain a property for the location of the ASCII file.

There are only a few expose functions:

- **Initialize-Log** : This will return back the Log object. This routine must be executed before any of the others.  It'll also initialize any settings needed for the module.
- **Start-Log**: This will not really necessary, however, for the ASCII log files, it'll inject a nice header into the log.  Should be used at the beginning of the script of course.
- **Write-LogEntry**:  This is the main work horse of the module.  You'll only have to submit the same properties to this function regardless of the type of logging you're doing.
- **Stop-Log**:  Similar to Start-Log, just use it at the end...
- **Send-Log**:  If you have an ASCII log file and you'd like to send it. A very straight forward SMTP function.

Included in the repo is a testingthemodule.ps1 file.  This gives you an idea of how to use the module.  Until I come up with more documentation that is.

## Acknowledgments ##
This tool would not have been possible without the following people that were generous to share their code with the world (GitHub FTW!):

- **PSLogging** from Luca Sturlese @ [http://9to5IT.com](http://9to5IT.com) & [https://github.com/9to5IT/PSLogging](https://github.com/9to5IT/PSLogging)
- **PSLogging (Write-LogEntry)** from Wojciech Sciesinski @ [https://github.com/it-praktyk/PSLogging](https://github.com/it-praktyk/PSLogging)
- **PSLog (Reset-Log)** from Thom Schumacher @ [https://github.com/crshnbrn66/PSLog/blob/master/PSLog.psm1](https://github.com/crshnbrn66/PSLog/blob/master/PSLog.psm1)

I started with Luca's excellent PSLogging as a base.  I saw that Wojciech had made an excellent change that saved a lot of coding.  Lastly, I had a routine that would perform the renames of log files for the circular log feature.  However, I stumbled upon a comment Thom had made on the internet someplace (I forget where) and he pointed to his Github repo.  His Reset-Log routine was MUCH better and cleaner than mine.  

Thank you Luca, Wojciech, and Thom for sharing your coding efforts!

## Future Features ##
Because of the way the code is structured, I can add other output types if needed.  For instance, I can output all of the code to a syslog server, or maybe to an SQL database.  The great thing about adding the additional functionality, if you're sharing the module's code base across multiple scripts, you shouldn't have to change any of those scripts!  Or you can change them to use the new features by changing the call to Initialize-Log!
