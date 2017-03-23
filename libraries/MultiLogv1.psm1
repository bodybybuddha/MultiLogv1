#MultiLogv1
# For help: https://github.com/bodybybuddha/MultiLogv1/wiki

#Based on:
#  PSLogging from Luca Sturlese @ URL: http://9to5IT.com & https://github.com/9to5IT/PSLogging
#  PSLogging (Write-LogEntry) from Wojciech Sciesinski @ URL: https://github.com/it-praktyk/PSLogging
#  PSLog (Reset-Log) from Thom Schumacher @ URL: https://github.com/crshnbrn66/PSLog/blob/master/PSLog.psm1
#  Logging_Functions from John Taylor

Set-StrictMode -Version Latest

#Internal variables for the module 
[int32]$DefaultNumOfArchives = 10
[int64]$DefaultSizeOfArchives = 1mb
[int32]$DefaultEventLogRetention = 30
[int64]$DefaultEventLogSize = 20mb

$Version = '1.05'
$ModuleName = 'MultiLogv1'

Function Initialize-Log{
<#
    .SYNOPSIS
    This function will return back a PS Custom Object that will be used with all of the functions in the MultiLogv1 module.  It will also prepare/Initialize any needed items for the script work.  For instance, if you opt for event log logging, this function will ensure that an event log exists to write to.
    .DESCRIPTION
    This function will return back a PS Custom Object that will be used with all of the functions in the MultiLogv1 module.  It will also prepare/Initialize any needed items for the script work.  For instance, if you opt for event log logging, this function will ensure that an event log exists to write to. 
    .PARAMETER ExecutingScriptName
    Mandatory. Name of the script executing this function.     
    .PARAMETER LogType
    Mandatory. Can be one of the following:  'LOGFILE','EVENT','CIRCULAR'   
    .PARAMETER LogFileName
    Mandatory. The path and file name of the log file desired.  This is used for both Log Types LOGFILE and CIRCULAR.
    .PARAMETER ArchiveSize
    Optional. If the Logtype is CIRCULAR, this parameter will allow you to specify a different size for the log file sizes.  The default is 1mb.  This is a [int64] variable type.  However, PowerShell is so smart you can use shortcuts, i.e. 1mb, 2gb, 50kb, etc.
    .PARAMETER ArchiveNumber
    Optional. If the log type is CIRCULAR, this parameter will allow you to specify a different number of log files to be kept.  The default is 10.
    .PARAMETER EventLogName
    Optional.  If the log type is EVENT, this parameter will allow you to specify the Event log to be written to.  By default, the script will use 'MultiLogv1'.  The first time this is executed, and either the default EventLogName is used or a different, non-existing event log name is given, it will be created.  You can use the existing Event Log names if you like as well (Application, etc).  Note:  You must be an administrator on the machine you are attempting to create an Event log on.
    .PARAMETER EventLogRetention
    Optional. When a new event log is created on a machine, this script will default to creating one that will retain 30 days worth of entries (given we don't go over the set size of the event log -- See EventLogSize parameter.)  This parameter will allow you to customize the number of days the events will be kept before overwritten.
    .PARAMETER EventLogSize
    Optional.  When a new event log is created on a machine, this script will default to creating one that is 20mb.  This parameter will allow you to override the defaults.  This is an [int64] field.  However, PowerShell is so smart you can use shortcuts, i.e. 1mb, 2gb, 50kb, etc. Note: The number specified must be in increments of 64kb.  Otherwise, the script will generate an error.
    .INPUTS
    Parameters above
    .OUTPUTS
    PS Custom Object to represent the LogObject
    .NOTES
    See VERSIONS.md in the github repo for historical version information.
    .LINK
    https://github.com/bodybybuddha/MultiLogv1/wiki
    
    .EXAMPLE
    $LogObj = Initialize-Log -ExecutingScriptName 'My.Script' -LogType 'LOGFILE' -LogFileName 'c:\temp\logs\log.log'
    Creates a new log file at 'c:\temp\logs\log.log'

    .EXAMPLE
    $LogObj = Initialize-Log -ExecutingScriptName 'My.Script' -LogType 'CIRCULAR' -LogFileName 'c:\temp\logs\log.log' -ArchiveSize 5mb -ArchiveNumber 30 
    Creates a new log file at 'c:\temp\logs\log.log' on the initial run. When filling in the log file, the system will monitor the size of the file.  Once the file goes over 5mb, it will rename the log.log file to log.log.1, and create a new log.log file.  If there is already another log.log.1 file, that file will renamed to log.log.2.  This will be repeated until the Archive Number of 30 is reached.  In which case the last one will be removed.

    .EXAMPLE
    $LogObj = Initialize-Log -ExecutingScriptName 'My.Script' -LogType 'EVENT' 
    Creates a new event log called 'MultiLogv1'.  It will register a new Event log source of the ExecutingScriptName.  The new event log will have the default settings of only retaining 30 days or 20mb of information.        
  #>
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$True)]
    [string]$ExecutingScriptName,
    [Parameter(Mandatory=$True)]
    [ValidateSet('LOGFILE','EVENT','CIRCULAR')]
    [string]$LogType,
    [Parameter(Mandatory=$True,ParameterSetName="LOGFILECIRCULAR")]
    [string]$LogFileName,	
    [Parameter(Mandatory=$False,ParameterSetName="LOGFILECIRCULAR")]
    [string]$ArchiveSize = $DefaultSizeOfArchives,	
    [Parameter(Mandatory=$False,ParameterSetName="LOGFILECIRCULAR")]	
    [string]$ArchiveNumber= $DefaultNumOfArchives,
    [Parameter(Mandatory=$False,ParameterSetName="EVENT")]	
    [string]$EventLogName = $ModuleName,
    [Parameter(Mandatory=$False,ParameterSetName="EVENT")]	
    [string]$EventLogRetention = $DefaultEventLogRetention,
    [Parameter(Mandatory=$False,ParameterSetName="EVENT")]	
    [string]$EventLogSize = $DefaultEventLogSize
    )
	
	#####################################################################################
	#  Need to test for parameters & some Initializing variables
	#####################################################################################
	if($LogType -eq "LOGFILE") {
		
	}
    if($LogType -eq "EVENT") {

	}
    if($LogType -eq "CIRCULAR") {
	
	}
    
	
		
	#####################################################################################
	#  Add properties to the $PSLoggingEnv object based on log type
	#####################################################################################	
	$PSLoggingEnv = [PSCustomObject] @{
		LogModuleName = $ModuleName
		LogModuleVersion = $Version
		LogType = $LogType
		IncludeDateTime = $True
		OutScreen = $True
		LogLevel = 0 
	} # main custom object to be passed back to calling script

	#  The NoteProperty ones could've been done in initial declartion, this is just an example	
	$PSLoggingEnv | Add-member -MemberType NoteProperty -name ScriptName -value $ExecutingScriptName
	
	if ($PSLoggingEnv.LogType -eq "LOGFILE") {
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name LogFileName -value $LogFileName  	
	}
	
    if ($PSLoggingEnv.LogType -eq "EVENT") {
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name EventModuleName -value $EventLogName 
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name EventRetention -value $EventLogRetention 
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name EventLogSize -value $EventLogSize 
	}
	
    if ($PSLoggingEnv.LogType -eq "CIRCULAR") {
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name LogFileName -value $LogFileName  
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name ArchiveNumber -value $ArchiveNumber 
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name ArchiveSize -value $ArchiveSize 
	}
    
	
	
	#####################################################################################
	#Initialize anything we need to do before we start using the Logging fuctions
	#####################################################################################
	if($PSLoggingEnv.LogType -eq "LOGFILE"){
		 
		#Check if file exists and delete if it does
		If ( (Test-Path -Path $PSLoggingEnv.LogFileName) ) {
		  Remove-Item -Path $PSLoggingEnv.LogFileName -Force
		}

		#Create file and start logging
		New-Item -Path $PSLoggingEnv.LogFileName -ItemType File  | out-null
	} 

	If($PSLoggingEnv.LogType -eq "EVENT"){
		
		#Check for the existence of the Event Log - If it's not there create it.
		#$ExistingActionPreference = $ErrorActionPreference
		#$ErrorActionPreference = "SilentlyContinue"
		
		$logFileExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $PSLoggingEnv.EventModuleName} 
		if (! $logFileExists) {
			try {
				New-Eventlog -LogName $PSLoggingEnv.EventModuleName -Source $PSLoggingEnv.ScriptName -erroraction stop | Out-Null
				Limit-Eventlog -Logname $PSLoggingEnv.EventModuleName -OverflowAction OverwriteOlder -RetentionDays $PSLoggingEnv.EventRetention -MaximumSize $PSLoggingEnv.EventLogSize
			}
			catch [System.Security.SecurityException] {
				Write-Error "Error:  Run as elevated user.  Unable to write or read to event logs."
			}
		} else {
		
		# Log does exist - see if the source is already registered
			if(!(Test-Sourcename -SourceName $PSLoggingEnv.ScriptName) ){
				try {
					New-Eventlog -LogName $PSLoggingEnv.EventModuleName -Source $PSLoggingEnv.ScriptName -erroraction stop | Out-Null					
				}
				catch [System.Security.SecurityException] {
					Write-Error "Error:  Run as elevated user.  Unable to write or read to event logs."
				}
			
			}
		
		
		}
		
		#	$ErrorActionPreference = $ExistingActionPreference
	} 
	
	If($PSLoggingEnv.LogType -eq "CIRCULAR") {
		
	}

	return $PSLoggingEnv

}  # End Function Initialize-Log

function Test-Sourcename {
    Param(
        [Parameter(Mandatory=$True)]
        [string] $SourceName
    )

    [System.Diagnostics.EventLog]::SourceExists($SourceName)
} # End of fucntion Test-Sourcename

Function CheckLogObject{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True,Position=0)]
		$LogObject 
		)
	if(-not $LogObject){return $False}
	
	try{if($LogObject.LogModuleName -eq $ModuleName){return $True} else {return $False}} catch {return $False}
	
	return $False
} # End Function CheckLogObject

Function Start-Log{
<#
    .SYNOPSIS
    Optional command - Adds a starting header for the log.  If you are using a file, it'll have a clear header section.  If you are using an event log, it'll be very simple.
    .DESCRIPTION
    Optional command - Adds a starting header for the log.  If you are using a file, it'll have a clear header section.  If you are using an event log, it'll be very simple.
    .PARAMETER LogObject
    Mandatory. PS Custom object created from the Initialize-Log cmdlet.      
    .PARAMETER ByPassScreen
    Optional. When parameter specified will bypass displaying the content to screen.  Default behavior of displaying messages on the screen can controlled by changing the OutScreen property of the LogObject passed into this function.  Note: debug mode may double up any screen displays.    
    .INPUTS
    Parameters above
    .OUTPUTS
    None or String
    .NOTES
    See VERSIONS.md in the github repo for historical version information.
    .LINK
    https://github.com/bodybybuddha/MultiLogv1/wiki
    
    .EXAMPLE
    Start-Log -LogObject $LogObj 
    Writes a Start log header to the log.
    
    .EXAMPLE
    Start-Log -LogObject $LogObj -ByPassScreen
    Writes a Start log header to the log - but doesn't write anything to the screen.    
#>
	[CmdletBinding()]
	Param (
    [Parameter(Mandatory=$True)]
    $LogObject,
    [Parameter(Mandatory=$False)]
    [switch]$ByPassScreen
    )
	
	#Check for $logObject
	if(!(CheckLogObject $LogObject)){	
		$errorRecord = New-Object System.Management.Automation.ErrorRecord((New-Object Exception "Logging Object doesn't seem to be the correct object! Must execute Initialize-Log before any logging functions. "),$ModuleName,[System.Management.Automation.ErrorCategory]::OperationStopped,$null)
		$PSCmdlet.ThrowTerminatingError($errorRecord)
		return
	}
	
	[DateTime]$EntryDateTime = $([DateTime]::Now)
	
	if($LogObject.LogType -eq "LOGFILE" -or $LogObject.LogType -eq "CIRCULAR" ) {
	
		if($LogObject.LogType -eq "CIRCULAR"){
			Reset-Log -FileName $LogObject.LogFileName -FileSize $LogObject.ArchiveSize -LogCount $LogObject.ArchiveNumber
		}
	
		Add-Content -Path $LogObject.LogFileName -Value "***************************************************************************************************"
		Add-Content -Path $LogObject.LogFileName -Value "Started processing at [$($EntryDateTime)]."
		Add-Content -Path $LogObject.LogFileName -Value "***************************************************************************************************"
		Add-Content -Path $LogObject.LogFileName -Value ""
	}
	
	if($LogObject.LogType -eq "EVENT") {
		$Message = "Started processing [$($LogObject.ScriptName)]."
		Write-EventLog -LogName $LogObject.EventModuleName -Source $LogObject.ScriptName -EntryType "INFORMATION" -EventId 0 -Message $Message
	}
		
	#Write to screen for debug mode
    Write-Debug "***************************************************************************************************"
    Write-Debug "Started processing at [$($EntryDateTime)]."
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
	
	write-Debug "Username: $($env:UserName)"
    write-Debug "Current Command: $(split-path $MyInvocation.PSCommandPath -Leaf)"
    write-Debug "Current Script: $($MyInvocation.ScriptName)"
    write-Debug "Script Running on: $($env:COMPUTERNAME)"
    write-Debug "Current Version of Powershell: $($psversiontable.psversion)"
	
	if($ByPassScreen){return} else { if($LogObject.OutScreen){
		Write-Host "***************************************************************************************************"
		Write-Host "Started processing at [$($EntryDateTime)]."
		Write-Host "***************************************************************************************************"
		Write-Host ""	
		}
	}

}  # End Function Start-Log

Function Stop-Log{
<#
    .SYNOPSIS
    Optional command - Adds a ending block of test to the log.  If you are using a file, it'll have a clear section.  If you are using an event log, it'll be very simple.
    .DESCRIPTION
    Optional command - Adds a ending block of test to the log.  If you are using a file, it'll have a clear section.  If you are using an event log, it'll be very simple.
    .PARAMETER LogObject
    Mandatory. PS Custom object created from the Initialize-Log cmdlet.      
    .PARAMETER ByPassScreen
    Optional. When parameter specified will bypass displaying the content to screen.  Default behavior of displaying messages on the screen can controlled by changing the OutScreen property of the LogObject passed into this function.  Note: debug mode may double up any screen displays.    
    .INPUTS
    Parameters above
    .OUTPUTS
    None or String
    .NOTES
    See VERSIONS.md in the github repo for historical version information.
    .LINK
    https://github.com/bodybybuddha/MultiLogv1/wiki

    .EXAMPLE
    Stop-Log -LogObject $LogObj 
    Writes a Stop log line to the log.

    .EXAMPLE
    Stop-Log -LogObject $LogObj -ByPassScreen
    Writes a Stop log section to the log - but doesn't write anything to the screen.
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$True)]
    $LogObject,
    [Parameter(Mandatory=$False)]
    [switch]$ByPassScreen
    )
	
	#Check for $logObject
	if(!(CheckLogObject $LogObject)){	
		$errorRecord = New-Object System.Management.Automation.ErrorRecord((New-Object Exception "Logging Object doesn't seem to be the correct object! Must execute Initialize-Log before any logging functions. "),$ModuleName,[System.Management.Automation.ErrorCategory]::OperationStopped,$null)
		$PSCmdlet.ThrowTerminatingError($errorRecord)
		return
	}
	
	[DateTime]$EntryDateTime = $([DateTime]::Now)
	
		if($LogObject.LogType -eq "LOGFILE" -or $LogObject.LogType -eq "CIRCULAR" ) {
	
		if($LogObject.LogType -eq "CIRCULAR"){
			Reset-Log -FileName $LogObject.LogFileName -FileSize $LogObject.ArchiveSize -LogCount $LogObject.ArchiveNumber
		}
	
		Add-Content -Path $LogObject.LogFileName -Value "***************************************************************************************************"
		Add-Content -Path $LogObject.LogFileName -Value "Finish processing at [$($EntryDateTime)]."
		Add-Content -Path $LogObject.LogFileName -Value "***************************************************************************************************"
		Add-Content -Path $LogObject.LogFileName -Value ""
	}
	
	if($LogObject.LogType -eq "EVENT") {
		$Message = "Finish processing [$($LogObject.ScriptName)]."
		Write-EventLog -LogName $LogObject.EventModuleName -Source $LogObject.ScriptName -EntryType "INFORMATION" -EventId 0 -Message $Message
	}
		
	#Write to screen for debug mode
    Write-Debug ""
	Write-Debug "***************************************************************************************************"
    Write-Debug "Finished processing at [$($EntryDateTime)]."
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
	
	if($ByPassScreen){return} else { if($LogObject.OutScreen){
		Write-Host ""	
		Write-Host "***************************************************************************************************"
		Write-Host "Finished processing at [$($EntryDateTime)]."
		Write-Host "***************************************************************************************************"
		Write-Host ""	
	}
	}

}  # End Function Stop-Log

Function Write-LogEntry {
<#
    .SYNOPSIS
    Writes a message to specified log file
    .DESCRIPTION
    Appends a new message to the specified log file
    .PARAMETER LogObject
    Mandatory. PS Custom object created from the Initialize-Log cmdlet.    
    .PARAMETER MessageType
    Mandatory. Allowed message types: "ERROR", "WARNING", "INFORMATION", "SUCCESSAUDIT", "FAILUREAUDIT"    
    .PARAMETER Message
    Mandatory. The string that you want to write to the log    
    .PARAMETER EventId
    Optional.  If provided, the entry will be added to the appropriate location when writing the message to a log.  For instance, if you are writing to a file, the Event ID will be added to the output line.  If you're writing to the Event log, it will be used as the Event Id for that entry.  Only positive integers are allowed here.  All negative numbers will be converted to their positive eqivalents.  By default, a 0 is used.
    .PARAMETER ByPassScreen
    Optional. When parameter is specified will bypass displaying the content to screen.  Default behavior of displaying messages on the screen can controlled by changing the OutScreen property of the LogObject passed into this function.  Note: debug mode may double up any screen displays.  
	.PARAMETER LogLevel
    Optional. When parameter is specified will set the Log Level.  The default is 0.  If this number is less or equal to the LogObject.LogLevel, the message will be written.  Otherwise it will be bypassed.  	
    .INPUTS
    Parameters above
    .OUTPUTS
    None or String
    .NOTES
    See VERSIONS.md in the github repo for historical version information.
    .LINK
    https://github.com/bodybybuddha/MultiLogv1/wiki
    
    .EXAMPLE
    Write-LogEntry -LogObject $LogObj -MessageType INFORMATION -Message "This is a new line which I am appending to the end of the log file."
    Writes a new message to a new line in the specified log file.
    
    .EXAMPLE
    Write-LogEntry -LogObject $LogObj -MessageType Error -EventId 1000 -Message "Error situation.. do something"
    Writes a new Error log message to a new line in the specified log file.    
  #>    
    [CmdletBinding()]
    Param (        
        [Parameter(Mandatory = $True)]
        $LogObject,
        [Parameter(Mandatory = $True, HelpMessage = "Allowed values: Error, Warning, Information, SuccessAudit, and FailureAudit")]
        [ValidateSet("ERROR", "WARNING", "INFORMATION", "SUCCESSAUDIT", "FAILUREAUDIT")]
        [String]$MessageType,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [Alias("EventMessage", "EntryMessage")]
        [string]$Message,
		[Parameter(Mandatory = $False)]
        [int]$EventId = 0,
        [Parameter(Mandatory = $False)]
        [switch]$ByPassScreen,
		[Parameter(Mandatory = $False)]
        [int]$LogLevel = 0
    )
    
    Process {
	
		#Check for $logObject
		if(!(CheckLogObject $LogObject)){	
			$errorRecord = New-Object System.Management.Automation.ErrorRecord((New-Object Exception "Logging Object doesn't seem to be the correct object! Must execute Initialize-Log before any logging functions. "),$ModuleName,[System.Management.Automation.ErrorCategory]::OperationStopped,$null)
			$PSCmdlet.ThrowTerminatingError($errorRecord)
			return
		}
        
        #Capitalize MessageType value
        [String]$CapitalizedMessageType = $MessageType.ToUpper()
        
        #A padding used to allign columns in output file
        [String]$Padding = " " * $(13 - $CapitalizedMessageType.Length)
		
		[DateTime]$EntryDateTime = $([DateTime]::Now)
		$EventId = [math]::abs( $EventId)
		
		[String]$EventString = if($EventId -eq 0){''}else{[string]': Event ID ' + [string]$EventId}
        
		#Add TimeStamp to message if required
		If ($LogObject.IncludeDateTime -eq $True) {			
			[String]$MessageToFile = "[{0}][{1}{2}]{3}: {4}" -f $EntryDateTime, $CapitalizedMessageType, $Padding, $EventString, $Message				
			[String]$MessageToScreen = "[{0}] {1}{2}: {3}" -f $EntryDateTime, $CapitalizedMessageType, $EventString, $Message
		} Else {
			[String]$MessageToFile = "[{0}{1}]{2}[{3}]" -f $type, $Padding, $EventString, $Message				
			[String]$MessageToScreen = "{0}{1}: {2}" -f $type, $EventString, $Message
		}
		
		#Is Environment log Level less than Messages? If so, write message
		if($LogObject.LogLevel -le $LogLevel){
			#Write Content to Log
			if($LogObject.LogType -eq "LOGFILE"){
				Add-Content -Path $LogObject.LogFileName -Value $MessageToFile
			}
			
			if($LogObject.LogType -eq "CIRCULAR"){
				Reset-Log -FileName $LogObject.LogFileName -FileSize $LogObject.ArchiveSize -LogCount $LogObject.ArchiveNumber
				Add-Content -Path $LogObject.LogFileName -Value $MessageToFile
			}

			If($LogObject.LogType -eq "EVENT"){		
				Write-EventLog -LogName $LogObject.EventModuleName -Source $LogObject.ScriptName -EntryType $CapitalizedMessageType -EventId $EventId -Message $Message
			}
			
			#Write to screen for debug mode
			Write-Debug $MessageToScreen
			
			#Write to screen for OutScreen mode
			If ($ByPassScreen){
				return
			} else { 
				if($LogObject.OutScreen){
					Write-Host $MessageToScreen
				}

			}
		}

    } # End of Process
} # End of Function Write-LogEntry

Function Send-Log {
<#
    .SYNOPSIS
    Emails completed log file to list of recipients

    .DESCRIPTION
    Emails the contents of the specified log file to a list of recipients

    .PARAMETER SMTPServer
    Mandatory. FQDN of the SMTP server used to send the email. Example: smtp.google.com

    .PARAMETER LogPath
    Mandatory. Full path of the log file you want to email. Example: C:\Windows\Temp\Test_Script.log

    .PARAMETER EmailFrom
    Mandatory. The email addresses of who you want to send the email from. Example: "admin@9to5IT.com"

    .PARAMETER EmailTo
    Mandatory. The email addresses of where to send the email to. Seperate multiple emails by ",". Example: "admin@9to5IT.com, test@test.com"

    .PARAMETER EmailSubject
    Mandatory. The subject of the email you want to send. Example: "Cool Script - [" + (Get-Date).ToShortDateString() + "]"

    .INPUTS
    Parameters above

    .OUTPUTS
    Email sent to the list of addresses specified

    .NOTES
    See VERSIONS.md in the github repo for historical version information.
    
    .LINK
    https://github.com/bodybybuddha/MultiLogv1/wiki

    .EXAMPLE
    Send-Log -SMTPServer "smtp.google.com" -LogPath "C:\Windows\Temp\Test_Script.log" -EmailFrom "admin@9to5IT.com" -EmailTo "admin@9to5IT.com, test@test.com" -EmailSubject "Cool Script"

    Sends an email with the contents of the log file as the body of the email. Sends the email from admin@9to5IT.com and sends
    the email to admin@9to5IT.com and test@test.com email addresses. The email has the subject of Cool Script. The email is
    sent using the smtp.google.com SMTP server.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)][string]$SMTPServer,
        [Parameter(Mandatory=$True,Position=1)][string]$LogPath,
        [Parameter(Mandatory=$True,Position=2)][string]$EmailFrom,
        [Parameter(Mandatory=$True,Position=3)][string]$EmailTo,
        [Parameter(Mandatory=$True,Position=4)][string]$EmailSubject
    )

    Process {
        Try {
            $sBody = ( Get-Content $LogPath | Out-String )

            #Create SMTP object and send email
            $oSmtp = new-object Net.Mail.SmtpClient( $SMTPServer )
            $oSmtp.Send( $EmailFrom, $EmailTo, $EmailSubject, $sBody )
            Exit 0
        }
        Catch {
            Exit 1
        }
    } # End of Process
} # End of Function Send-Log

Function Reset-Log{
<#
  .Synopsis
     Based on filename ensures only x files exist of y size.
  .DESCRIPTION
     The purpose of this script is to only keep the number of log files with the .number extension based on the value passed for log count.  In addition it will ensure that the file size does not exceed the value specified by the Logsize parameter.
     -filename = logfile that this function will write to.
     -filesize = filesize limit. this will be checked by powershell to ensure that the file doesn't exceed this amount if it does exceed the amount then this script will roll the current log file to: 
     logfilename.1 
     if Logfilename.1 exists then logfilename.1 will change to logfilename.2 and the most recent file will be numbered logfilename.1.  
     This .1 or .x extension will not exceed the number specified by the logcount
     When this utility rolls a log from its name to .1 if reset-log is called again on the same log file it will not roll the log if the file doesn't exist. 
  .EXAMPLE
     Reset-Log -fileName c:\temp\test.log -filesize 1mb -logcount 5
     This will roll the log file c:\temp\test.log if the log file is greater that 1megabyte (1mb) bytes.
  .EXAMPLE
     Reset-Log -fileName c:\temp\test.log -filesize 1tb -logcount 20
     This will roll the log file c:\temp\test.log if the log file is greater that 1terabyte (1tb) bytes.
  .EXAMPLE
    Reset-Log -fileName c:\temp\test.log -filesize 1kb -logcount 20
    This will roll the log file c:\temp\test.log if the log file is greater that 1kiloByte (1kb) bytes.
  .EXAMPLE
    Reset-Log -fileName c:\temp\test.log -filesize 150 -logcount 5 
    This will roll the log file c:\temp\test.log if the log file is greater that 150 bytes.
  .INPUTS
     -filename = logfile that this function will write to.
     -filesize = filesize limit. this will be checked by powershell to ensure that the file doesn't exceed this amount if it does exceed the amount then this script will roll the current log file to: 
     logfilename.1 
     if Logfilename.1 exists then logfilename.1 will change to logfilename.2 and the most recent file will be numbered logfilename.1.  
     This .1 or .x extension will not exceed the number specified by the logcount
  .OUTPUTS
     [boolean] this indicates whether the function rolled to a new log number.
  .FUNCTIONALITY
     Log Rolling utility - function
#>
	[CmdletBinding()]
    param(
		[parameter(mandatory)][string]$fileName, 
		[ValidateNotNullOrEmpty()][int64]$filesize = 1mb, 
		[ValidateNotNullOrEmpty()][int]$logcount 
	)
 
    $logRollStatus = $True
    if(test-path $filename)
    {
        $file = Get-ChildItem $filename
        if((($file).length) -ige $filesize) #this starts the log roll
        {
            $fileDir = $file.Directory
            $fn = $file.name #this gets the name of the file we started with
            $files = @(Get-ChildItem $filedir | Where-Object{$_.name -like "$fn*"} | Sort-Object lastwritetime) #Need to force array
            $filefullname = $file.fullname #this gets the fullname of the file we started with
            for ($i = ($files.count); $i -gt 0; $i--)
            { 
                $files = @(Get-ChildItem $filedir | Where-Object{$_.name -like "$fn*"} | Sort-Object lastwritetime) #Need to force array
                $operatingFile = $files | Where-Object{($_.name).trim($fn) -eq $i}
                if ($operatingfile)
                 {$operatingFilenumber = ($files | Where-Object{($_.name).trim($fn) -eq $i}).name.trim($fn)}
                else
                {$operatingFilenumber = $null}

                if(($operatingFilenumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount))
                {
                    $operatingFilenumber = $i
                    $newfilename = "$filefullname.$operatingFilenumber"
                    $operatingFile = $files | Where-Object{($_.name).trim($fn) -eq ($i-1)}
                    write-debug "moving to $newfilename"
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force
                }
                elseif($i -ge $logcount)
                {
                    if($operatingFilenumber -eq $null)
                    { 
                        $operatingFilenumber = $i - 1
                        $operatingFile = $files | Where-Object{($_.name).trim($fn) -eq $operatingFilenumber}
                       
                    }
                    write-debug "deleting  $($operatingFile.FullName)"
                    remove-item ($operatingFile.FullName) -Force
                }
                elseif($i -eq 1)
                {
                    $operatingFilenumber = 1
                    $newfilename = "$filefullname.$operatingFilenumber"
                    write-debug "moving to $newfilename"
                    move-item $filefullname -Destination $newfilename -Force
                }
                else
                {
                    $operatingFilenumber = $i +1 
                    $newfilename = "$filefullname.$operatingFilenumber"
                    $operatingFile = $files | Where-Object{($_.name).trim($fn) -eq ($i-1)}
                    write-debug "moving to $newfilename"
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force   
                }
                    
            }

          }
         else
         { $logRollStatus = $False}
    }
    else
    {
        $logrollStatus = $False
    }
    #$logRollStatus
}



Export-ModuleMember -function 'Initialize-Log','Start-Log','Stop-Log','Write-LogEntry','Send-Log'

