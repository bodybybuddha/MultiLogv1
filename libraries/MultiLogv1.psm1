#MultiLogv1
#Based on:
#  PSLogging from Luca Sturlese @ URL: http://9to5IT.com & https://github.com/9to5IT/PSLogging
#  PSLogging (Write-LogEntry) from Wojciech Sciesinski @ URL: https://github.com/it-praktyk/PSLogging
#  PSLog (Reset-Log) from Thom Schumacher @ URL: https://github.com/crshnbrn66/PSLog/blob/master/PSLog.psm1
#  Logging_Functions from John Taylor

Set-StrictMode -Version Latest

#Internal variables for the module 
[int32]$DefaultNumOfArchives = 10
[int64]$DefaultSizeOfArchives = 1mb

$Version = '1.0'
$ModuleName = 'MultiLogv1'

Function Initialize-Log{
[CmdletBinding()]
Param (
	[Parameter(Mandatory=$true)]
	[string]$ExecutingScriptName,
    [Parameter(Mandatory=$true)]
	[ValidateSet('LOGFILE','EVENT','CIRCULAR')]
    [string]$LogType,
	[Parameter(Mandatory=$True,ParameterSetName="LOGFILECIRCULAR")]
    [string]$LogFileName,	
	[Parameter(Mandatory=$false,ParameterSetName="LOGFILECIRCULAR")]	
    [string]$LogFileExtension = '.log',
    [Parameter(Mandatory=$false,ParameterSetName="EVENT")]	
    [string]$EventLogName = $ModuleName	
    )
	
	#####################################################################################
	#  Need to test for parameters & some Initializing variables
	#####################################################################################
	if($LogType -eq "LOGFILE") {
		# Check for LogFileName - IF none found use the ExecutingScriptName and default logfile extension
		If(!$LogFileName){ 
			$LogFileName = $ExecutingScriptName + $LogFileExtension					
		}		
	}
    if($LogType -eq "EVENT") {
		

	}
    if($LogType -eq "CIRCULAR") {
		# Check for LogFileName - IF none found use the ExecutingScriptName and default logfile extension
		If(!$LogFileName){ 
			$LogFileName = $ExecutingScriptName + $LogFileExtension					
		}		
	
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
	} # main custom object to be passed back to calling script

	#  The NoteProperty ones could've been done in initial declartion, this is just an example	
	$PSLoggingEnv | Add-member -MemberType NoteProperty -name ScriptName -value $ExecutingScriptName
	
	if ($PSLoggingEnv.LogType -eq "LOGFILE") {
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name LogFileName -value $LogFileName  	
	}
	
    if ($PSLoggingEnv.LogType -eq "EVENT") {
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name EventModuleName -value $EventLogName 
	}
	
    if ($PSLoggingEnv.LogType -eq "CIRCULAR") {
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name LogFileName -value $LogFileName  
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name ArchiveNumber -value $DefaultNumOfArchives 
		$PSLoggingEnv | Add-member -MemberType NoteProperty -name ArchiveSize -value $DefaultSizeOfArchives 
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
		New-Item -Path $PSLoggingEnv.LogFileName –ItemType File  | out-null
	} 

	If($PSLoggingEnv.LogType -eq "EVENT"){
		
		#Check for the existence of the Event Log - If it's not there create it.
		#$ExistingActionPreference = $ErrorActionPreference
		#$ErrorActionPreference = "SilentlyContinue"
		
		$logFileExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $PSLoggingEnv.EventModuleName} 
		if (! $logFileExists) {
			try {New-Eventlog -LogName $PSLoggingEnv.EventModuleName -Source $PSLoggingEnv.ScriptName -erroraction stop | Out-Null}
			catch [System.Security.SecurityException] {
				Write-Error "Error:  Run as elevated user.  Unable to write or read to event logs."
			}
		} else {
		
		# Log does exist - see if the source is already registered
			if(!(Test-Sourcename -SourceName $PSLoggingEnv.ScriptName) ){
				try {New-Eventlog -LogName $PSLoggingEnv.EventModuleName -Source $PSLoggingEnv.ScriptName -erroraction stop | Out-Null}
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
        [Parameter(Mandatory=$true)]
        [string] $SourceName
    )

    [System.Diagnostics.EventLog]::SourceExists($SourceName)
} # End of fucntion Test-Sourcename

Function CheckLogObject{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,Position=0)]
		$LogObject 
		)
	if(-not $LogObject){return $false}
	
	try{if($LogObject.LogModuleName -eq $ModuleName){return $true} else {return $false}} catch {return $false}
	
	return $false
} # End Function CheckLogObject

Function Start-Log{
	[CmdletBinding()]
	Param (
    [Parameter(Mandatory=$true)]
    $LogObject,
    [Parameter(Mandatory=$false)]
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
		Write-Output "***************************************************************************************************"
		Write-Output "Started processing at [$($EntryDateTime)]."
		Write-Output "***************************************************************************************************"
		Write-Output ""	
		}
	}

}  # End Function Start-Log

Function Stop-Log{
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    $LogObject,
    [Parameter(Mandatory=$false)]
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
		Write-Output ""	
		Write-Output "***************************************************************************************************"
		Write-Output "Finished processing at [$($EntryDateTime)]."
		Write-Output "***************************************************************************************************"
		Write-Output ""	
	}
	}

}  # End Function Stop-Log

Function Write-LogEntry {
<#
    .SYNOPSIS
    Writes a message to specified log file
    .DESCRIPTION
    Appends a new message to the specified log file
    .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
    
    .PARAMETER MessageType
    Mandatory. Allowed message types: INFO, WARNING, ERROR, CRITICAL, START, STOP, SUCCESS, FAILURE
    .PARAMETER Message
    Mandatory. The string that you want to write to the log
    .PARAMETER TimeStamp
    Optional. When parameter specified will append the current date and time to the end of the line. Useful for knowing
    when a task started and stopped.
    
    .PARAMETER EntryDateTime
    Optional. By default a current date and time is used but it is possible provide any other correct date/time.
    
    .PARAMETER ConvertTimeToUTF
    # Need be filled
    .PARAMETER ToScreen
    Optional. When parameter specified will display the content to screen as well as write to log file. This provides an additional
    another option to write content to screen as opposed to using debug mode.
    
    .PARAMETER
    .INPUTS
    Parameters above
    .OUTPUTS
    None or String
    .NOTES
    
	Current version:  1.2.0
	
	Authors: 
	- Wojciech Sciesinski wojciech[at]sciesinski[dot]net
	
	Version history: github.com/9to5IT/PSLogging/VERSIONS.MD
    
    Inspired and partially based on PSLogging module authored by Luca Sturlese - https://github.com/9to5IT/PSLogging
    
    TODO
    Updated examples - add additional with new implemented parameters
    Implement converting day/time to UTF
    Output with colors (?) - Write-Host except Write-Output need to be used
    
    .LINK
    http://9to5IT.com/powershell-logging-v2-easily-create-log-files
    .LINK
    https://github.com/it-praktyk/PSLogging
    
    .LINK
    https://www.linkedin.com/in/sciesinskiwojciech
    
    .EXAMPLE
    Write-LogEntry -LogPath "C:\Windows\Temp\Test_Script.log" -MessageType CRITICAL -Message "This is a new line which I am appending to the end of the log file."
    Writes a new critical log message to a new line in the specified log file.
    
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
		[Parameter(Mandatory = $false)]
        [int]$EventId = 0,
        [Parameter(Mandatory = $false)]
        [switch]$ByPassScreen
        
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
			
		}
		Else {
			
			[String]$MessageToFile = "[{0}{1}]{2}[{3}]" -f $type, $Padding, $EventString, $Message				
			[String]$MessageToScreen = "{0}{1}: {2}" -f $type, $EventString, $Message
			
		}
		
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
		If ($ByPassScreen){return
		} else { 
			if($LogObject.OutScreen){
				Write-Output $MessageToScreen
			}

		}
       
        
    }
}

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
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  05.10.12
    Purpose/Change: Initial function development.

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  02/09/15
    Purpose/Change: Changed function name to use approved PowerShell Verbs. Improved help documentation.

    Version:        1.2
    Author:         Luca Sturlese
    Creation Date:  02/09/15
    Purpose/Change: Added SMTPServer parameter to pass SMTP server as oppposed to having to set it in the function manually.

  .LINK
    http://9to5IT.com/powershell-logging-v2-easily-create-log-files

  .EXAMPLE
    Send-Log -SMTPServer "smtp.google.com" -LogPath "C:\Windows\Temp\Test_Script.log" -EmailFrom "admin@9to5IT.com" -EmailTo "admin@9to5IT.com, test@test.com" -EmailSubject "Cool Script"

    Sends an email with the contents of the log file as the body of the email. Sends the email from admin@9to5IT.com and sends
    the email to admin@9to5IT.com and test@test.com email addresses. The email has the subject of Cool Script. The email is
    sent using the smtp.google.com SMTP server.
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$SMTPServer,
    [Parameter(Mandatory=$true,Position=1)][string]$LogPath,
    [Parameter(Mandatory=$true,Position=2)][string]$EmailFrom,
    [Parameter(Mandatory=$true,Position=3)][string]$EmailTo,
    [Parameter(Mandatory=$true,Position=4)][string]$EmailSubject
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
  }
}

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
 
    $logRollStatus = $true
    if(test-path $filename)
    {
        $file = Get-ChildItem $filename
        if((($file).length) -ige $filesize) #this starts the log roll
        {
            $fileDir = $file.Directory
            $fn = $file.name #this gets the name of the file we started with
            $files = @(Get-ChildItem $filedir | Where-Object{$_.name -like "$fn*"} | Sort-Object lastwritetime)
            $filefullname = $file.fullname #this gets the fullname of the file we started with
            for ($i = ($files.count); $i -gt 0; $i--)
            { 
                $files = @(Get-ChildItem $filedir | Where-Object{$_.name -like "$fn*"} | Sort-Object lastwritetime)
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
         { $logRollStatus = $false}
    }
    else
    {
        $logrollStatus = $false
    }
    $logRollStatus
}



Export-ModuleMember -function *
