Function TestCircular{
    $LogObj = Initialize-Log -logtype "CIRCULAR" -LogFileName $testCircularFile -ExecutingScriptName "testingmodule"

    $LogObj.ArchiveSize = 25kb
    $LogObj.ArchiveNumber = 3

    Start-Log -LogObject $LogObj

    write-logEntry -LogObject $LogObj -MessageType "Information" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Information" -EventId 1 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "Warning" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Warning" -EventId 2 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "Error" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Error" -EventId -1 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "SUCCESSAUDIT" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "SUCCESSAUDIT" -EventId 3 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "FAILUREAUDIT" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "FAILUREAUDIT" -EventId -2 -Message "With Event ID"

    Stop-log -LogObject $LogObj
}

Function TestLog{
    $LogObj = Initialize-Log -logtype "LOGFILE" -LogFileName $testLogFile -ExecutingScriptName "testingmodule"


    Start-Log -LogObject $LogObj

    write-logEntry -LogObject $LogObj -MessageType "Information" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Information" -EventId 1 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "Warning" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Warning" -EventId 2 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "Error" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Error" -EventId -1 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "SUCCESSAUDIT" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "SUCCESSAUDIT" -EventId 3 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "FAILUREAUDIT" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "FAILUREAUDIT" -EventId -2 -Message "With Event ID"

    Stop-log -LogObject $LogObj
}

Function TestEvent{
    $LogObj = Initialize-Log -logtype "EVENT" -ExecutingScriptName "testingmodule"

    Start-Log -LogObject $LogObj

    write-logEntry -LogObject $LogObj -MessageType "Information" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Information" -EventId 1 -Message "With Event ID"
		
    write-logEntry -LogObject $LogObj -MessageType "Warning" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Warning" -EventId 2 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "Error" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "Error" -EventId -1 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "SUCCESSAUDIT" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "SUCCESSAUDIT" -EventId 3 -Message "With Event ID"

    write-logEntry -LogObject $LogObj -MessageType "FAILUREAUDIT" -Message "Without Event ID"
    write-logEntry -LogObject $LogObj -MessageType "FAILUREAUDIT" -EventId -2 -Message "With Event ID"

    Stop-log -LogObject $LogObj
}

if(get-module -name MultiLogv1){Remove-Module MultiLogv1} else {import-module ./Libraries/MultiLogv1.psm1}
if($LogObj){$LogObj = $Null}
$testLogFile="D:\JTWorkFolder\MultiLogv1\log.log"
$testCircularFile="D:\JTWorkFolder\MultiLogv1\Circular.log"

TestLog
TestCircular
TestEvent


remove-module MultiLogv1 -force

write-host $LogObj.NumOfArchives

