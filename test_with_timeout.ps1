# Simple timeout wrapper for individual test commands (Windows PowerShell)
# Usage: .\test_with_timeout.ps1 <timeout_seconds> <command> [args...]
# Example: .\test_with_timeout.ps1 300 .\build\test_setup.exe

param(
    [Parameter(Mandatory=$true, Position=0)]
    [int]$TimeoutSeconds,
    
    [Parameter(Mandatory=$true, Position=1)]
    [string]$Command,
    
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
)

$ErrorActionPreference = "Continue"

Write-Host "[TIMEOUT] Starting: $Command" -ForegroundColor Yellow
if ($Args) {
    Write-Host "[TIMEOUT] Arguments: $Args" -ForegroundColor Gray
}
Write-Host "[TIMEOUT] Timeout: ${TimeoutSeconds}s" -ForegroundColor Yellow
Write-Host ""

$startTime = Get-Date

# Build process info
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Command
$psi.Arguments = $Args -join " "
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $false

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $psi

# Start process
try {
    [void]$process.Start()
    
    # Create output collectors
    $outputBuilder = New-Object System.Text.StringBuilder
    $errorBuilder = New-Object System.Text.StringBuilder
    
    $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
        $Event.Message | Write-Host
        [void]$Event.MessageData.AppendLine($Event.Message)
    } -MessageData $outputBuilder
    
    $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
        $Event.Message | Write-Host -ForegroundColor Red
        [void]$Event.MessageData.AppendLine($Event.Message)
    } -MessageData $errorBuilder
    
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    
    # Wait with timeout
    $completed = $process.WaitForExit($TimeoutSeconds * 1000)
    
    if (-not $completed) {
        Write-Host ""
        Write-Host "[TIMEOUT] Process timed out after ${TimeoutSeconds}s!" -ForegroundColor Red
        Write-Host "[TIMEOUT] Killing process (PID: $($process.Id))..." -ForegroundColor Red
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $outputEvent.Name
        Unregister-Event -SourceIdentifier $errorEvent.Name
        $process.Dispose()
        exit 124  # Linux timeout exit code
    }
    
    # Wait a bit for all output to be collected
    Start-Sleep -Milliseconds 500
    
    Unregister-Event -SourceIdentifier $outputEvent.Name
    Unregister-Event -SourceIdentifier $errorEvent.Name
}
catch {
    Write-Host "[TIMEOUT] Error starting process: $_" -ForegroundColor Red
    exit 1
}
finally {
    $process.Dispose()
}

$elapsed = (Get-Date) - $startTime

Write-Host ""
Write-Host "[TIMEOUT] Completed in $($elapsed.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
Write-Host "[TIMEOUT] Exit code: $($process.ExitCode)" -ForegroundColor $(if ($process.ExitCode -eq 0) { "Green" } else { "Red" })

exit $process.ExitCode

