# PowerShell script to test LCP-ABE step by step with timeout support
# Usage: .\test_step_by_step.ps1 [setup_timeout] [keygen_timeout] [encrypt_timeout] [decrypt_timeout] [decrypt_file]

param(
    [int]$SetupTimeout = 300,      # 5 minutes default for setup
    [int]$KeygenTimeout = 600,     # 10 minutes default for keygen
    [int]$EncryptTimeout = 300,    # 5 minutes default for encrypt
    [int]$DecryptTimeout = 120,    # 2 minutes default for decrypt
    [string]$DecryptFile = ""      # Specific .bin file to decrypt
)

$ErrorActionPreference = "Stop"

function Run-WithTimeout {
    param(
        [string]$Command,
        [string[]]$Args = @(),
        [int]$TimeoutSeconds,
        [string]$StepName
    )
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "[$StepName] Starting (timeout: ${TimeoutSeconds}s)" -ForegroundColor Yellow
    if ($Args) {
        Write-Host "[$StepName] Command: $Command $($Args -join ' ')" -ForegroundColor Gray
    } else {
        Write-Host "[$StepName] Command: $Command" -ForegroundColor Gray
    }
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $startTime = Get-Date
    
    # Use Start-Process for better control
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Command
    if ($Args) {
        $psi.Arguments = $Args -join " "
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $false
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    
    try {
        [void]$process.Start()
        
        # Collect output
        $outputBuilder = New-Object System.Text.StringBuilder
        $errorBuilder = New-Object System.Text.StringBuilder
        
        $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
            $msg = $Event.Message
            Write-Host $msg
            [void]$Event.MessageData.AppendLine($msg)
        } -MessageData $outputBuilder
        
        $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
            $msg = $Event.Message
            Write-Host $msg -ForegroundColor Red
            [void]$Event.MessageData.AppendLine($msg)
        } -MessageData $errorBuilder
        
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        
        # Wait with timeout
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        
        if (-not $completed) {
            Write-Host ""
            Write-Host "[$StepName] TIMEOUT after $TimeoutSeconds seconds!" -ForegroundColor Red
            Write-Host "[$StepName] Killing process (PID: $($process.Id))..." -ForegroundColor Red
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Unregister-Event -SourceIdentifier $outputEvent.Name
            Unregister-Event -SourceIdentifier $errorEvent.Name
            $process.Dispose()
            return 124  # Timeout exit code
        }
        
        # Wait for output to finish
        Start-Sleep -Milliseconds 500
        
        Unregister-Event -SourceIdentifier $outputEvent.Name
        Unregister-Event -SourceIdentifier $errorEvent.Name
        
        $elapsed = (Get-Date) - $startTime
        Write-Host ""
        Write-Host "[$StepName] Completed in $($elapsed.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
        Write-Host "[$StepName] Exit code: $($process.ExitCode)" -ForegroundColor $(if ($process.ExitCode -eq 0) { "Green" } else { "Red" })
        
        $exitCode = $process.ExitCode
        $process.Dispose()
        return $exitCode
    }
    catch {
        Write-Host "[$StepName] Error: $_" -ForegroundColor Red
        $process.Dispose()
        return 1
    }
}

# Check if build directory exists
if (-not (Test-Path "build")) {
    Write-Host "Error: build directory not found. Run 'cmake --build build' first." -ForegroundColor Red
    exit 1
}

# Step 1: Setup
Write-Host ""
Write-Host "=== STEP 1: SETUP ===" -ForegroundColor Cyan
$setupExit = Run-WithTimeout -Command ".\build\test_setup.exe" -Args @() -TimeoutSeconds $SetupTimeout -StepName "SETUP"
if ($setupExit -ne 0) {
    Write-Host ""
    Write-Host "SETUP FAILED or TIMED OUT!" -ForegroundColor Red
    exit $setupExit
}

# Step 2: KeyGen
Write-Host ""
Write-Host "=== STEP 2: KEYGEN ===" -ForegroundColor Cyan
$keygenExit = Run-WithTimeout -Command ".\build\test_keygen.exe" -Args @() -TimeoutSeconds $KeygenTimeout -StepName "KEYGEN"
if ($keygenExit -ne 0) {
    Write-Host ""
    Write-Host "KEYGEN FAILED or TIMED OUT!" -ForegroundColor Red
    exit $keygenExit
}

# Step 3: Encrypt
Write-Host ""
Write-Host "=== STEP 3: ENCRYPT ===" -ForegroundColor Cyan
$encryptExit = Run-WithTimeout -Command ".\build\test_encrypt.exe" -Args @() -TimeoutSeconds $EncryptTimeout -StepName "ENCRYPT"
if ($encryptExit -ne 0) {
    Write-Host ""
    Write-Host "ENCRYPT FAILED or TIMED OUT!" -ForegroundColor Red
    exit $encryptExit
}

# Step 4: Decrypt
Write-Host ""
Write-Host "=== STEP 4: DECRYPT ===" -ForegroundColor Cyan
if ($DecryptFile) {
    Write-Host "[DECRYPT] Using specific file: $DecryptFile" -ForegroundColor Yellow
    $decryptExit = Run-WithTimeout -Command ".\build\test_decrypt.exe" -Args @($DecryptFile) -TimeoutSeconds $DecryptTimeout -StepName "DECRYPT"
} else {
    Write-Host "[DECRYPT] Decrypting all files in out/encrypted/" -ForegroundColor Yellow
    $decryptExit = Run-WithTimeout -Command ".\build\test_decrypt.exe" -Args @() -TimeoutSeconds $DecryptTimeout -StepName "DECRYPT"
}
if ($decryptExit -ne 0) {
    Write-Host ""
    Write-Host "DECRYPT FAILED or TIMED OUT!" -ForegroundColor Red
    exit $decryptExit
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "ALL STEPS COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

