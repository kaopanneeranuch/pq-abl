# Quick test script to generate only ONE key (faster testing)
# Usage: .\test_keygen_single.ps1 [key_index] [timeout]
# key_index: 0=admin_storage, 1=admin_only, 2=app_team (default: 0)

param(
    [int]$KeyIndex = 0,
    [int]$Timeout = 180  # 3 minutes for single key
)

$ErrorActionPreference = "Stop"

# Check if build directory exists
if (-not (Test-Path "build\test_keygen.exe")) {
    Write-Host "Error: test_keygen.exe not found. Run 'cmake --build build' first." -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Quick KeyGen Test (Single Key)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] This script generates only ONE key instead of 3" -ForegroundColor Yellow
Write-Host "[INFO] Key Index: $KeyIndex (0=admin_storage, 1=admin_only, 2=app_team)" -ForegroundColor Gray
Write-Host "[INFO] Timeout: ${Timeout}s (3 minutes should be enough for one key)" -ForegroundColor Gray
Write-Host ""

# Create a temporary modified keygen test that only generates one key
$tempKeygen = @"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/policy/lcp_policy.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

int main(void) {
    init_crt_trees();
    init_cplx_roots_of_unity();
    
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0 ||
        lcp_load_msk(&msk, "keys/MSK.bin") != 0) {
        fprintf(stderr,"Failed to load MPK/MSK\n"); return 1;
    }

    const char* keys[3][3] = {
        {"keys/SK_admin_storage.bin", "user_role:admin", "team:storage-team"},
        {"keys/SK_admin_only.bin", "user_role:admin", NULL},
        {"keys/SK_app_team.bin", "team:app-team", NULL}
    };
    
    int key_idx = $KeyIndex;
    if (key_idx < 0 || key_idx > 2) {
        fprintf(stderr, "Invalid key index %d (must be 0-2)\n", key_idx);
        return 1;
    }

    AttributeSet attrs;
    attribute_set_init(&attrs);

    for (int i = 0; i < 2; i++) {
        const char* name = keys[key_idx][i+1];
        if (!name) continue;

        Attribute attr;
        uint32_t index = attr_name_to_index(name);
        attribute_init(&attr, name, index);
        attribute_set_add(&attrs, &attr);
        printf("  - %s (index %u)\n", attr.name, attr.index);
    }

    UserSecretKey sk;
    usk_init(&sk, (uint32_t)attrs.count);

    printf("[KeyGen] Generating key %d/%d...\n", key_idx+1, 1);
    if (lcp_keygen(&mpk, &msk, &attrs, &sk) != 0) {
        fprintf(stderr, "KeyGen failed\n");
        usk_free(&sk);
        return 1;
    }

    if (lcp_save_usk(&sk, keys[key_idx][0]) != 0) {
        fprintf(stderr, "Failed to write %s\n", keys[key_idx][0]);
        usk_free(&sk);
        return 1;
    }

    printf("Saved %s\n", keys[key_idx][0]);
    usk_free(&sk);
    return 0;
}
"@

# Write temporary test file
$tempFile = "lcp-abe/test/keygen_single_temp.c"
$tempFile | Out-File -Encoding ASCII -NoNewline -InputObject $tempKeygen

Write-Host "[BUILD] Compiling single-key test..." -ForegroundColor Yellow

# Build it (quick and dirty - just compile directly)
$env:CFLAGS = "-O3"
if (Get-Command cl -ErrorAction SilentlyContinue) {
    # MSVC
    $buildCmd = "cl /O2 /I. /I lcp-abe\common /I module_gaussian_lattice\Module_BFRS $tempFile lcp-abe\keygen\lcp_keygen.c ..."
    Write-Host "[WARN] Direct compilation not implemented. Using full test_keygen instead." -ForegroundColor Yellow
    Write-Host "[INFO] Tip: Modify lcp-abe/test/keygen.c to only generate one key for faster testing" -ForegroundColor Gray
    Remove-Item $tempFile -ErrorAction SilentlyContinue
    
    # Fall back to using timeout with original test
    Write-Host ""
    Write-Host "[INFO] Running original test_keygen with reduced timeout..." -ForegroundColor Yellow
    Write-Host "[INFO] It will generate all 3 keys, but we'll timeout after $Timeout seconds" -ForegroundColor Gray
    Write-Host "[INFO] This will generate at least the first key before timeout" -ForegroundColor Gray
    Write-Host ""
    
    & ".\test_with_timeout.ps1" $Timeout ".\build\test_keygen.exe"
    exit $LASTEXITCODE
} else {
    Write-Host "[ERROR] Cannot compile directly. Use original test_keygen." -ForegroundColor Red
    Remove-Item $tempFile -ErrorAction SilentlyContinue
    exit 1
}

