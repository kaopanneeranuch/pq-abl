# Post-Quantum Attribute-Based Logging System (PQ-ABL)

## LCP-ABE Implementation with Module-LWE

This project implements a **Lattice-based Ciphertext-Policy Attribute-Based Encryption (LCP-ABE)** system for secure logging, based on Module-LWE assumptions for post-quantum security.

### Architecture

```
lcp-abe/
├── common/          # Common types and parameters
├── setup/           # Phase 1: Setup (MPK, MSK generation)
├── keygen/          # Phase 2: KeyGen (user secret keys)
├── encrypt/         # Phase 3: Encrypt (ABE + AES-GCM + microbatch)
├── decrypt/         # Phase 4: Decrypt
├── policy/          # Policy parsing and LSSS
└── util/            # Utilities (RNG, SHA3, JSON parser)

module_gaussian_lattice/
└── Module_BFRS/     # Lattice trapdoor and Gaussian sampling
```

### Features

- **Module-LWE based CP-ABE**: Quantum-resistant encryption
- **Microbatching**: Efficient batch processing of logs with same policy
- **Hybrid Encryption**: ABE encrypts symmetric keys, AES-GCM encrypts log data
- **Epoch-based Processing**: Logs grouped by 30-minute time windows
- **LSSS**: Linear Secret Sharing Scheme for flexible access policies

### Building (Ubuntu VM)

```bash
# Install dependencies
sudo apt-get install build-essential cmake libssl-dev

# Create build directory
mkdir build && cd build

# Configure with OpenSSL
cmake .. -DUSE_OPENSSL=ON

# Build
make -j$(nproc)

# Libraries will be in build/
# liblcp_abe.a and libmodule_bfrs.a
```

### Parameters

Current parameters (128-bit security level):
- **Modulus q**: 12289
- **Polynomial degree n**: 256
- **Module rank d**: 4
- **Gaussian σ**: 4.2
- **Irreducible factors r**: 8

See `lcp-abe/common/lcp_params.h` and `module_gaussian_lattice/Module_BFRS/common.h`

### Usage Example

#### 1. Setup - Generate Master Keys

```c
#include "lcp-abe/setup/lcp_setup.h"

MasterPublicKey mpk;
MasterSecretKey msk;

// Generate keys for 32 attributes
lcp_setup(32, &mpk, &msk);

// Save keys
lcp_save_mpk(&mpk, "mpk.bin");
lcp_save_msk(&msk, "msk.bin");
```

#### 2. KeyGen - Generate User Secret Keys

```c
#include "lcp-abe/keygen/lcp_keygen.h"

// Define user attributes
AttributeSet user_attrs;
attribute_set_init(&user_attrs);

Attribute attr1, attr2;
attribute_init(&attr1, "user_role:admin", 0);
attribute_init(&attr2, "team:storage-team", 1);
attribute_set_add(&user_attrs, &attr1);
attribute_set_add(&user_attrs, &attr2);

// Generate secret key
UserSecretKey usk;
lcp_keygen(&mpk, &msk, &user_attrs, &usk);
lcp_save_usk(&usk, "user_sk.bin");
```

#### 3. Encrypt - Process Logs

```c
#include "lcp-abe/encrypt/lcp_encrypt.h"

// Parse logs
JsonLogArray logs;
json_parse_log_file("logs/log.json", &logs);

// Define policies
AccessPolicy policies[2];
policy_init(&policies[0]);
policy_parse("(user_role:admin AND team:storage-team)", &policies[0]);
lsss_policy_to_matrix(&policies[0]);

policy_init(&policies[1]);
policy_parse("(user_role:devops AND team:infra-team)", &policies[1]);
lsss_policy_to_matrix(&policies[1]);

// Process logs in microbatches
Microbatch *batches;
uint32_t n_batches;
process_logs_microbatch(&logs, policies, 2, &mpk, &batches, &n_batches);

// Save encrypted batches
for (uint32_t i = 0; i < n_batches; i++) {
    save_encrypted_batch(&batches[i], "encrypted_logs/");
}
```

#### 4. Decrypt - Recover Logs

```c
#include "lcp-abe/decrypt/lcp_decrypt.h"

// Load encrypted batch
load_and_decrypt_batch("encrypted_logs/batch_epoch123_policy1.bin", &usk, &mpk);

// Or decrypt single log
uint8_t *log_data;
size_t log_len;
decrypt_log_entry(&encrypted_log, &usk, &mpk, &log_data, &log_len);
printf("Decrypted: %.*s\n", (int)log_len, log_data);
free(log_data);
```

### Log Format

Sample `log.json` format (see `logs/log_sample.json`):

```json
{
  "timestamp": "2025-10-31T10:00:15.123456Z",
  "user_id": "u-100eff",
  "user_role": "admin",
  "team": "storage-team",
  "action_type": "read",
  "resource_id": "res-9651e77d",
  "resource_type": "VM",
  "service_name": "RDS",
  "region": "ap-southeast-1",
  "log_data": "SELECT * FROM users WHERE id=12345"
}
```

**Note**: `abe_policy` field removed - policies are derived from log attributes

### Policy Configuration

See `policy_config.json`:

```json
{
  "policies": [
    {
      "policy_id": "admin_storage",
      "expression": "(user_role:admin AND team:storage-team)"
    }
  ],
  "epoch_duration_minutes": 30
}
```

### Microbatching Strategy

1. Logs are grouped by **epoch** (30-min windows) and **access policy**
2. For each batch:
   - One ABE ciphertext structure is created (shared policy evaluation)
   - Each log gets fresh `K_log` (256-bit), encrypted individually with ABE
   - Log data encrypted with AES-GCM using `K_log`
   - `CT_obj = {CT_sym, CT_ABE, metadata, hash}`

### Security Notes

- **AES-GCM**: Currently uses stub implementation. In Ubuntu VM, compile with `-DUSE_OPENSSL=ON` to use OpenSSL's secure AES-GCM.
- **RNG**: Uses stdlib `rand()` for simplicity. Replace with `/dev/urandom` or hardware RNG for production.
- **Module_BFRS**: External lattice library - parameters already configured in `common.h`

### File Structure

```
CMakeLists.txt              # Build configuration
policy_config.json          # Policy definitions
logs/
  └── log_sample.json       # Sample log format (create your own)
lcp-abe/                    # All LCP-ABE implementation
encrypted_logs/             # Output directory (created at runtime)
module_gaussian_lattice/    # Lattice operations (DO NOT MODIFY)
```

### Next Steps

1. **Generate Log File**: Create `logs/log.json` with 1000+ entries using the sample format
2. **Build in Ubuntu**: Transfer to Ubuntu VM and build with CMake
3. **Run Tests**: Create test programs to run each phase
4. **Performance Testing**: Compare encryption times with other papers

### References

- Paper: "Post-Quantum Attribute-Based Logging System for Insider Forensics in the Cloud"
- Module-LWE parameters: 128-bit post-quantum security level
- Based on lattice trapdoors and Gaussian sampling from Module_BFRS

---

**Status**: ✅ Core implementation complete  
**TODO**: Testing, optimization, benchmarking
