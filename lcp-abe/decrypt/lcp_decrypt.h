#ifndef LCP_DECRYPT_H
#define LCP_DECRYPT_H

#include "../common/lcp_types.h"
#include <stddef.h>

// Phase 4: Decryption

// Decrypt ABE ciphertext to recover K_log
int lcp_abe_decrypt(const ABECiphertext *ct_abe,
                    const UserSecretKey *usk,
                    const MasterPublicKey *mpk,
                    uint8_t key_out[AES_KEY_SIZE]);

// Decrypt symmetric ciphertext with AES-GCM
int decrypt_log_symmetric(const SymmetricCiphertext *ct_sym,
                         const uint8_t key[AES_KEY_SIZE],
                         const LogMetadata *metadata,
                         uint8_t **plaintext_out,
                         size_t *plaintext_len);

// Decrypt complete log entry
int decrypt_log_entry(const EncryptedLogObject *encrypted_log,
                     const UserSecretKey *usk,
                     const MasterPublicKey *mpk,
                     uint8_t **log_data_out,
                     size_t *log_len);

// Load individual CT_obj file
int load_ctobj_file(const char *filename, EncryptedLogObject *log);

// Batch decryption with policy reuse optimization (Phase 6 spec)
// Processes multiple CT_obj files and reuses ABE decryption for same policies
int decrypt_ctobj_batch(const char **filenames,
                       uint32_t n_files,
                       const UserSecretKey *usk,
                       const MasterPublicKey *mpk,
                       const char *output_dir);

// Legacy functions (for old batch file format)
// Decrypt microbatch
int decrypt_microbatch(const Microbatch *batch,
                      const UserSecretKey *usk,
                      const MasterPublicKey *mpk);

// Load and decrypt batch from file
int load_and_decrypt_batch(const char *filename,
                          const UserSecretKey *usk,
                          const MasterPublicKey *mpk);

#endif // LCP_DECRYPT_H
