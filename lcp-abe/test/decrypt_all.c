#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <dirent.h>
#include <string.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "module_gaussian_lattice/Module_BFRS/sampling.h"
#ifdef _WIN32
#include <direct.h>
#endif

int main(int argc, char *argv[]) {
    // Initialize Module_BFRS components (required for polynomial operations)
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();  // REQUIRED: Initialize l_coeffs, d_coeffs, h_coeffs for sampling
    
    // Parse command-line arguments
    // Usage: test_decrypt_all [SK_directory]
    //   - No args: find all SK files in keys/ directory and try each one
    //   - 1 arg: directory containing SK files (default: keys/)
    const char *sk_dir = "keys";
    if (argc > 1) {
        sk_dir = argv[1];
    }
    if (argc > 2) {
        fprintf(stderr, "Usage: %s [SK_directory]\n", argv[0]);
        fprintf(stderr, "  - No args: find all SK files in keys/ and try each one for decryption\n");
        fprintf(stderr, "  - 1 arg: directory containing SK files\n");
        return 1;
    }
    
    // Load MPK
    MasterPublicKey mpk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0) {
        fprintf(stderr, "Error: Failed to load MPK\n");
        return 1;
    }
    
    // Find all SK files
    char *sk_files[100];
    uint32_t n_sks = 0;
    
    DIR *sk_dir_handle = opendir(sk_dir);
    if (!sk_dir_handle) {
        fprintf(stderr, "Error: Cannot open SK directory %s\n", sk_dir);
        mpk_free(&mpk);
        return 1;
    }
    
    struct dirent *entry;
    while ((entry = readdir(sk_dir_handle)) != NULL) {
        // Look for SK_*.bin files
        if (strstr(entry->d_name, "SK_") && strstr(entry->d_name, ".bin")) {
            char *filepath = (char*)malloc(512);
            snprintf(filepath, 512, "%s/%s", sk_dir, entry->d_name);
            sk_files[n_sks++] = filepath;
            
            if (n_sks >= 100) break;
        }
    }
    closedir(sk_dir_handle);
    
    if (n_sks == 0) {
        fprintf(stderr, "Error: No SK files found in %s\n", sk_dir);
        mpk_free(&mpk);
        return 1;
    }
    
    // Create output directory (cross-platform)
#ifdef _WIN32
    _mkdir("out/decrypted");
#else
    mkdir("out/decrypted", 0755);
#endif
    
    // Find all CT_obj files
    char *ctobj_files[1000];
    uint32_t n_files = 0;
    
    DIR *enc_dir = opendir("out/encrypted");
    if (!enc_dir) {
        fprintf(stderr, "Error: Cannot open out/encrypted/ directory\n");
        for (uint32_t i = 0; i < n_sks; i++) {
            free(sk_files[i]);
        }
        mpk_free(&mpk);
        return 1;
    }
    
    while ((entry = readdir(enc_dir)) != NULL) {
        // Look for ctobj_*.bin files
        if (strstr(entry->d_name, "ctobj_") && 
            strstr(entry->d_name, ".bin") && 
            !strstr(entry->d_name, "hash")) {
            
            char *filepath = (char*)malloc(512);
            snprintf(filepath, 512, "out/encrypted/%s", entry->d_name);
            ctobj_files[n_files++] = filepath;
            
            if (n_files >= 1000) break;
        }
    }
    closedir(enc_dir);
    
    if (n_files == 0) {
        fprintf(stderr, "Error: No CT_obj files found in out/encrypted/\n");
        for (uint32_t i = 0; i < n_sks; i++) {
            free(sk_files[i]);
        }
        mpk_free(&mpk);
        return 1;
    }
    
    // Decrypt each file by trying all SKs until one works
    uint32_t success_count = 0;
    uint32_t total_attempts = 0;
    
    for (uint32_t i = 0; i < n_files; i++) {
        // Load CT_obj
        EncryptedLogObject log;
        if (load_ctobj_file(ctobj_files[i], &log) != 0) {
            continue;
        }
        
        int decrypted = 0;
        UserSecretKey sk;
        
        // Try each SK until one works
        for (uint32_t j = 0; j < n_sks && !decrypted; j++) {
            total_attempts++;
            
            // Load SK
            if (lcp_load_usk(&sk, sk_files[j]) != 0) {
                continue;
            }
            
            // Try to decrypt (suppress error messages - we'll try next SK)
            uint8_t k_log[AES_KEY_SIZE];
            if (lcp_abe_decrypt(&log.ct_abe, &sk, &mpk, k_log) == 0) {
                // ABE decryption succeeded, try symmetric decryption
                uint8_t *log_data = NULL;
                size_t log_len = 0;
                
                if (decrypt_log_symmetric(&log.ct_sym, k_log, &log.metadata, 
                                         &log_data, &log_len) == 0) {
                    // Success! Save decrypted log
                    char output_filename[512];
                    snprintf(output_filename, sizeof(output_filename), 
                            "out/decrypted/decrypted_log_%d.json", i + 1);
                    
                    FILE *out_fp = fopen(output_filename, "w");
                    if (out_fp) {
                        // Reconstruct full JSON object
                        fprintf(out_fp, "{\n");
                        fprintf(out_fp, "  \"timestamp\": \"%s\",\n", log.metadata.timestamp);
                        fprintf(out_fp, "  \"user_id\": \"%s\",\n", log.metadata.user_id);
                        fprintf(out_fp, "  \"user_role\": \"%s\",\n", log.metadata.user_role);
                        fprintf(out_fp, "  \"team\": \"%s\",\n", log.metadata.team);
                        fprintf(out_fp, "  \"action_type\": \"%s\",\n", log.metadata.action_type);
                        fprintf(out_fp, "  \"resource_id\": \"%s\",\n", log.metadata.resource_id);
                        fprintf(out_fp, "  \"resource_type\": \"%s\",\n", log.metadata.resource_type);
                        fprintf(out_fp, "  \"resource_owner\": \"%s\",\n", log.metadata.resource_owner);
                        fprintf(out_fp, "  \"service_name\": \"%s\",\n", log.metadata.service_name);
                        fprintf(out_fp, "  \"region\": \"%s\",\n", log.metadata.region);
                        fprintf(out_fp, "  \"instance_id\": \"%s\",\n", log.metadata.instance_id);
                        fprintf(out_fp, "  \"ip_address\": \"%s\",\n", log.metadata.ip_address);
                        fprintf(out_fp, "  \"application\": \"%s\",\n", log.metadata.application);
                        fprintf(out_fp, "  \"event_description\": \"%s\",\n", log.metadata.event_description);
                        fprintf(out_fp, "  \"log_data\": \"");
                        
                        // Escape JSON special characters
                        for (size_t k = 0; k < log_len; k++) {
                            char c = log_data[k];
                            if (c == '"') {
                                fprintf(out_fp, "\\\"");
                            } else if (c == '\\') {
                                fprintf(out_fp, "\\\\");
                            } else if (c == '\n') {
                                fprintf(out_fp, "\\n");
                            } else if (c == '\r') {
                                fprintf(out_fp, "\\r");
                            } else if (c == '\t') {
                                fprintf(out_fp, "\\t");
                            } else if (c >= 0 && c < 32) {
                                fprintf(out_fp, "\\u%04x", (unsigned char)c);
                            } else {
                                fputc(c, out_fp);
                            }
                        }
                        fprintf(out_fp, "\"\n");
                        fprintf(out_fp, "}\n");
                        fclose(out_fp);
                    }
                    
                    free(log_data);
                    decrypted = 1;
                    success_count++;
                }
            }
            
            usk_free(&sk);
        }
        
        if (!decrypted) {
            // All SKs failed for this file
            fprintf(stderr, "[Decrypt All] Failed to decrypt file %d: No matching SK found\n", i + 1);
        }
        
        encrypted_log_free(&log);
    }
    
    // Cleanup
    for (uint32_t i = 0; i < n_files; i++) {
        free(ctobj_files[i]);
    }
    for (uint32_t i = 0; i < n_sks; i++) {
        free(sk_files[i]);
    }
    mpk_free(&mpk);
    
    if (success_count == 0) {
        fprintf(stderr, "Decryption failed: No files successfully decrypted\n");
        return 1;
    }
    
    return 0;
}

