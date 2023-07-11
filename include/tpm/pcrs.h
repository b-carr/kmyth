/**
 * @file  pcrs.h
 *
 * @brief Provides utility functions for using TPM 2.0 platform configuration
 *        registers (PCRs).
 *
 */
#ifndef PCRS_H
#define PCRS_H

#include <stdbool.h>

#include <tss2/tss2_sys.h>
#include "defines.h"

/**
 * pcr_t:
 *
 * Typedef for PCR values used to compute a policy digest from specified
 * PCR values.
 */
typedef unsigned char pcr_value_t[KMYTH_DIGEST_SIZE];
  
/**
 * @brief Converts a PCR selection input string, from the user, into the
 *        TPM 2.0 struct used to specify which PCRs to use in a sealing
 *        (or other) operation.  Also verifies that the user's PCR 
 *        selections are valid. 
 *
 * @param[in]  sapi_ctx    System API (SAPI) context, must be initialized
 *                         and passed in as pointer to the SAPI context
 *
 * @param[in]  pcrs        An array containing integers specifying which 
 *                         PCRs to apply.
 *
 * @param[in]  pcrs_len    The length of the PCRs array.
 *
 * @param[out] pcrs_struct TPM 2.0 PCR Selection List struct - the struct will
 *                         first be initialized to empty and then populated to
 *                         select any PCRs specified by the user (passed in as
 *                         a pointer to a TPML_PCR_SELECTION struct)
 *
 * @return 0 if success, 1 if error
 */
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx,
                       int *pcrs,
                       size_t pcrs_len, TPML_PCR_SELECTION * pcrs_struct);

/**
 * @brief Obtains the total count of available PCRs by reading the
 *        TPM2_PT_PCR_COUNT property from the TPM.
 *
 * @param[in]  sapi_ctx  System API (SAPI) context, must be initialized
 *                       and passed in as pointer to the SAPI context
 *
 * @param[out] pcrCount  Integer that the PCR count result will be returned
 *                       in (passed in as a pointer to an int value)
 *
 * @return 0 if success, 1 if error
 */
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount);


/**
 * @brief Computes the appropriate policy digest from a list of 
 *        PCR values.
 *
 * @param[in] pcr_values     An array of pcr_value_t structs containing the PCR values.
 * 
 * @param[in] num_values     The number of pcr_values to be processed.
 *
 * @param[out] policy_digest A pointer to memory to hold the computed digest.
 *
 * @param[out] digest_len    A pointer to hold the computed digest length.
 *
 * @return 0 if success, 1 if error
 */
int compute_policy_digest_from_pcr_values(pcr_value_t* pcr_values, size_t num_values, uint8_t** policy_digest, size_t* digest_len);

/**
 * @brief Reads a file of expected PCR values and produces the appropriate policy digest.
 *
 * @param[in] digests_file  The name of the filel.
 *
 * @param[in,out] expected_policy  A pointer to be allocated to hold the digest.
 *
 * @return 0 if success, 1 if error
 */
int compute_policy_digest_from_digests_file(char* digests_file, uint8_t** expected_policy);
#endif /* PRCS_H */
