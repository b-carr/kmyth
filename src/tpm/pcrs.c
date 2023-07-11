/**
 * @file  pcrs.c
 * @brief Implements library supporting Kmyth applications utilizing
 *        Platform Configuration Registers (PCRs) in TPM 2.0.
 */

#include "pcrs.h"

#include <ctype.h>
#include <string.h>

#include <openssl/evp.h>

#include "defines.h"
#include "tpm2_interface.h"

//############################################################################
// init_pcr_selection()
//############################################################################
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx,
                       int *pcrs,
                       size_t pcrs_len, TPML_PCR_SELECTION * pcrs_struct)
{
  kmyth_log(LOG_DEBUG, "creating PCR select struct from user input string");

  // Get the total number of PCRs from the TPM
  int numPCRs = -1;

  if (get_pcr_count(sapi_ctx, &numPCRs) || numPCRs < 0 || numPCRs > UINT8_MAX)
  {
    kmyth_log(LOG_ERR, "unable to retrieve PCR count ... exiting");
    return 1;
  }

  // initialize pcrs_struct to a "no PCRs selected" state
  // One set of PCR registers for our TPM
  // Each selection "mask" is 8 bits)
  pcrs_struct->count = 1;
  pcrs_struct->pcrSelections[0].hash = KMYTH_HASH_ALG;
  pcrs_struct->pcrSelections[0].sizeofSelect = (uint8_t)numPCRs / 8;
  for (int i = 0; i < pcrs_struct->pcrSelections[0].sizeofSelect; i++)
  {
    pcrs_struct->pcrSelections[0].pcrSelect[i] = 0;
  }
  kmyth_log(LOG_DEBUG, "initialized PCR struct with no PCRs selected");

  // If the user specified PCRs, update the empty PCR Selection
  // structure appropriately
  if (pcrs)
  {
    kmyth_log(LOG_DEBUG, "applying user-specified PCRs ...");

    if (pcrs_len == 0)
    {
      kmyth_log(LOG_ERR,
                "non-NULL PCRs array supplied, but length is 0 ... exiting");
      return 1;
    }

    for (size_t i = 0; i < pcrs_len; i++)
    {
      int pcr = pcrs[i];

      if (pcr < 0 || pcr >= numPCRs)
      {
        kmyth_log(LOG_ERR, "invalid PCR value specified (%d) ... exiting", pcr);
        return 1;
      }
      pcrs_struct->pcrSelections[0].pcrSelect[pcr / 8] |= (uint8_t)(1 << (pcr % 8));
    }

    if (pcrs_struct->pcrSelections[0].sizeofSelect == 3)
    {
      kmyth_log(LOG_DEBUG,
                "PCR Selection List Mask (msb->lsb): 0x%02X%02X%02X",
                pcrs_struct->pcrSelections[0].pcrSelect[2],
                pcrs_struct->pcrSelections[0].pcrSelect[1],
                pcrs_struct->pcrSelections[0].pcrSelect[0]);
    }
  }

  return 0;
}

//############################################################################
// tpm2_get_pcr_count()
//############################################################################
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount)
{
  // query TPM 2.0 to obtain the count of available PCRs
  TPMS_CAPABILITY_DATA capData;

  if (get_tpm2_properties
      (sapi_ctx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PCR_COUNT, TPM2_PT_GROUP,
       &capData))
  {
    kmyth_log(LOG_ERR, "error obtaining PCR count from TPM ... exiting");
    return 1;
  }
  *pcrCount = (int) capData.data.tpmProperties.tpmProperty[0].value;
  kmyth_log(LOG_DEBUG, "count of available PCRs (TPM2_PT_PCR_COUNT) = %d",
            *pcrCount);
  return 0;
}

int compute_policy_digests_from_digest_file(char* digests_file, uint8_t** expected_policy){
  return 0;
}

//############################################################################
// tpm2_compute_polcy_digest_from_pcr_values
//############################################################################
int compute_policy_digest_from_pcr_values(pcr_value_t* pcr_values, size_t num_values, uint8_t** policy_digest, size_t* digest_len)
{
  // have to use the full digest stuff here to make it work.
  EVP_MD_CTX* policy_ctx = NULL;
  policy_ctx = EVP_MD_CTX_new();
  if(policy_ctx == NULL)
  {
    return 1;
  }
  if(EVP_DigestInit_ex(policy_ctx, KMYTH_OPENSSL_HASH, NULL) != 1)
  {
    EVP_MD_CTX_free(policy_ctx);
    return 1;
  }

  for(size_t i = 0; i < num_values; i++)
  {
    if(EVP_DigestUpdate(policy_ctx, pcr_values[i], KMYTH_DIGEST_SIZE) != 1)
    {
      EVP_MD_CTX_free(policy_ctx);
      return 1;
    }
  }
  *policy_digest = malloc(KMYTH_DIGEST_SIZE);
  if(*policy_digest == NULL)
  {
    EVP_MD_CTX_free(policy_ctx);
    return 1;
  }
  
  if((EVP_DigestFinal_ex(policy_ctx, *policy_digest, (unsigned int*)digest_len) != 1) || (*digest_len != KMYTH_DIGEST_SIZE))
  {
    free(*policy_digest);
    *policy_digest = NULL;
    *digest_len = 0;
    EVP_MD_CTX_free(policy_ctx);
    return 1;
  }
  
  EVP_MD_CTX_free(policy_ctx);
  return 0;
}

