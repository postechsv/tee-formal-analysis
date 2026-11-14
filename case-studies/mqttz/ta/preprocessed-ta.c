/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include <hot_cache_ta.h>

#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)
#define TABLE_SIZE              128

//@process_struct
// Manually copied from optee_os/lib/libutee/include/tee_api_types.h
// (the model provides TeeObjectInfo itself)
//@ignore
typedef struct {
    uint32_t objectType;
    uint32_t objectSize;
    uint32_t maxObjectSize;
    uint32_t objectUsage;
    size_t dataSize;
    size_t dataPosition;
    uint32_t handleFlags;
} TEE_ObjectInfo;
//@endignore

typedef struct aes_cipher {
    //@type TEE-Algorithm
    uint32_t algo;
    //@type TEE-OperationMode
    uint32_t mode;
    uint32_t key_size;
    TEE_OperationHandle op_handle;
    TEE_ObjectHandle key_handle;
} aes_cipher;
//@endprocess_struct

//@func_start
//@param session (struct AesCipher) &
//@alias sess session
static TEE_Result alloc_resources(void *session, uint32_t mode)
{
    printf("MQTTZ: Started AES Resource Allocation\n");
    aes_cipher *sess;
    TEE_Attribute attr;
    TEE_Result res;
    sess = (aes_cipher *)session;
    sess->algo = TEE_ALG_AES_CBC_NOPAD;
    sess->key_size = TA_AES_KEY_SIZE;
    printf("MQTTZ: Loaded algo and key size\n");
    // switch (mode) {
    //     case TA_AES_MODE_ENCODE:
    //         sess->mode = TEE_MODE_ENCRYPT;
    //         break;
    //     case TA_AES_MODE_DECODE:
    //         sess->mode = TEE_MODE_DECRYPT;
    //         break;
    //     default:
    //         return TEE_ERROR_BAD_PARAMETERS;
    // }
    if (mode == TA_AES_MODE_ENCODE) {
        sess->mode = TEE_MODE_ENCRYPT;
    } else {
        if (mode == TA_AES_MODE_DECODE) {
            sess->mode = TEE_MODE_DECRYPT;
        } else {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    // Free previous operation handle
    if (!(sess->op_handle == TEE_HANDLE_NULL)) {
        TEE_FreeOperation(sess->op_handle);
    }
    // Allocate operation (the model counts key sizes in bits)
    //@drop * 8
    res = TEE_AllocateOperation(&sess->op_handle, sess->algo, sess->mode, sess->key_size * 8);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: TEE_AllocateOperation failed!\n");
        sess->op_handle = TEE_HANDLE_NULL;
        goto err;
    }
    printf("MQTTZ: Allocated Operation Handle\n");
    // Free Previous Key Handle
    if (!(sess->key_handle == TEE_HANDLE_NULL)) {
        TEE_FreeTransientObject(sess->key_handle);
    }
    //@drop * 8
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, sess->key_size * 8, &sess->key_handle);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: TEE_AllocateTransitionObject failed\n");
        sess->key_handle = TEE_HANDLE_NULL;
        goto err;
    }
    printf("MQTTZ: Allocated Key Handle\n");
    // Load Dummy Key 
    //@ignore
    char *key;
    key = TEE_Malloc(sess->key_size, 0);
    if (!key)
    {
        printf("MQTTZ-ERROR: Out of memory!\n");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    //@endignore
    //@subst key => # (attrContentData(randomAttrVal))
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);
    printf("MQTTZ: InitRef\n");
    res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
    printf("MQTTZ: Populate\n");
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: TEE_PopulateTransientObject failed!\n");
        goto err;
    }
    printf("MQTTZ: Reset Operation\n");
    res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: TEE_SetOperationKey failed!\n");
        goto err;
    }
    printf("MQTTZ: Set Operation\n");
    return res;
err:
    if (!(sess->op_handle == TEE_HANDLE_NULL)) {
        TEE_FreeOperation(sess->op_handle);
    }
    sess->op_handle = TEE_HANDLE_NULL;
    if (!(sess->key_handle == TEE_HANDLE_NULL)) {
        TEE_FreeTransientObject(sess->key_handle);
    }
    sess->key_handle = TEE_HANDLE_NULL;
    return res;
}

//@func_start
//@param session (struct AesCipher) &
//@alias sess session
static TEE_Result set_aes_key(void *session, char *key)
{
    aes_cipher *sess;
    TEE_Attribute attr;
    TEE_Result res;
    sess = session;

    //@ignore
    /*
    if (key_size != sess->key_size)
    {
        prinf("MQTTZ-ERROR: Wrong Key Size!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }*/
    //@endignore

    // Load Key Another Time 
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);
    TEE_ResetTransientObject(sess->key_handle);
    res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: TEE_PopulateTransientObject Failed\n");
        return res;
    }
    TEE_ResetOperation(sess->op_handle);
    res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: TEE_SetOperationKey failed\n");
        return res;
    }
    return res;
}

//@func_start
//@param session (struct AesCipher) &
//@alias sess session
static TEE_Result set_aes_iv(void *session, char *iv)
{
    aes_cipher *sess;
    sess = (aes_cipher *)session;
    // Load IV
    TEE_CipherInit(sess->op_handle, iv, TA_AES_IV_SIZE);
    return TEE_SUCCESS;
}

/*
 * Read Raw Object from Secure Storage within TA
 *
 * This method reads an object from Secure Storage but is always invoked
 * from within a TA. Hence why we don't check the parameter types.
 */
//@func_start
//@param cli_id TEE-ObjectId
//@param data TEE-Buffer &
static TEE_Result read_raw_object(char *cli_id, char *data)
{
    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    TEE_Result res;
    //@ignore
    uint32_t read_bytes;
    //@endignore
    // Check if object is in memory
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, cli_id, cli_id_size, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &object);
    if (!(res == TEE_SUCCESS)) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        return res;
    }
    res = TEE_GetObjectInfo1(object, &object_info);
    if (!(res == TEE_SUCCESS)) {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        goto exit;
    }
    //@ignore
    if (object_info.dataSize > data_sz) {
        /*
         * Provided buffer is too short.
         * Return the expected size together with status "short buffer"
         */
        data_sz = object_info.dataSize;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }
    //@endignore
    res = TEE_ReadObjectData(object, data, object_info.dataSize, &read_bytes);
    // if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
    if (!(res == TEE_SUCCESS)) {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, object_info.dataSize);
        goto exit;
    }
    //@ignore
    data_sz = read_bytes;
    //@endignore
exit:
    TEE_CloseObject(object);
    return res;
}

//@func_start
//@param sess (struct AesCipher) &
//@param dec_data TEE-Buffer &
static TEE_Result cipher_buffer(void *sess, char *enc_data, char *dec_data)
{
    printf("MQTTZ: Starting AES Cipher!\n");
    aes_cipher *session;
    session = (aes_cipher *) sess;
    if (session->op_handle == TEE_HANDLE_NULL) {
        return TEE_ERROR_BAD_STATE;
    }
    printf("MQTTZ: Starting CipherUpdate \n");
    // return TEE_CipherUpdate(session->op_handle, enc_data, dec_data); 
    TEE_Result res;
    res = TEE_CipherUpdate(session->op_handle, enc_data, dec_data);
    return res;
}

//@func_start
//@param cli_id TEE-ObjectId
static int save_key(char *cli_id, char *cli_key)
{
    //@type TEE-DataFlags
    uint32_t obj_data_flag;
    TEE_Result res;
    TEE_ObjectHandle object;
    obj_data_flag = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
    // dummy object handle for the object to be created
    //@insert object := # oid(0, ta) ;
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, cli_id, strlen(cli_id), obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
    if (!(res == TEE_SUCCESS)) {
        return 1;
    }
    res = TEE_WriteObjectData(object, cli_key, strlen(cli_key));
    if (!(res == TEE_SUCCESS))
    {
        // the model's CloseAndDeletePersistentObject1 returns a result
        //@assign res
        TEE_CloseAndDeletePersistentObject1(object);
        return 1;
    }
    TEE_CloseObject(object);
    printf("Saved key with id: %s!\n", cli_id);
    return 0;
}

//@func_start
// Preprocess: delete key_mode arguement
//@param cli_id TEE-ObjectId
//@param cli_key TEE-Buffer &
static int get_key(char *cli_id, char *cli_key)
{
    //@ignore
    // TODO Implement Cache Logic
    char fke_key[TA_AES_KEY_SIZE + 1] = "11111111111111111111111111111111";
    size_t read_bytes = TA_AES_KEY_SIZE + 1;
    char my_id[TA_MQTTZ_CLI_ID_SZ + 1];
    strncpy(my_id, cli_id, TA_MQTTZ_CLI_ID_SZ);
    my_id[TA_MQTTZ_CLI_ID_SZ] = '\0';
    printf("My ID: %s %i\n", my_id, strlen(my_id));
    // FIXME this is only for comparing w/ cache, comment after
    /*
    int rand_num = rand() % TABLE_SIZE;
    char my_id[TA_MQTTZ_CLI_ID_SZ + 1];
    if (rand_num >= 1000)
        snprintf(my_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000%i", rand_num);
    else if (rand_num < 1000 && rand_num >= 100)
        snprintf(my_id, TA_MQTTZ_CLI_ID_SZ + 1, "000000000%i", rand_num);
    else if (rand_num < 100 && rand_num >= 10)
        snprintf(my_id, TA_MQTTZ_CLI_ID_SZ + 1, "0000000000%i",
                rand_num);
    else
        snprintf(my_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000000%i",
                rand_num);
    printf("Rand ID: %s %i\n", my_id, strlen(my_id));
    */// Until here
    if (key_mode == 0)
        goto keyinmem;
    //if ((read_raw_object(cli_id, strlen(cli_id), cli_key, read_bytes) 
    //@endignore
    TEE_Result res;
    int save_key_res;

    // if ((read_raw_object(my_id, strlen(my_id), cli_key, read_bytes) != TEE_SUCCESS))// || (read_bytes != TA_AES_KEY_SIZE))
    // Preprocess: my_id is a copy of cli_id
    res = read_raw_object(cli_id, cli_key);
    if (!(res == TEE_SUCCESS))
    {
        // FIXME We should not do this, using cache instead
        // FIXME We should run the TA as a service not to reload it every time
        printf("MQTTZ: Key not found! Saving it to persistent storage.\n");
        // save_key(my_id, cli_key);
        save_key_res = save_key(cli_id, cli_key);
        printf("MQTTZ: Only once!!!\n");
        return 0;
        // FIXME delete from previous FIXME to this one
        //printf("Key not found in storage!\n");
        //@ignore
        return 1;
        //@endignore
    }
    return 0;
//@ignore
keyinmem:
    strcpy(cli_key, fke_key);
    cli_key[TA_AES_KEY_SIZE] = '\0';
    return 0;
//@endignore
}


//@ignore
static int fill_ss(int table_size)
{
    printf("Filling Secure Storage...\n");
    unsigned int i;
    char fake_key[TA_AES_KEY_SIZE + 1] = "11111111111111111111111111111111";
    for (i = 0; i < table_size; i++)
    {
        char fake_cli_id[TA_MQTTZ_CLI_ID_SZ + 1];
        if (i >= 1000)
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000%i", i);
        else if (i < 1000 && i >= 100)
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "000000000%i", i);
        else if (i < 100 && i >= 10)
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "0000000000%i", i);
        else
            snprintf(fake_cli_id, TA_MQTTZ_CLI_ID_SZ + 1, "00000000000%i", i);
        //printf("This is the fake client id: %s\n", fake_cli_id);
        save_key(fake_cli_id, fake_key);
    }
    return 0;
}
//@endignore

//@func_start
// Preprocess: the inputs are unpacked from params[0..3] into separate arguments
//@params (struct AesCipher) & session, TEE-ObjectId oriCliId, TEE-Buffer oriCliIv, TEE-Buffer oriCliData, TEE-ObjectId destCliId, TEE-Buffer & destCliData
static TEE_Result payload_reencryption(void *session, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    int get_key_res;
    //@ignore
    TEE_Time t1, t2;
    TEE_Time t_aux;
    uint32_t exp_param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_MEMREF_INOUT,
            TEE_PARAM_TYPE_MEMREF_INOUT,
            TEE_PARAM_TYPE_VALUE_INPUT);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    printf("MQTTZ: Entered SW\n");
    // 0. Pre-load keys for a fair comparison with the cache
    if (params[3].value.b == 1)
    {
        fill_ss(TABLE_SIZE);
    }
    // 1. Decrypt from Origin
    size_t data_size = params[0].memref.size - TA_MQTTZ_CLI_ID_SZ - TA_AES_IV_SIZE;
    // 2. Read key from secure storage
    TEE_GetSystemTime(&t1);
    //@endignore
    char *ori_cli_key;
    ori_cli_key = (char *) TEE_Malloc(sizeof *ori_cli_key * (TA_AES_KEY_SIZE + 1), 0);
    printf("MQTTZ: Allocated Origin Cli Key\n");
    // if (get_key((char *) params[0].memref.buffer, ori_cli_key, params[3].value.a) != 0)
    get_key_res = get_key(ori_cli_id, ori_cli_key);
    if (!(get_key_res == 0))
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    printf("MQTTZ: Got Origin Key! %s\n", ori_cli_key);
    TEE_GetSystemTime(&t2);
    TEE_TIME_SUB(t2, t1, t_aux);
    //sprintf(params[2].memref.buffer, "%s%i", params[2].memref.buffer, t_aux.seconds * 1000 + t_aux.millis);
    //snprintf(tmp_buffer, 100, "%s%i,", tmp_buffer,
    //        t_aux.seconds * 1000 + t_aux.millis);
    snprintf((char *) params[2].memref.buffer, 100, "%s%i,", (char *) params[2].memref.buffer, t_aux.seconds * 1000 + t_aux.millis);
    TEE_GetSystemTime(&t1);
    // 2. Decrypt Inbound Traffic w/ Origin Key
    // FIXME FIXME FIXME
    //if (alloc_resources(session, TA_AES_MODE_DECODE) != TEE_SUCCESS)
    // if (!(alloc_resources(session, TA_AES_MODE_ENCODE) == TEE_SUCCESS))
    res = alloc_resources(session, TA_AES_MODE_DECODE);
    if (!(res == TEE_SUCCESS))
    {
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    printf("MQTTZ: Initialized AES Session!\n");
    // if (set_aes_key(session, ori_cli_key) != TEE_SUCCESS)
    res = set_aes_key(session, ori_cli_key);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: set_aes_key failed\n");
        res = TEE_ERROR_GENERIC;
        TEE_Free((void *) ori_cli_key);
        goto exit;
    }
    TEE_Free((void *) ori_cli_key);
    //if (set_aes_iv(session, ori_cli_iv) != TEE_SUCCESS)
    // if (set_aes_iv(session, (char *) params[0].memref.buffer + TA_MQTTZ_CLI_ID_SZ) != TEE_SUCCESS)
    res = set_aes_iv(session, ori_cli_iv);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: set_aes_iv failed\n");
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    char *dec_data;
    //@ignore
    size_t dec_data_size = TA_MQTTZ_MAX_MSG_SZ;
    //@endignore
    dec_data = (char *) TEE_Malloc(sizeof *dec_data * dec_data_size, 0);
    //@ignore
    if (!dec_data)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    //@endignore
    printf("MQTTZ: Allocated decrypted data!\n");
    // FIXME This is gonna fail, most likely
    // if (cipher_buffer(session, (char *) params[0].memref.buffer + TA_MQTTZ_CLI_ID_SZ + TA_AES_IV_SIZE, data_size, dec_data, &dec_data_size) != TEE_SUCCESS)
    res = cipher_buffer(session, ori_cli_data, dec_data);
    if (!(res == TEE_SUCCESS))
    {
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    printf("MQTTZ: Finished decrypting, now we encrypt with the other key!\n");
    //printf("MQTTZ: Decrypted data: %s\n", dec_data);
    TEE_GetSystemTime(&t2);
    TEE_TIME_SUB(t2, t1, t_aux);
    snprintf((char *) params[2].memref.buffer, 100, "%s%i,", (char *) params[2].memref.buffer, t_aux.seconds * 1000 + t_aux.millis);
    // 3. Encrypt outbound traffic with destination key
    printf("MQTTZ: Freed previous resources we don't need anymore.\n");
    //char *dest_cli_id;
    char *dest_cli_iv;
    //char *dest_cli_data;
    // The IV of the destination is a fixed dummy value (see fake_iv below)
    //@expr # dummyIv
    dest_cli_iv = (char *) TEE_Malloc(sizeof *dest_cli_iv * (TA_AES_IV_SIZE + 1), 0);
    //@ignore
    //dest_cli_data = (char *) TEE_Malloc(sizeof *dest_cli_data 
    //        * (TA_MQTTZ_MAX_MSG_SZ + 1), 0);
    if (!(dest_cli_iv))
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    //@endignore
    printf("MQTTZ: Allocated Destination Cli Data. \n");
    // 4. Get Destination Client Key from Secure Storage
    TEE_GetSystemTime(&t1);
    char *dest_cli_key;
    dest_cli_key = (char *) TEE_Malloc(sizeof *dest_cli_key * (TA_AES_KEY_SIZE + 1), 0);
    printf("MQTTZ: Allocated Destination Cli Key\n");
    // if (get_key((char *) params[1].memref.buffer, dest_cli_key, (int) params[3].value.a) != 0)
    get_key_res = get_key(dest_cli_id, dest_cli_key);
    if (!(get_key_res == 0))
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    printf("MQTTZ: Got Destination Key! %s\n", dest_cli_key);
    TEE_GetSystemTime(&t2);
    TEE_TIME_SUB(t2, t1, t_aux);
    snprintf((char *) params[2].memref.buffer, 100, "%s%i,", (char *) params[2].memref.buffer, t_aux.seconds * 1000 + t_aux.millis);
    TEE_GetSystemTime(&t1);
    // FIXME 
    // if (alloc_resources(session, TA_AES_MODE_ENCODE) != TEE_SUCCESS)
    res = alloc_resources(session, TA_AES_MODE_ENCODE);
    if (!(res == TEE_SUCCESS))
    {
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    printf("MQTTZ: Initialized AES ENCODE Session!\n");
    // if (set_aes_key(session, dest_cli_key) != TEE_SUCCESS)
    res = set_aes_key(session, dest_cli_key);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: set_aes_key failed\n");
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    printf("MQTTZ: Set Destination Key in Session\n");
    // Set random IV for encryption TODO
    //@ignore
    char fake_iv[TA_AES_IV_SIZE + 1] = "1111111111111111";
    strcpy(dest_cli_iv, fake_iv);
    //@endignore
    printf("This is the initial IV: %s\n", dest_cli_iv);
    // if (set_aes_iv(session, dest_cli_iv) != TEE_SUCCESS)
    res = set_aes_iv(session, dest_cli_iv);
    if (!(res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: set_aes_iv failed\n");
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    //@ignore
    size_t enc_data_size = TA_MQTTZ_MAX_MSG_SZ;
    //@endignore
    // if (cipher_buffer(session, dec_data, dec_data_size, (char *) params[1].memref.buffer + TA_MQTTZ_CLI_ID_SZ + TA_AES_IV_SIZE, &enc_data_size) != TEE_SUCCESS)
    res = cipher_buffer(session, dec_data, dest_cli_data);
    if (! (res == TEE_SUCCESS))
    {
        printf("MQTTZ-ERROR: Error in cipher_buffer Encrypting!\n");
        res = TEE_ERROR_GENERIC;
        goto exit;
    }
    printf("MQTTZ: Finished encrypting!\n");
    printf("MQTTZ: This is the final IV: %s\n", dest_cli_iv);
    TEE_GetSystemTime(&t2);
    TEE_TIME_SUB(t2, t1, t_aux);
    snprintf((char *) params[2].memref.buffer, 100, "%s%i,", (char *) params[2].memref.buffer, t_aux.seconds * 1000 + t_aux.millis);
    // Rebuild the return value
    //@ignore
    strcpy((char *) params[1].memref.buffer + TA_MQTTZ_CLI_ID_SZ, dest_cli_iv);
    //@endignore
    res = TEE_SUCCESS;
    TEE_Free((void *) dest_cli_iv);
    TEE_Free((void *) dest_cli_key);
    TEE_Free((void *) dec_data);
    goto exit;
exit:
    return res;
}

//@ignore
TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
    aes_cipher *sess;
    sess = TEE_Malloc(sizeof *sess, 0);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;
    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;
    *session = (void *)sess;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
    aes_cipher *sess;
    sess = (aes_cipher *) session;
    if (sess->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(sess->key_handle);
    if (sess->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(sess->op_handle);
    TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {
        case TA_REENCRYPT:
            printf("Aloha?\n");
            return payload_reencryption(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
//@endignore
