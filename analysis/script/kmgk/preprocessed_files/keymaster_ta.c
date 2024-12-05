/*
 * This function fills @identity parameter with current client identity
 * value. @identity parameter should point to the valid TEE_Identity object
 *
 * @return TEE_SUCCESS on success
 */
//@process_func
static TEE_Result TA_GetClientIdentity(TEE_Identity *identity)
{
	// Preprocess: separate variable delcarion & value assigment
	// TEE_Result res = TEE_SUCCESS;
	TEE_Result res;
	res = TEE_SUCCESS;

	res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,
			(char *)"gpd.client.identity", identity);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to get property, res=%x", res);
		goto exit;
	}

exit:
	return res;
}

/*
 * This function fills @key array with secret value for auth_token key.
 * @key_size parameter is the @key array size. @key parameter should
 * point to the valid memory that has size at least @key_size
 *
 * @return TEE_SUCCESS on success
 */
//@process_func
static TEE_Result TA_ReadAuthTokenKey(uint8_t *key, uint32_t key_size)
{
	// Preprocess: separate variable delcarion & value assigment
	// TEE_Result res = TEE_SUCCESS;
	TEE_Result res;
	res = TEE_SUCCESS;
	// TEE_ObjectHandle auth_token_key_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle auth_token_key_obj;
	auth_token_key_obj = TEE_HANDLE_NULL;
	// uint32_t read_size = 0;
	uint32_t read_size;
	read_size = 0;

	//@func_annote |res(out) | auth_token_key_obj(out)|, # auth_token_key_id, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ(in)|, auth_token_key_id, sizeof(auth_token_key_id), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &auth_token_key_obj(ignore)|
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, auth_token_key_id, sizeof(auth_token_key_id), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &auth_token_key_obj);
	// Preprocess: change to equivalent condition
	if (! (res == TEE_SUCCESS)) {
	// if (res != TEE_SUCCESS) {
		EMSG("Failed to open auth_token key secret, res=%x", res);
		goto exit; //@no_semi_colon
	}

	//@func_annote |# dataSize(1)(in)|res, key(out)|key, key_size, &read_size(ignore)|
	res = TEE_ReadObjectData(auth_token_key_obj, key, key_size, &read_size);
	// if (res != TEE_SUCCESS || key_size != read_size) {
	// Preprocess: change to equivalent condition (not regarding read_size)
	if (! (res == TEE_SUCCESS)) {
		EMSG("Failed to read secret data, bytes = %u, res=%x", read_size, res);
		goto close_obj; //@no_semi_colon
	}

close_obj:
	//@func_annote |auth_token_key_obj(out)|
	TEE_CloseObject(auth_token_key_obj);
exit:
	return res; //@no_semi_colon
}

//@process_func
keymaster_error_t TA_GetAuthTokenKey(TEE_Param params[TEE_NUM_PARAMS])
{
	// Preprocess: separate variable delcarion & value assigment
	// TEE_Result res = TEE_SUCCESS;
	TEE_Result res;
	res = TEE_SUCCESS;
	TEE_Identity identity;
	uint8_t auth_token_key[HMAC_SHA256_KEY_SIZE_BYTE];

	res = TA_GetClientIdentity(&identity);
	// Preprocess: change to equivalent condition
	if (! (res == TEE_SUCCESS)) {
	// if (res != TEE_SUCCESS) {
		EMSG("Failed to get identity property, res=%x", res);
		goto exit; //@no_semi_colon
	}

	if (identity.login != TEE_LOGIN_TRUSTED_APP) {
		EMSG("Not trusted app trying to get auth_token key");
		res = TEE_ERROR_ACCESS_DENIED;
		goto exit; //@no_semi_colon
	}

	DMSG("%pUl requests auth_token key", (void *)&identity.uuid);
	//@func_annote(assign) |, sizeof(auth_token_key)(ignore)|
	res = TA_ReadAuthTokenKey(auth_token_key, sizeof(auth_token_key));
	// Preprocess: change to equivalent condition
	if (! (res == TEE_SUCCESS)) {
	// if (res != TEE_SUCCESS) {
		EMSG("Failed to get auth_token key, res=%x", res);
		goto exit; //@no_semi_colon
	}

	//@ignore
	if (params[1].memref.size < sizeof(auth_token_key)) {
		EMSG("Output buffer to small");
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}
	//@endignore

	//@ignore
	TEE_MemMove(params[1].memref.buffer, auth_token_key,
			sizeof(auth_token_key));
	//@endignore

exit:
	return res; //@no_semi_colon
}

//@ignore
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		EMSG("Keystore TA wrong parameters");
		return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
	}

	switch(cmd_id) {
	/* Keymaster commands */
	case KM_CONFIGURE:
		DMSG("KM_CONFIGURE");
		return TA_configure(params);
	case KM_GET_VERSION:
		DMSG("KM_GET_VERSION");
		return TA_getVersion(params);
	case KM_ADD_RNG_ENTROPY:
		DMSG("KM_ADD_RNG_ENTROPY");
		return TA_addRngEntropy(params);
	case KM_GENERATE_KEY:
		DMSG("KM_GENERATE_KEY");
		return TA_generateKey(params);
	case KM_GET_KEY_CHARACTERISTICS:
		DMSG("KM_GET_KEY_CHARACTERISTICS");
		return TA_getKeyCharacteristics(params);
	case KM_IMPORT_KEY:
		DMSG("KM_IMPORT_KEY");
		return TA_importKey(params);
	case KM_EXPORT_KEY:
		DMSG("KM_EXPORT_KEY");
		return TA_exportKey(params);
	case KM_ATTEST_KEY:
		DMSG("KM_ATTEST_KEY");
		return TA_attestKey(params);
	case KM_UPGRADE_KEY:
		DMSG("KM_UPGRADE_KEY");
		return TA_upgradeKey(params);
	case KM_DELETE_KEY:
		DMSG("KM_DELETE_KEY");
		return TA_deleteKey(params);
	case KM_DELETE_ALL_KEYS:
		DMSG("KM_DELETE_ALL_KEYS");
		return TA_deleteAllKeys(params);
	case KM_DESTROY_ATT_IDS:
		DMSG("KM_DESTROY_ATT_IDS");
		return TA_destroyAttestationIds(params);
	case KM_BEGIN:
		DMSG("KM_BEGIN");
		return TA_begin(params);
	case KM_UPDATE:
		DMSG("KM_UPDATE");
		return TA_update(params);
	case KM_FINISH:
		DMSG("KM_FINISH");
		return TA_finish(params);
	case KM_ABORT:
		DMSG("KM_ABORT");
		return TA_abort(params);
#ifdef CFG_ATTESTATION_PROVISIONING
	/* Provisioning commands */
	case KM_SET_ATTESTATION_KEY:
		DMSG("KM_SET_ATTESTATION_KEY");
		return TA_SetAttestationKey(params);
	case KM_APPEND_ATTESTATION_CERT_CHAIN:
		DMSG("KM_APPEND_ATTESTATION_CERT_CHAIN");
		return TA_AppendAttestationCertKey(params);
#endif
	/* Gatekeeper commands */
	case KM_GET_AUTHTOKEN_KEY:
		DMSG("KM_GET_AUTHTOKEN_KEY");
		return TA_GetAuthTokenKey(params);

	default:
		DMSG("Unknown command %d",cmd_id);
		return KM_ERROR_UNIMPLEMENTED;
	}
}
//@endignore

//@create_custom_main