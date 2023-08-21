/* Copyright 2023 kmwebnet
 * SPDX-License-Identifier: Apache-2.0
 */

#include <windows.h>
#include <stdio.h>
#include "se050.h"
#include <ex_sss_objid.h>

#include <fsl_sss_se05x_apis.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_ecc_curves.h>
#include <se05x_ecc_curves_values.h>
#include <se05x_tlv.h>
#include <string.h>
#include <time.h>

 /*Common KeyID for generating key pair*/
#define CERTIFICATE_KEY_ID (EX_SSS_OBJID_DEMO_CLOUD_START + 1)

#define ECC_KEY_BIT_LEN 256

sss_status_t se050work(void)
{
    static ex_sss_boot_ctx_t pCtx;
    sss_status_t status = kStatus_SSS_Fail;
    uint32_t keyId = CERTIFICATE_KEY_ID;
    size_t keyBitLen = ECC_KEY_BIT_LEN;
    size_t keyLen = keyBitLen * 8;
    sss_key_part_t keyPart = kSSS_KeyPart_Pair;
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;
    sss_object_t obj = { 0 };

    status = ex_sss_boot_open(&pCtx, "0");
    if (status != kStatus_SSS_Success) {
        LOG_E("ex_sss_boot_open failed");
        return status;
    }

    status = ex_sss_key_store_and_object_init(&pCtx);
    if (status != kStatus_SSS_Success) {
		LOG_E("ex_sss_key_store_and_object_init failed");
		return status;
	}

    status = sss_key_object_init(&obj, &pCtx.ks);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_init Failed!!!");
        return status;
    }

    status = sss_key_object_allocate_handle(&obj, keyId, keyPart, cipherType, keyLen, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E("Object allocate handle failed");
        return status;
    }
    status = sss_key_store_generate_key(&pCtx.ks, &obj, keyBitLen, NULL);
    if (status != kStatus_SSS_Success) {
        LOG_E("Failed to inject key");
    }
    else {
        LOG_I("Success");
    }

    //create self signed certificate

    sss_object_t pobj;
    X509* certificate = X509_new();
    ASN1_INTEGER* serialNumber = NULL;
    X509_NAME* subjectName = NULL;
    ASN1_TIME* notBefore = NULL;
    ASN1_TIME* notAfter = NULL;
    uint8_t key[550];
    size_t keybytelen = sizeof(key);
    size_t keybitlen = keybytelen * 8;

    BIO* bio = NULL;
    EVP_PKEY* pKey = NULL;
    X509V3_CTX x509v3_ctx = { 0 };
    char* subjectAlternateName = "email:d:NXP-SE050-PROVISIONED";
    char* basicConstraints = "CA:TRUE";
    X509_EXTENSION* extension_SAN = NULL;
    X509_EXTENSION* extension_BasicConstraints = NULL;
    int type = NID_ecdsa_with_SHA256;
    int len = 0;
    uint8_t tbs_bytes[500];
    uint8_t* p_tbs_bytes = &tbs_bytes[0];
    uint8_t digest[32] = { 0 };
    size_t digestLen = sizeof(digest);
    sss_digest_t digestCtx = {
        0,
    };
    sss_asymmetric_t asymmCtx = {
        0,
    };
    uint8_t signature[256] = {
        0,
    };
    uint8_t* p_signature = &signature[0];
    size_t signatureLen = sizeof(signature);
    unsigned char cert[4000];
    unsigned char* pCert = &cert[0];
    sss_object_t cert_obj = {
        0,
    };
 
    sss_key_part_t ckeyPart = kSSS_KeyPart_Default;
    sss_cipher_type_t ccipherType = kSSS_CipherType_Binary;

    status = sss_key_object_init(&pobj, &pCtx.ks);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_init Failed!!!");
        goto cleanup;
    }

    status = kStatus_SSS_Fail;
    if (!X509_set_version(certificate, 2)) {
        goto cleanup;
    }

    serialNumber = ASN1_INTEGER_new();
    if (!ASN1_INTEGER_set(serialNumber, 1) || !X509_set_serialNumber(certificate, serialNumber)) {
        goto cleanup;
    }

    subjectName = X509_NAME_new();
    if (!X509_NAME_add_entry_by_txt(subjectName,
        "CN",
        MBSTRING_ASC,
        (const unsigned char*)"selfSignedCA",
        -1 /* len */,
        -1 /* loc */,
        0 /* set */) ||
        !X509_set_subject_name(certificate, subjectName)) {
        goto cleanup;
    }

    if (!X509_set_issuer_name(certificate, subjectName)) {
        goto cleanup;
    }

    notBefore = ASN1_TIME_new();
    time_t activeDateTime = time(NULL);
    if (!ASN1_TIME_set(notBefore, activeDateTime) || !X509_set_notBefore(certificate, notBefore)) {
        goto cleanup;
    }

    notAfter = ASN1_TIME_new();
    time_t notAfterTime = time(NULL);
    if (!ASN1_TIME_set(notAfter, notAfterTime * 2) || !X509_set_notAfter(certificate, notAfter)) {
        goto cleanup;
    }

    /*Generate a keypair*/

    status = sss_key_object_get_handle(&pobj, keyId);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_get_handle Failed!!!");
        goto cleanup;
    }

    status = sss_key_store_get_key(&pCtx.ks, &pobj, key, &keybytelen, &keybitlen);
    LOG_I("sss_key_store_get_key status %x", status);
    if (status != kStatus_SSS_Success) {
        goto cleanup;
    }

    status = kStatus_SSS_Fail;
    bio = BIO_new_mem_buf(key, (int)sizeof(key));
    if (bio == NULL) {
        goto cleanup;
    }

    pKey = d2i_PUBKEY_bio(bio, NULL);
    if (pKey == NULL) {
        goto cleanup;
    }
    /*Add public key*/

    if (!X509_set_pubkey(certificate, pKey)) {
        goto cleanup;
    }

    extension_SAN = X509V3_EXT_nconf_nid(NULL, &x509v3_ctx, NID_subject_alt_name, subjectAlternateName);
    if (!X509_add_ext(certificate, extension_SAN, -1)) {
        goto cleanup;
    }

    extension_BasicConstraints = X509V3_EXT_nconf_nid(NULL, &x509v3_ctx, NID_basic_constraints, basicConstraints);
    if (!X509_add_ext(certificate, extension_BasicConstraints, -1)) {
        goto cleanup;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    X509_ALGOR* tbs_algo = certificate->cert_info->signature;
    X509_ALGOR* algo = certificate->sig_alg;
    X509_ALGOR_set0(algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);
#else
    const X509_ALGOR* tmp_tbs_algo = X509_get0_tbs_sigalg((const X509*)certificate);
    X509_ALGOR* tbs_algo = (X509_ALGOR*)tmp_tbs_algo;
#endif
    X509_ALGOR_set0(tbs_algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);

    /*Convert to DER format to sign*/
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    X509_CINF* cinf = certificate->cert_info;
    len = i2d_X509_CINF(cinf, &p_tbs_bytes);
#else
    len = i2d_re_X509_tbs(certificate, &p_tbs_bytes);
    LOG_I("len = %d", len);
#endif

    /*Calculate digest for signing*/
    status = sss_digest_context_init(&digestCtx, &pCtx.session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_context_init Failed!!!");
        goto cleanup;
    }

    status = sss_digest_one_go(&digestCtx, &tbs_bytes[0], len, digest, &digestLen);
    sss_digest_context_free(&digestCtx);
    if (status != kStatus_SSS_Success) {
        goto cleanup;
    }

    status = kStatus_SSS_Fail;
    /*Sign digest*/
    status = sss_asymmetric_context_init(&asymmCtx, &pCtx.session, &pobj, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_digest_context_init Failed!!!");
        goto cleanup;
    }

    status = sss_asymmetric_sign_digest(&asymmCtx, digest, digestLen, signature, &signatureLen);
    if (status != kStatus_SSS_Success) {
        goto cleanup;
    }

    sss_asymmetric_context_free(&asymmCtx);

    /*Add signature to certificate structure*/
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ASN1_BIT_STRING* sig = certificate->signature;
#else
    ASN1_BIT_STRING* sig;
    const X509_ALGOR* tmp_algo = NULL;
    X509_get0_signature((const ASN1_BIT_STRING**)&sig, &tmp_algo, (const X509*)certificate);
    X509_ALGOR* algo = (X509_ALGOR*)tmp_algo;
    X509_ALGOR_set0(algo, OBJ_nid2obj(type), V_ASN1_NULL, NULL);
#endif
    len = ASN1_BIT_STRING_set(sig, p_signature, signatureLen);

    len = i2d_X509(certificate, NULL);
    if (len == 0) {
        LOG_I("i2d_X509 Failed");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    len = i2d_X509(certificate, &pCert);
    LOG_AU8_I(cert, len);

    status = sss_key_object_init(&cert_obj, &pCtx.ks);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_init Failed!!!");
        goto cleanup;
    }

    sss_se05x_session_t* pSession = (sss_se05x_session_t*)&pCtx.session;

    Se05x_API_DeleteSecureObject(&pSession->s_ctx, keyId + 1);

    status = sss_key_object_allocate_handle(&cert_obj, keyId + 1, ckeyPart, ccipherType, len, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        LOG_E("sss_key_object_allocate_handle Failed!!!");
        goto cleanup;
    }

    status = sss_key_store_set_key(&pCtx.ks, &cert_obj, cert, len, len * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        LOG_E("Failed to inject generated certificate");
    }
    else {
        LOG_I("Success");
    }

cleanup:
    if (pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (notAfter != NULL) {
        ASN1_TIME_free(notAfter);
    }
    if (notBefore != NULL) {
        ASN1_TIME_free(notBefore);
    }
    if (subjectName != NULL) {
        X509_NAME_free(subjectName);
    }
    if (serialNumber != NULL) {
        ASN1_INTEGER_free(serialNumber);
    }
    if (extension_SAN != NULL) {
        X509_EXTENSION_free(extension_SAN);
    }
    if (extension_BasicConstraints != NULL) {
        X509_EXTENSION_free(extension_BasicConstraints);
    }
    if (certificate != NULL) {
        X509_free(certificate);
    }
    sss_key_object_free(&obj);
    sss_key_object_free(&pobj);
    sss_key_object_free(&cert_obj);
    sss_key_store_context_free(&pCtx.ks);

    ex_sss_session_close(&pCtx);

    return status;
}

int main(int argc, char const* argv[]) {

    sss_status_t status = kStatus_SSS_Success;

    //get windows mutex
    HANDLE hMutex = CreateMutex(NULL, FALSE, L"Global\\SE050");
    if (hMutex == NULL) {
        printf("CreateMutex error: %d\n", GetLastError());
        return 1;
    }
    //wait for mutex
    DWORD dwWaitResult = WaitForSingleObject(hMutex, INFINITE);
    switch (dwWaitResult)
    {
    case WAIT_OBJECT_0:

        status = se050work();
        if (status != kStatus_SSS_Success) {
            LOG_E("ex_sss_boot_open failed");
        };

        ReleaseMutex(hMutex);
        break;
    default:
        printf("Mutex error\n");
        return 1;
    }

    CloseHandle(hMutex);

    return 0;
}
