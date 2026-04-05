/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * test/wh_test_caliptra_hwmodel.c
 *
 * wolfHSM + Caliptra hw-model integration test (Architecture B).
 *
 * Architecture
 * ------------
 * This test exercises the "Architecture B" integration model:
 *
 *   wolfHSM CLIENT
 *       |  (mem transport — in-process, no IPC)
 *   wolfHSM SERVER  (SoC-side)
 *       |  devId = WOLF_CALIPTRA_DEVID, affinity = WH_CRYPTO_AFFINITY_HW
 *   wolfCrypt CryptoCb dispatch
 *       |  wc_caliptra_cb registered for WOLF_CALIPTRA_DEVID
 *   Caliptra mailbox protocol
 *       |  caliptra_mailbox_exec() in port/caliptra/caliptra_hwmodel.c
 *   Caliptra hw-model emulator
 *       (libcaliptra_hw_model_c_binding.a, running reference firmware)
 *
 * The wolfHSM server's RNG is initialised with WOLF_CALIPTRA_DEVID, so
 * wh_Client_RngGenerateBlock() fetches random bytes from real Caliptra
 * firmware running in the emulator.
 *
 * Crypto operations (AES-GCM, ECDSA, HMAC) are tested by calling wolfCrypt
 * directly with WOLF_CALIPTRA_DEVID; wolfHSM's generic server crypto path
 * does not yet bridge between its key management and Caliptra CMK handles,
 * so those tests bypass the wolfHSM server intentionally.
 *
 * Compile-time guard
 * ------------------
 * The entire file is compiled only when WOLFHSM_CFG_TEST_CALIPTRA_HWMODEL
 * is defined (set by the Makefile when CALIPTRA_HWMODEL=1).
 *
 * Additional required defines (set by Makefile):
 *   WOLFSSL_CALIPTRA          — enable caliptra_port.c compilation
 *   WOLF_CRYPTO_CB            — enable wolfCrypt callback framework
 *   HAVE_ANONYMOUS_INLINE_AGGREGATES=1 — ABI match for prebuilt libwolfssl.a
 *   CALIPTRA_ROM_PATH         — path to Caliptra ROM binary
 *   CALIPTRA_FW_PATH          — path to Caliptra firmware image bundle
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_TEST_CALIPTRA_HWMODEL) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)             && \
    defined(WOLF_CRYPTO_CB)

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/port/caliptra/caliptra_port.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "port/caliptra/caliptra_hwmodel.h"

#include "wh_test_common.h"
#include "wh_test_caliptra_hwmodel.h"

/* =========================================================================
 * Sizes
 * ========================================================================= */

#define BUFFER_SIZE         4096
#define FLASH_RAM_SIZE      (1024 * 1024)
#define FLASH_SECTOR_SIZE   (128 * 1024)
#define FLASH_PAGE_SIZE     (8)

/* =========================================================================
 * Helper: compare byte arrays; return 1 if equal
 * ========================================================================= */

static int bytes_eq(const byte *a, const byte *b, int len)
{
    int i;
    int diff = 0;
    for (i = 0; i < len; i++) diff |= (int)(a[i] ^ b[i]);
    return diff == 0;
}

/* =========================================================================
 * Test: Caliptra RNG via wolfCrypt CryptoCb
 *
 * Initialises a WC_RNG with WOLF_CALIPTRA_DEVID so that GenerateBlock
 * dispatches to wc_caliptra_cb -> CM_RANDOM_GENERATE mailbox command.
 * Verifies the returned bytes are not all-zero.
 * ========================================================================= */

static int test_caliptra_rng(void)
{
    WC_RNG  rng;
    uint8_t buf[32];
    int     any_nonzero = 0;
    int     i;
    int     ret;

    memset(buf, 0, sizeof(buf));

    ret = wc_InitRng_ex(&rng, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, buf, sizeof(buf));
        wc_FreeRng(&rng);
    }

    if (ret != 0) {
        WH_ERROR_PRINT("  RNG: failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    for (i = 0; i < (int)sizeof(buf); i++) {
        if (buf[i]) any_nonzero = 1;
    }
    if (!any_nonzero) {
        WH_ERROR_PRINT("  RNG: Caliptra returned all-zero bytes\n");
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("    RNG (Caliptra CM_RANDOM_GENERATE): PASS\n");
    return WH_ERROR_OK;
}

/* =========================================================================
 * Test: wolfHSM server with WOLF_CALIPTRA_DEVID processes AES-CBC
 *
 * Sends an AES-CBC request through the wolfHSM client -> server path.
 * The server is configured with devId = WOLF_CALIPTRA_DEVID; for AES-CBC
 * wc_caliptra_cb returns CRYPTOCB_UNAVAILABLE, causing wolfCrypt to fall
 * back to software.  This exercises the full wolfHSM crypto dispatch path
 * (including devId routing) even when Caliptra doesn't handle the operation.
 * ========================================================================= */

static int test_wh_aescbc_devid(whClientContext *client, whServerContext *server)
{
    Aes     aes[1];
    uint8_t key[16]       = {0x01};
    uint8_t iv[16]        = {0x02};
    uint8_t plain[16]     = {0x03};
    uint8_t cipher[16]    = {0};
    uint32_t out_size     = 0;
    int rc;

    WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(wc_AesSetKey(aes, key, sizeof(key), iv,
                                        AES_ENCRYPTION));

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AesCbcRequest(client, aes, 1, plain, sizeof(plain)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    rc = wh_Client_AesCbcResponse(client, aes, cipher, &out_size);
    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(rc);

    WH_TEST_PRINT("    AES-CBC via wolfHSM server (WOLF_CALIPTRA_DEVID): PASS\n");
    return WH_ERROR_OK;
}

/* =========================================================================
 * Test: AES-GCM encrypt / decrypt roundtrip via Caliptra
 *
 * Imports a raw AES-256 key into Caliptra, encrypts, then decrypts.
 * Caliptra generates the IV server-side; it is retrieved via
 * wc_caliptra_aesgcm_get_iv().
 * ========================================================================= */

static int test_caliptra_aesgcm_roundtrip(void)
{
    static const byte aes_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const byte plaintext[] = "Hello, Caliptra! This is a test.";
    static const byte aad[]       = "additional data";

    CaliptraCmk enc_cmk;
    byte        ciphertext[48];
    byte        decrypted[48];
    byte        enc_tag[16];
    byte        iv_out[12];
    byte        dummy_iv[12]; /* wolfSSL requires ivSz>0; Caliptra ignores it */
    Aes         enc_aes;
    Aes         dec_aes;
    int         ret;

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted,  0, sizeof(decrypted));
    memset(enc_tag,    0, sizeof(enc_tag));
    memset(iv_out,     0, sizeof(iv_out));
    memset(dummy_iv,   0, sizeof(dummy_iv));

    ret = wc_caliptra_import_key(aes_key, 32, CMB_KEY_USAGE_AES, &enc_cmk);
    if (ret != 0) {
        WH_ERROR_PRINT("  AES-GCM: key import failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_AesInit(&enc_aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        enc_aes.devCtx = &enc_cmk;
        ret = wc_AesGcmEncrypt(&enc_aes,
                               ciphertext, plaintext, 32,
                               dummy_iv, 12,
                               enc_tag, 16,
                               aad, 15);
        if (ret == 0)
            ret = wc_caliptra_aesgcm_get_iv(&enc_aes, iv_out, sizeof(iv_out));
        wc_AesFree(&enc_aes);
    }

    if (ret != 0) {
        wc_caliptra_delete_key(&enc_cmk);
        WH_ERROR_PRINT("  AES-GCM: encrypt failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_AesInit(&dec_aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        dec_aes.devCtx = &enc_cmk;
        ret = wc_AesGcmDecrypt(&dec_aes,
                               decrypted, ciphertext, 32,
                               iv_out, 12,
                               enc_tag, 16,
                               aad, 15);
        wc_AesFree(&dec_aes);
    }

    wc_caliptra_delete_key(&enc_cmk);

    if (ret != 0) {
        WH_ERROR_PRINT("  AES-GCM: decrypt failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }
    if (!bytes_eq(decrypted, plaintext, 32)) {
        WH_ERROR_PRINT("  AES-GCM: plaintext mismatch after roundtrip\n");
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("    AES-GCM encrypt/decrypt roundtrip: PASS\n");
    return WH_ERROR_OK;
}

/* =========================================================================
 * Test: AES-GCM authentication failure (tampered tag)
 * ========================================================================= */

static int test_caliptra_aesgcm_auth_failure(void)
{
    static const byte aes_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const byte plaintext[] = "Hello, Caliptra! This is a test.";

    CaliptraCmk cmk;
    byte        ciphertext[48];
    byte        discarded[48];
    byte        auth_tag[16];
    byte        bad_tag[16];
    byte        iv[12];
    byte        dummy_iv[12];
    Aes         aes;
    int         ret;

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(discarded,  0, sizeof(discarded));
    memset(auth_tag,   0, sizeof(auth_tag));
    memset(iv,         0, sizeof(iv));
    memset(dummy_iv,   0, sizeof(dummy_iv));

    ret = wc_caliptra_import_key(aes_key, 32, CMB_KEY_USAGE_AES, &cmk);
    if (ret != 0) {
        WH_ERROR_PRINT("  AES-GCM auth fail: key import failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_AesInit(&aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        aes.devCtx = &cmk;
        ret = wc_AesGcmEncrypt(&aes,
                               ciphertext, plaintext, 32,
                               dummy_iv, 12,
                               auth_tag, 16,
                               NULL, 0);
        if (ret == 0)
            ret = wc_caliptra_aesgcm_get_iv(&aes, iv, sizeof(iv));
        wc_AesFree(&aes);
    }

    if (ret != 0) {
        wc_caliptra_delete_key(&cmk);
        WH_ERROR_PRINT("  AES-GCM auth fail: encrypt failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    /* Tamper the authentication tag: flip the first byte */
    memcpy(bad_tag, auth_tag, 16);
    bad_tag[0] ^= 0xFF;

    ret = wc_AesInit(&aes, NULL, WOLF_CALIPTRA_DEVID);
    if (ret == 0) {
        aes.devCtx = &cmk;
        ret = wc_AesGcmDecrypt(&aes,
                               discarded, ciphertext, 32,
                               iv, 12,
                               bad_tag, 16,
                               NULL, 0);
        wc_AesFree(&aes);
    }

    wc_caliptra_delete_key(&cmk);

    if (ret != AES_GCM_AUTH_E) {
        WH_ERROR_PRINT("  AES-GCM auth fail: expected AES_GCM_AUTH_E (%d)"
                       " got %d\n", AES_GCM_AUTH_E, ret);
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("    AES-GCM tampered-tag returns AES_GCM_AUTH_E: PASS\n");
    return WH_ERROR_OK;
}

/* =========================================================================
 * Test: ECDSA P-384 sign and verify via Caliptra
 *
 * Imports the same 48-byte seed as both sign and verify CMK. Caliptra
 * derives the same P-384 key pair from the seed on both sides, so the
 * hardware-to-hardware sign+verify round-trip succeeds.
 * ========================================================================= */

static int test_caliptra_ecdsa(void)
{
    WC_RNG      rng;
    ecc_key     sign_key;
    ecc_key     ver_key;
    CaliptraCmk sign_cmk;
    CaliptraCmk verify_cmk;
    byte        sig_der[160];
    word32      sig_len = sizeof(sig_der);
    byte        hash[48];
    byte        seed[48];
    int         verify_res = 0;
    int         ret;

    memset(hash, 0xAB, 48);
    memset(sig_der, 0, sizeof(sig_der));

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WH_ERROR_PRINT("  ECDSA: InitRng failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_RNG_GenerateBlock(&rng, seed, sizeof(seed));
    if (ret != 0) {
        wc_FreeRng(&rng);
        WH_ERROR_PRINT("  ECDSA: RNG seed failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_caliptra_import_key(seed, 48, CMB_KEY_USAGE_ECDSA, &sign_cmk);
    if (ret != 0) {
        wc_FreeRng(&rng);
        WH_ERROR_PRINT("  ECDSA: sign key import failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_caliptra_import_key(seed, 48, CMB_KEY_USAGE_ECDSA, &verify_cmk);
    if (ret != 0) {
        wc_caliptra_delete_key(&sign_cmk);
        wc_FreeRng(&rng);
        WH_ERROR_PRINT("  ECDSA: verify key import failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    /* Sign: initialise curve metadata via make_key, then override devCtx */
    wc_ecc_init_ex(&sign_key, NULL, WOLF_CALIPTRA_DEVID);
    ret = wc_ecc_make_key_ex(&rng, 48, &sign_key, ECC_SECP384R1);
    if (ret == 0) {
        sign_key.devCtx = &sign_cmk;
        sign_key.devId  = WOLF_CALIPTRA_DEVID;
        ret = wc_ecc_sign_hash(hash, 48, sig_der, &sig_len, &rng, &sign_key);
    }
    wc_ecc_free(&sign_key);

    if (ret != 0) {
        wc_caliptra_delete_key(&sign_cmk);
        wc_caliptra_delete_key(&verify_cmk);
        wc_FreeRng(&rng);
        WH_ERROR_PRINT("  ECDSA: sign failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    /* Verify: same trick */
    wc_ecc_init_ex(&ver_key, NULL, WOLF_CALIPTRA_DEVID);
    ret = wc_ecc_make_key_ex(&rng, 48, &ver_key, ECC_SECP384R1);
    if (ret == 0) {
        ver_key.devCtx = &verify_cmk;
        ver_key.devId  = WOLF_CALIPTRA_DEVID;
        ret = wc_ecc_verify_hash(sig_der, sig_len, hash, 48,
                                 &verify_res, &ver_key);
    }
    wc_ecc_free(&ver_key);

    wc_caliptra_delete_key(&sign_cmk);
    wc_caliptra_delete_key(&verify_cmk);
    wc_FreeRng(&rng);

    if (ret != 0 || verify_res != 1) {
        WH_ERROR_PRINT("  ECDSA: verify failed: ret=%d verify_res=%d\n",
                       ret, verify_res);
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("    ECDSA P-384 sign+verify: PASS\n");
    return WH_ERROR_OK;
}

/* =========================================================================
 * Test: HMAC-SHA-384 via Caliptra, cross-validated against wolfSSL software
 *
 * Caliptra HMAC is single-shot only (see caliptra_port.h).  This test calls
 * wc_caliptra_hmac() directly and compares the result against a wolfSSL
 * software HMAC reference.
 * ========================================================================= */

static int test_caliptra_hmac_sha384(void)
{
    /* Caliptra firmware requires HMAC keys of exactly 48 or 64 bytes */
    static const byte hmac_key[48] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static const byte msg[]     = "data";
    static const int  msg_len   = 4;

    CaliptraCmk hmac_cmk;
    byte        mac[48];
    byte        sw_mac[48];
    word32      mac_len = sizeof(mac);
    Hmac        sw_hmac;
    int         ret;

    memset(mac,    0, sizeof(mac));
    memset(sw_mac, 0, sizeof(sw_mac));

    ret = wc_caliptra_import_key(hmac_key, 48, CMB_KEY_USAGE_HMAC, &hmac_cmk);
    if (ret != 0) {
        WH_ERROR_PRINT("  HMAC: key import failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = wc_caliptra_hmac(&hmac_cmk, WC_SHA384,
                           msg, (word32)msg_len,
                           mac, &mac_len);

    wc_caliptra_delete_key(&hmac_cmk);

    if (ret != 0) {
        WH_ERROR_PRINT("  HMAC: Caliptra HMAC failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    /* Software reference */
    ret = wc_HmacInit(&sw_hmac, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(&sw_hmac, WC_SHA384, hmac_key, 48);
        if (ret == 0)
            ret = wc_HmacUpdate(&sw_hmac, msg, (word32)msg_len);
        if (ret == 0)
            ret = wc_HmacFinal(&sw_hmac, sw_mac);
        wc_HmacFree(&sw_hmac);
    }

    if (ret != 0) {
        WH_ERROR_PRINT("  HMAC: software reference failed: %d\n", ret);
        return WH_ERROR_ABORTED;
    }
    if (!bytes_eq(mac, sw_mac, 48)) {
        WH_ERROR_PRINT("  HMAC: Caliptra result differs from software\n");
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("    HMAC-SHA-384 matches software reference: PASS\n");
    return WH_ERROR_OK;
}

/* =========================================================================
 * Entry point
 * ========================================================================= */

int whTest_CaliptraHwmodel(void)
{
    int rc = WH_ERROR_OK;

    /* wolfHSM transport / server / client contexts */
    uint8_t              req_buf[BUFFER_SIZE]  = {0};
    uint8_t              resp_buf[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]               = {{
                  .req       = (whTransportMemCsr*)req_buf,
                  .req_size  = sizeof(req_buf),
                  .resp      = (whTransportMemCsr*)resp_buf,
                  .resp_size = sizeof(resp_buf),
    }};

    whTransportClientCb         tccb[1]   = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]   = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 1,
    }};
    whClientConfig              c_conf[1] = {{.comm = cc_conf}};
    whClientContext             client[1] = {0};

    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 1,
    }};

    uint8_t          flash_mem[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                     = {0};
    whFlashRamsimCfg fc_conf[1]                = {{
                          .size       = FLASH_RAM_SIZE,
                          .sectorSize = FLASH_SECTOR_SIZE,
                          .pageSize   = FLASH_PAGE_SIZE,
                          .erasedByte = ~(uint8_t)0,
                          .memory     = flash_mem,
    }};
    const whFlashCb  fcb[1] = {WH_FLASH_RAMSIM_CB};

    whNvmFlashContext nfc[1]     = {0};
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmCb      nfcb[1]   = {WH_NVM_FLASH_CB};
    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1] = {0};

    whServerCryptoContext crypto[1] = {0};
    whServerConfig        s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
         .crypto      = crypto,
         .devId       = WOLF_CALIPTRA_DEVID,
    }};
    whServerContext server[1] = {0};

    WH_TEST_PRINT("whTest_CaliptraHwmodel\n");
    fflush(stdout); /* flush before hw-model UART output begins on stderr */

#ifndef CALIPTRA_ROM_PATH
#error "CALIPTRA_ROM_PATH must be defined (set by Makefile CALIPTRA_HWMODEL=1)"
#endif
#ifndef CALIPTRA_FW_PATH
#error "CALIPTRA_FW_PATH must be defined (set by Makefile CALIPTRA_HWMODEL=1)"
#endif

    /* Boot the hw-model emulator */
    rc = caliptra_hwmodel_init(CALIPTRA_ROM_PATH, CALIPTRA_FW_PATH);
    if (rc != 0) {
        WH_ERROR_PRINT("  caliptra_hwmodel_init failed: %d\n", rc);
        return WH_ERROR_ABORTED;
    }

    /* Register the Caliptra CryptoCb device */
    rc = wolfCrypt_Init();
    if (rc != 0) {
        WH_ERROR_PRINT("  wolfCrypt_Init failed: %d\n", rc);
        caliptra_hwmodel_cleanup();
        return WH_ERROR_ABORTED;
    }

    rc = wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
    if (rc != 0) {
        WH_ERROR_PRINT("  CryptoCb_RegisterDevice failed: %d\n", rc);
        wolfCrypt_Cleanup();
        caliptra_hwmodel_cleanup();
        return WH_ERROR_ABORTED;
    }

    /* Set up wolfHSM server + client */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    /* Server RNG uses WOLF_CALIPTRA_DEVID so random generation dispatches
     * to Caliptra firmware via wc_caliptra_cb */
    rc = wc_InitRng_ex(crypto->rng, NULL, WOLF_CALIPTRA_DEVID);
    if (rc != 0) {
        WH_ERROR_PRINT("  wc_InitRng_ex(WOLF_CALIPTRA_DEVID) failed: %d\n",
                       rc);
        wh_Nvm_Cleanup(nvm);
        wc_CryptoCb_UnRegisterDevice(WOLF_CALIPTRA_DEVID);
        wolfCrypt_Cleanup();
        caliptra_hwmodel_cleanup();
        return WH_ERROR_ABORTED;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    /* Signal server as connected (in-process mem transport, no connect cb) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Bootstrap the comm layer */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, NULL, NULL));

    WH_TEST_PRINT("  wolfHSM server (WOLF_CALIPTRA_DEVID configured):\n");

    /* AES-CBC: wc_caliptra_cb returns CRYPTOCB_UNAVAILABLE for CBC (software
     * fallback), but the full wolfHSM devId dispatch path is exercised. */
    rc = test_wh_aescbc_devid(client, server);
    if (rc != WH_ERROR_OK) goto cleanup;

    WH_TEST_PRINT("  Direct Caliptra crypto (wolfCrypt + WOLF_CALIPTRA_DEVID):\n");

    rc = test_caliptra_rng();
    if (rc != WH_ERROR_OK) goto cleanup;

    rc = test_caliptra_aesgcm_roundtrip();
    if (rc != WH_ERROR_OK) goto cleanup;

    rc = test_caliptra_aesgcm_auth_failure();
    if (rc != WH_ERROR_OK) goto cleanup;

    rc = test_caliptra_ecdsa();
    if (rc != WH_ERROR_OK) goto cleanup;

    rc = test_caliptra_hmac_sha384();
    if (rc != WH_ERROR_OK) goto cleanup;

    WH_TEST_PRINT("  whTest_CaliptraHwmodel: all tests passed\n");
    fflush(stdout); /* flush after all tests before cleanup UART output */

cleanup:
    wh_Client_Cleanup(client);
    wh_Server_Cleanup(server);
    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wc_CryptoCb_UnRegisterDevice(WOLF_CALIPTRA_DEVID);
    wolfCrypt_Cleanup();
    caliptra_hwmodel_cleanup();

    return rc;
}

#endif /* WOLFHSM_CFG_TEST_CALIPTRA_HWMODEL && !WOLFHSM_CFG_NO_CRYPTO && WOLF_CRYPTO_CB */
