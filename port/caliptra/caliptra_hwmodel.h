/* Licensed under the Apache-2.0 license */
/*
 * port/caliptra/caliptra_hwmodel.h
 *
 * Caliptra hw-model backend for the wolfHSM Caliptra integration test.
 *
 * Declares the lifecycle functions that must be called before and after
 * using the Caliptra mailbox transport via caliptra_mailbox_exec().
 *
 * Typical usage:
 *
 *   caliptra_hwmodel_init(ROM_PATH, FW_PATH);
 *   wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
 *   ... run wolfSSL / wolfHSM operations ...
 *   caliptra_hwmodel_cleanup();
 *
 * This file is test/simulation support only; it is NOT part of the wolfHSM
 * library and is not compiled in production builds.
 *
 * Build-time dependencies (set via Makefile -I and -L flags):
 *   caliptra_model.h     — ~/caliptra/hw-model/c-binding/out/
 *   caliptra_top_reg.h   — port/caliptra/ (this directory)
 *   libcaliptra_hw_model_c_binding.a — ~/caliptra/target/debug/
 */

#ifndef WOLFHSM_PORT_CALIPTRA_HWMODEL_H_
#define WOLFHSM_PORT_CALIPTRA_HWMODEL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * caliptra_hwmodel_init
 *
 * Boot the Caliptra hw-model emulator.
 *
 * Loads ROM from rom_path, firmware from fw_path, initialises the hw-model,
 * writes zero fuses (debug/unprovisioned mode), releases boot FSM, uploads
 * firmware, and steps the model until the runtime is ready to accept
 * cryptographic mailbox commands (boot status 0x600).
 *
 * Returns 0 on success, negative errno on failure.
 * Calling init when already initialised returns -EALREADY.
 */
int caliptra_hwmodel_init(const char *rom_path, const char *fw_path);

/*
 * caliptra_hwmodel_cleanup
 *
 * Destroy the hw-model and release all resources.
 * Safe to call if init was never called or already failed.
 */
void caliptra_hwmodel_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFHSM_PORT_CALIPTRA_HWMODEL_H_ */
