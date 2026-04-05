/* Licensed under the Apache-2.0 license */
/*
 * test/caliptra_if.h
 *
 * Test stub matching the public interface of libcaliptra/inc/caliptra_if.h.
 *
 * In a production build this header is provided by libcaliptra.  In the
 * wolfHSM test suite (CALIPTRA=1) the three functions declared here are
 * implemented by the in-memory mailbox shim in wh_test_caliptra_transport.c.
 *
 * The declarations are byte-for-byte identical to the upstream libcaliptra
 * header so that wh_transport_caliptra.c compiles against both without
 * modification.
 */
#ifndef CALIPTRA_IF_H
#define CALIPTRA_IF_H

#include <stdint.h>
#include <stdbool.h>

#define CALIPTRA_STATUS_OK 0

#ifdef __cplusplus
extern "C" {
#endif

/**
 * caliptra_write_u32
 *
 * Writes a uint32_t value to the specified address.
 *
 * @param[in] address  Memory address to write
 * @param[in] data     Data to write at address
 *
 * @return 0 if successful, non-zero on error
 */
int caliptra_write_u32(uint32_t address, uint32_t data);

/**
 * caliptra_read_u32
 *
 * Reads a uint32_t value from the specified address.
 *
 * @param[in]  address  Memory address to read
 * @param[out] data     Pointer to a uint32_t to store the data
 *
 * @return 0 if successful, non-zero on error
 */
int caliptra_read_u32(uint32_t address, uint32_t *data);

/**
 * caliptra_wait
 *
 * Pend the current operation (yield / delay).
 */
void caliptra_wait(void);

#ifdef __cplusplus
}
#endif

#endif /* CALIPTRA_IF_H */
