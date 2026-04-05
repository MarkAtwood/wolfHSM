/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * test/wh_test_caliptra_transport.h
 *
 * pthread-based integration test for the Caliptra mailbox transport
 * (port/caliptra/wh_transport_caliptra.c).
 *
 * Only available when WOLFHSM_CFG_TEST_CALIPTRA, WOLFHSM_CFG_TEST_POSIX,
 * WOLFHSM_CFG_ENABLE_CLIENT, and WOLFHSM_CFG_ENABLE_SERVER are all defined.
 * Enable by building with CALIPTRA=1 in the test/ Makefile.
 */

#ifndef TEST_WH_TEST_CALIPTRA_TRANSPORT_H_
#define TEST_WH_TEST_CALIPTRA_TRANSPORT_H_

/*
 * Runs the Caliptra transport test using a two-thread POSIX harness:
 *   - one thread acts as the wolfHSM client driving MMIO over the simulated
 *     mailbox FIFO registers
 *   - one thread acts as the Caliptra runtime firmware, polling for commands
 *     and driving the wolfHSM server via ServerSetRequest/ServerGetResponse
 *
 * Returns 0 on success, non-zero on failure.
 */
int whTest_CaliptraTransport(void);

#endif /* TEST_WH_TEST_CALIPTRA_TRANSPORT_H_ */
