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
 * test/wh_test_caliptra_transport.c
 *
 * pthread-based integration test for port/caliptra/wh_transport_caliptra.c.
 *
 * Overview
 * --------
 * This file provides two things:
 *
 *   1. An in-memory model of the Caliptra mailbox hardware (the "MMIO shim").
 *      The shim implements caliptra_read_u32() and caliptra_write_u32() from
 *      caliptra_if.h (libcaliptra's platform interface) using a mutex-protected
 *      struct that mimics the LOCK, CMD, DLEN, DATAIN FIFO, DATAOUT FIFO,
 *      EXECUTE, and STATUS registers.
 *
 *   2. A two-thread test harness:
 *        Client thread  – wolfHSM client wired to WH_TRANSPORT_CALIPTRA_CLIENT_CB;
 *                         runs whTest_ClientServerClientConfig to exercise echo,
 *                         NVM, and (if enabled) crypto operations.
 *        Firmware thread – simulates the Caliptra RISC-V runtime; waits for
 *                         EXECUTE=1, reads the DATAIN FIFO payload, injects it
 *                         via wh_TransportCaliptra_ServerSetRequest, drives
 *                         wh_Server_HandleRequestMessage, retrieves the response
 *                         via wh_TransportCaliptra_ServerGetResponse, and writes
 *                         it to the DATAOUT FIFO before setting STATUS.
 *
 * Hardware model
 * --------------
 * The shim models the Caliptra mailbox CSR block as documented in the Caliptra
 * hardware specification and reflected in libcaliptra/src/caliptra_mbox.h.
 * Register offsets are taken directly from wh_transport_caliptra.h (WH_CALIPTRA_REG_*).
 *
 *   LOCK     read → atomic test-and-set: returns 0 if acquired, 1 if busy
 *   CMD      write → stores the command ID
 *   DLEN     read/write → data length in bytes
 *   DATAIN   write → appends 4 bytes to the DATAIN FIFO buffer
 *   DATAOUT  read  → reads 4 bytes from the DATAOUT FIFO buffer
 *   EXECUTE  write 1 → signals firmware (sets req_ready, signals req_cond)
 *            write 0 → releases mailbox (clears locked)
 *   STATUS   read  → returns current status (BUSY / DATA_READY / CMD_COMPLETE /
 *                    CMD_FAILURE)
 *   UNLOCK   write → no-op (SoC-read-only on real hardware; SoC writes ignored)
 *
 * Synchronisation
 * ---------------
 * All register accesses hold s_mbox.mutex.  The firmware thread blocks on
 * s_mbox.req_cond until req_ready becomes non-zero.  The DATAIN buffer is
 * protected by the same mutex; because the client writes all DATAIN words
 * before signalling EXECUTE=1 (while holding the mutex for each word), the
 * firmware thread always observes a complete payload after it wakes.
 *
 * Compile-time guards
 * -------------------
 * The entire file is conditionally compiled.  All four guards must be set:
 *   WOLFHSM_CFG_TEST_CALIPTRA   – set by the Makefile when CALIPTRA=1
 *   WOLFHSM_CFG_TEST_POSIX      – POSIX threading available
 *   WOLFHSM_CFG_ENABLE_CLIENT   – client transport is compiled in
 *   WOLFHSM_CFG_ENABLE_SERVER   – server transport is compiled in
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_TEST_CALIPTRA) && \
    defined(WOLFHSM_CFG_TEST_POSIX)    && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>    /* sched_yield() used in caliptra_wait() */
#include <pthread.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"


#include "port/caliptra/wh_transport_caliptra.h"

#include "wh_test_common.h"
#include "wh_test_clientserver.h"
#include "wh_test_caliptra_transport.h"

/* =========================================================================
 * Test configuration
 * ========================================================================= */

#define FLASH_RAM_SIZE    (1024 * 1024) /* 1 MB */
#define FLASH_SECTOR_SIZE (128 * 1024)  /* 128 KB */
#define FLASH_PAGE_SIZE   (8)           /* 8 bytes */


/* =========================================================================
 * In-memory Caliptra mailbox hardware model (MMIO shim)
 *
 * Shared between the SoC client (which accesses it via caliptra_read_u32 /
 * caliptra_write_u32) and the Caliptra firmware thread (which accesses the
 * FIFO buffers directly, simulating memory-mapped SRAM access).
 *
 * All fields are protected by mutex.  The firmware thread blocks on req_cond
 * until req_ready becomes non-zero, then clears it before processing.
 * ========================================================================= */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t  req_cond;   /* signalled: req_ready 0→1              */

    uint32_t mbox_base;         /* absolute base for address decoding     */
    uint32_t locked;            /* 0 = free, 1 = held by SoC             */
    uint32_t cmd;               /* CMD register                          */
    uint32_t dlen;              /* DLEN register (request or response)   */
    uint32_t execute;           /* EXECUTE register                      */
    uint32_t status;            /* STATUS register                       */
    int      req_ready;         /* 1: firmware should process; 0: idle   */

    /* DATAIN FIFO — client appends 4-byte words here via Write(DATAIN).
     * The firmware thread copies the completed payload out of this buffer
     * after waking, then resets datain_pos for the next transaction.
     * +4: one extra word of headroom for the partial-word write that
     * caliptra_fifo_write emits when (WH_COMM_MTU & 3) != 0.            */
    uint8_t  datain_buf[WH_COMM_MTU + 4];
    uint32_t datain_pos;        /* next write offset (bytes)             */

    /* DATAOUT FIFO — firmware thread writes the response payload here.
     * The client reads 4-byte words via Read(DATAOUT), advancing
     * dataout_pos each time.
     * +4: same partial-word headroom as datain_buf (see above).
     *
     * dataout_data_len tracks how many bytes were actually written by the
     * firmware for the current response.  The DATAOUT underflow guard uses
     * this watermark — not sizeof(dataout_buf) — so that reads beyond the
     * valid data return 0 rather than stale buffer contents.             */
    uint8_t  dataout_buf[WH_COMM_MTU + 4];
    uint32_t dataout_pos;       /* next read offset (bytes)              */
    uint32_t dataout_data_len;  /* bytes written for current response    */
} CaliptraMboxShim;

/* Single mailbox instance; caliptra_read_u32/write_u32 have no context
 * parameter, so the shim state must be file-global.                      */
static CaliptraMboxShim s_mbox;

/* Initialise the global shim.  Must be called before the test threads
 * are created.                                                           */
static int caliptra_mbox_sim_init(uint32_t mbox_base)
{
    int rc;

    memset(&s_mbox, 0, sizeof(s_mbox));
    s_mbox.mbox_base = mbox_base;
    /* WH_CALIPTRA_MBOX_ST_BUSY == 0, so memset already set this; the explicit
     * assignment documents that BUSY is the correct initial state. */
    s_mbox.status    = (uint32_t)WH_CALIPTRA_MBOX_ST_BUSY;

    rc = pthread_mutex_init(&s_mbox.mutex, NULL);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    rc = pthread_cond_init(&s_mbox.req_cond, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&s_mbox.mutex);
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

static void caliptra_mbox_sim_destroy(void)
{
    pthread_cond_destroy(&s_mbox.req_cond);
    pthread_mutex_destroy(&s_mbox.mutex);
    memset(&s_mbox, 0, sizeof(s_mbox));
}


/* =========================================================================
 * caliptra_if.h implementations (MMIO shim)
 *
 * These are the three symbols declared in test/caliptra_if.h (the test stub
 * for libcaliptra's platform interface).  wh_transport_caliptra.c includes
 * caliptra_if.h and calls these functions; here we redirect them into the
 * in-memory shim.
 *
 * All register accesses hold s_mbox.mutex for the duration of the access to
 * ensure ordering between the client thread and firmware thread.
 * ========================================================================= */

int caliptra_read_u32(uint32_t address, uint32_t *data)
{
    uint32_t offset;
    uint32_t word;

    if (data == NULL) {
        return -1;
    }

    pthread_mutex_lock(&s_mbox.mutex);

    offset = address - s_mbox.mbox_base;

    switch (offset) {

        case WH_CALIPTRA_REG_LOCK:
            /* Atomic hardware test-and-set: returns 0 (acquired) if the lock
             * was free, 1 (busy) if already held by another agent.          */
            if (s_mbox.locked == 0U) {
                s_mbox.locked = 1U;
                *data = 0U; /* lock acquired */
            } else {
                *data = WH_CALIPTRA_LOCK_MASK; /* lock is held */
            }
            break;

        case WH_CALIPTRA_REG_DLEN:
            *data = s_mbox.dlen;
            break;

        case WH_CALIPTRA_REG_DATAOUT:
            /* Each read dequeues the next 4-byte word from the DATAOUT FIFO.
             * Use dataout_data_len (bytes actually written by firmware) as the
             * bound to prevent reading stale bytes from a previous response.
             *
             * The check is "pos < data_len" (at least one valid byte remains),
             * not "pos + 4 <= data_len", to allow reading the last partial word
             * of a response whose byte count is not a multiple of 4.  The
             * caller knows the true byte count from the DLEN register and
             * discards the zero-padding bytes in the final word.
             *
             * The word is reconstructed by clipping copy_len to the remaining
             * buffer space; bytes beyond that are zero (padding positions).
             *
             * Case 2 LE contract: real Caliptra hardware returns DATAOUT words
             * as little-endian values — bit 0 of the returned uint32_t is the
             * first byte the firmware enqueued.  The shim rebuilds the word
             * from the raw bytes in dataout_buf using explicit LE shifts rather
             * than memcpy, so the returned value has the correct LE encoding
             * on both LE and BE hosts.  The transport's caliptra_fifo_read uses
             * symmetric LE shifts to extract the bytes, so the two sides are
             * consistent on all hosts.
             *
             * For an 8-byte response, reads beyond offset 8 still return 0. */
            if (s_mbox.dataout_pos < s_mbox.dataout_data_len) {
                uint32_t buf_remaining =
                    (uint32_t)sizeof(s_mbox.dataout_buf) - s_mbox.dataout_pos;
                uint32_t copy_len = (buf_remaining >= 4U) ? 4U : buf_remaining;
                /* Build LE word from raw bytes; unread positions are zero. */
                word = 0U;
                if (copy_len >= 1U) {
                    word |= (uint32_t)s_mbox.dataout_buf[s_mbox.dataout_pos];
                }
                if (copy_len >= 2U) {
                    word |= (uint32_t)s_mbox.dataout_buf[s_mbox.dataout_pos + 1U] << 8;
                }
                if (copy_len >= 3U) {
                    word |= (uint32_t)s_mbox.dataout_buf[s_mbox.dataout_pos + 2U] << 16;
                }
                if (copy_len >= 4U) {
                    word |= (uint32_t)s_mbox.dataout_buf[s_mbox.dataout_pos + 3U] << 24;
                }
                s_mbox.dataout_pos += 4U;
                *data = word;
            } else {
                /* FIFO underflow or read beyond valid data: return 0 */
                *data = 0U;
            }
            break;

        case WH_CALIPTRA_REG_EXECUTE:
            *data = s_mbox.execute;
            break;

        case WH_CALIPTRA_REG_STATUS:
            *data = s_mbox.status & WH_CALIPTRA_STATUS_MASK;
            break;

        default:
            /* Unknown register — return 0 and succeed (mirrors real hardware
             * which returns 0 for unimplemented read-only registers).        */
            *data = 0U;
            break;
    }

    pthread_mutex_unlock(&s_mbox.mutex);
    return 0; /* CALIPTRA_STATUS_OK */
}

int caliptra_write_u32(uint32_t address, uint32_t data)
{
    uint32_t offset;

    pthread_mutex_lock(&s_mbox.mutex);

    offset = address - s_mbox.mbox_base;

    switch (offset) {

        case WH_CALIPTRA_REG_CMD:
            s_mbox.cmd = data;
            break;

        case WH_CALIPTRA_REG_DLEN:
            s_mbox.dlen = data;
            break;

        case WH_CALIPTRA_REG_DATAIN:
            /* Each write enqueues a 4-byte word into the DATAIN FIFO.
             *
             * Overflow check uses the safe form "pos <= buf_size - 4" rather
             * than "pos + 4 <= buf_size": the latter overflows uint32_t when
             * pos is near UINT32_MAX, falsely accepting the write.  Since
             * sizeof(datain_buf) >= 4 always holds (the buffer is WH_COMM_MTU+4
             * bytes), the subtraction cannot underflow.
             *
             * Case 2 LE contract: real Caliptra hardware stores DATAIN words
             * in little-endian byte order regardless of SoC host endianness
             * (the platform HAL byte-swaps before the MMIO store on BE SoCs).
             * The shim mimics this by writing each byte explicitly via shifts
             * rather than using memcpy, so the datain_buf byte sequence is
             * always the little-endian encoding of 'data'.  The transport's
             * caliptra_fifo_write constructs 'data' using symmetric LE shifts,
             * so the two sides are consistent on both LE and BE hosts.        */
            if (s_mbox.datain_pos <=
                    (uint32_t)sizeof(s_mbox.datain_buf) - 4U) {
                s_mbox.datain_buf[s_mbox.datain_pos]      = (uint8_t)(data);
                s_mbox.datain_buf[s_mbox.datain_pos + 1U] = (uint8_t)(data >> 8);
                s_mbox.datain_buf[s_mbox.datain_pos + 2U] = (uint8_t)(data >> 16);
                s_mbox.datain_buf[s_mbox.datain_pos + 3U] = (uint8_t)(data >> 24);
                s_mbox.datain_pos += 4U;
            }
            /* FIFO overflow silently dropped (mirrors hardware behaviour).   */
            break;

        case WH_CALIPTRA_REG_EXECUTE:
            if (data == 1U) {
                /* SoC is submitting a new command to Caliptra firmware.      */
                s_mbox.execute   = 1U;
                s_mbox.status    = (uint32_t)WH_CALIPTRA_MBOX_ST_BUSY;
                s_mbox.req_ready = 1;
                pthread_cond_signal(&s_mbox.req_cond);
            } else {
                /* SoC has finished reading the response; release the mailbox.
                 * Reset dataout_data_len so any spurious Read(DATAOUT) before
                 * the next transaction is set up returns 0, not stale bytes. */
                s_mbox.execute          = 0U;
                s_mbox.locked           = 0U;
                s_mbox.dataout_data_len = 0U;
            }
            break;

        case WH_CALIPTRA_REG_UNLOCK:
            /* WH_CALIPTRA_REG_UNLOCK (0x020) is SoC-read-only on real Caliptra
             * hardware; SoC writes are silently ignored by the hardware.  The
             * shim mirrors this behaviour: writes are accepted without error
             * but have no effect.  wh_transport_caliptra.c never writes to
             * this register (EXECUTE=0 is the correct release path), so this
             * case exists only to prevent caliptra_write_u32 from returning an
             * error for an address that falls within the mailbox CSR range. */
            break;

        default:
            /* Unknown register — silently ignore.                            */
            break;
    }

    pthread_mutex_unlock(&s_mbox.mutex);
    return 0; /* CALIPTRA_STATUS_OK */
}

void caliptra_wait(void)
{
    /* Provided to satisfy the caliptra_if.h symbol requirement.  The Caliptra
     * transport never calls this function — all polling is handled by returning
     * WH_ERROR_NOTREADY to the caller, which is responsible for pacing retries.
     * In a real SoC this would insert platform-specific delay cycles. */
    sched_yield();
}


/* =========================================================================
 * Caliptra firmware thread
 *
 * Simulates the Caliptra RISC-V runtime handling wolfHSM mailbox commands:
 *   1. Block until the SoC client writes EXECUTE=1.
 *   2. Snapshot CMD, DLEN, and the DATAIN FIFO payload from the shim.
 *   3. Verify CMD == WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID.
 *   4. Inject the payload via wh_TransportCaliptra_ServerSetRequest.
 *   5. Drive wh_Server_HandleRequestMessage until it returns != NOTREADY.
 *   6. Retrieve the response via wh_TransportCaliptra_ServerGetResponse.
 *   7. Write the response to the DATAOUT FIFO; set DLEN and STATUS.
 *   8. Repeat until the wolfHSM server signals WH_COMM_DISCONNECTED.
 * ========================================================================= */

typedef struct {
    whServerContext                  *server;
    whTransportCaliptraServerContext *transport_ctx;
    int                               stop_requested; /* set under s_mbox.mutex before
                                                       * signalling req_cond; read inside
                                                       * pthread_cond_wait loop which also
                                                       * holds s_mbox.mutex — all accesses
                                                       * are mutex-protected, so volatile
                                                       * is neither needed nor correct here */
} CaliptraFirmwareArg;

static void* _caliptraFirmwareTask(void *arg)
{
    CaliptraFirmwareArg *farg = (CaliptraFirmwareArg*)arg;
    whServerContext                  *server        = farg->server;
    whTransportCaliptraServerContext *transport_ctx = farg->transport_ctx;

    uint8_t          req_buf[WH_COMM_MTU];
    uint8_t          resp_buf[WH_COMM_MTU];
    uint16_t         resp_size;
    uint32_t         local_cmd;
    uint32_t         local_dlen;
    whCommConnected  connected;
    int              rc;

    for (;;) {
        /* ------------------------------------------------------------------
         * 1. Wait for the SoC to write EXECUTE=1.
         * ------------------------------------------------------------------ */
        pthread_mutex_lock(&s_mbox.mutex);

        while (s_mbox.req_ready == 0 && !farg->stop_requested) {
            pthread_cond_wait(&s_mbox.req_cond, &s_mbox.mutex);
        }

        if (farg->stop_requested) {
            pthread_mutex_unlock(&s_mbox.mutex);
            break;
        }

        /* Consume the request signal before releasing the mutex so the
         * firmware cannot accidentally re-enter the same request.          */
        s_mbox.req_ready = 0;

        /* ------------------------------------------------------------------
         * 2. Snapshot the request from the shim (simulates Caliptra firmware
         *    reading from its internal SRAM view of the mailbox).
         * ------------------------------------------------------------------ */
        local_cmd  = s_mbox.cmd;
        local_dlen = s_mbox.dlen;

        if (local_dlen > (uint32_t)WH_COMM_MTU) {
            WH_ERROR_PRINT("[firmware] DLEN %u exceeds MTU\n",
                           (unsigned int)local_dlen);
            s_mbox.datain_pos = 0U;
            s_mbox.status     = (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE;
            pthread_mutex_unlock(&s_mbox.mutex);
            rc = wh_Server_GetConnected(server, &connected);
            if (rc != WH_ERROR_OK || connected != WH_COMM_CONNECTED) {
                break;
            }
            continue;
        }
        memcpy(req_buf, s_mbox.datain_buf, local_dlen);

        /* Reset DATAIN write pointer for the next transaction.             */
        s_mbox.datain_pos = 0U;

        pthread_mutex_unlock(&s_mbox.mutex);

        /* ------------------------------------------------------------------
         * 3. Validate command ID.
         * ------------------------------------------------------------------ */
        if (local_cmd != WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID) {
            WH_ERROR_PRINT("[firmware] Unknown CMD 0x%08X\n",
                           (unsigned int)local_cmd);
            pthread_mutex_lock(&s_mbox.mutex);
            s_mbox.status = (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE;
            pthread_mutex_unlock(&s_mbox.mutex);
            rc = wh_Server_GetConnected(server, &connected);
            if (rc != WH_ERROR_OK || connected != WH_COMM_CONNECTED) {
                break;
            }
            continue;
        }

        /* ------------------------------------------------------------------
         * 4. Inject the request into the wolfHSM server transport.
         * ------------------------------------------------------------------ */
        /* safe: local_dlen <= WH_COMM_MTU <= UINT16_MAX after the overflow check above */
        rc = wh_TransportCaliptra_ServerSetRequest(transport_ctx,
                                                   req_buf,
                                                   (uint16_t)local_dlen);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("[firmware] ServerSetRequest failed: %d\n", rc);
            pthread_mutex_lock(&s_mbox.mutex);
            s_mbox.status = (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE;
            pthread_mutex_unlock(&s_mbox.mutex);
            rc = wh_Server_GetConnected(server, &connected);
            if (rc != WH_ERROR_OK || connected != WH_COMM_CONNECTED) {
                break;
            }
            continue;
        }

        /* ------------------------------------------------------------------
         * 5. Drive the wolfHSM server until the request is fully processed.
         *    A single call normally suffices; loop defensively on NOTREADY.
         * ------------------------------------------------------------------ */
        do {
            rc = wh_Server_HandleRequestMessage(server);
        } while (rc == WH_ERROR_NOTREADY);

        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("[firmware] HandleRequestMessage failed: %d\n", rc);
            pthread_mutex_lock(&s_mbox.mutex);
            s_mbox.status = (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE;
            pthread_mutex_unlock(&s_mbox.mutex);
            rc = wh_Server_GetConnected(server, &connected);
            if (rc != WH_ERROR_OK || connected != WH_COMM_CONNECTED) {
                break;
            }
            continue;
        }
        /* HandleRequestMessage succeeded; retrieve and forward the response.
         * (The failure branch above always continues/breaks, so no else needed.) */

        /* ------------------------------------------------------------------
         * 6. Retrieve the wolfHSM response.
         * ------------------------------------------------------------------ */
        resp_size = 0U;
        rc = wh_TransportCaliptra_ServerGetResponse(transport_ctx,
                                                    resp_buf,
                                                    &resp_size);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("[firmware] ServerGetResponse failed: %d\n", rc);
            pthread_mutex_lock(&s_mbox.mutex);
            s_mbox.status = (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE;
            pthread_mutex_unlock(&s_mbox.mutex);
        } else {
            /* ------------------------------------------------------------------
             * 7. Write response to DATAOUT and signal the SoC.
             *    Simulates the Caliptra firmware writing its SRAM output and
             *    asserting DATA_READY via a firmware register write.
             * ------------------------------------------------------------------ */
            pthread_mutex_lock(&s_mbox.mutex);

            if (resp_size > 0U) {
                memcpy(s_mbox.dataout_buf, resp_buf, resp_size);
                s_mbox.dataout_pos      = 0U;
                s_mbox.dataout_data_len = (uint32_t)resp_size;
                s_mbox.dlen             = (uint32_t)resp_size;
                s_mbox.status           = (uint32_t)WH_CALIPTRA_MBOX_ST_DATA_READY;
            } else {
                s_mbox.dataout_pos      = 0U;
                s_mbox.dataout_data_len = 0U;
                s_mbox.dlen             = 0U;
                s_mbox.status           = (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_COMPLETE;
            }

            pthread_mutex_unlock(&s_mbox.mutex);
        }

        /* ------------------------------------------------------------------
         * 8. Exit when the wolfHSM server has been disconnected (CommClose).
         * ------------------------------------------------------------------ */
        rc = wh_Server_GetConnected(server, &connected);
        if (rc != WH_ERROR_OK || connected != WH_COMM_CONNECTED) {
            break;
        }
    }

    return NULL;
}


/* =========================================================================
 * Fault-injection helpers for error-path tests (wolfHSM-3k8)
 *
 * These bypass the client transport layer and inject requests directly into
 * the MMIO shim, allowing each firmware error branch to be triggered
 * deterministically.
 * ========================================================================= */

/** Inject one request directly into the MMIO shim.
 *
 *  Bypasses the client transport layer: sets CMD, DLEN, and the DATAIN buffer
 *  directly, then signals req_ready.  Polls until STATUS transitions away from
 *  BUSY and returns the resulting STATUS value.
 *
 *  @param cmd     Mailbox CMD register value.
 *  @param dlen    DLEN register value (bytes).
 *  @param datain  Request payload; may be NULL when dlen == 0.
 *
 *  @return STATUS register value after firmware finishes processing. */
/* Maximum poll iterations in inject_request_and_get_status before the
 * firmware thread is declared stalled.  10 million iterations at a
 * sched_yield() per iteration is generous enough to survive heavy
 * scheduling jitter while still catching a crashed firmware thread in a
 * bounded time instead of hanging the test suite indefinitely. */
#define INJECT_POLL_MAX_ITERS (10000000U)

static uint32_t inject_request_and_get_status(
        uint32_t cmd, uint32_t dlen, const uint8_t *datain)
{
    uint32_t status;
    uint32_t iters = 0U;

    pthread_mutex_lock(&s_mbox.mutex);
    s_mbox.cmd        = cmd;
    s_mbox.dlen       = dlen;
    s_mbox.datain_pos = 0U;
    if (datain != NULL && dlen > 0U && dlen <= (uint32_t)WH_COMM_MTU) {
        memcpy(s_mbox.datain_buf, datain, dlen);
    }
    s_mbox.locked    = 1U;
    s_mbox.execute   = 1U;
    s_mbox.status    = (uint32_t)WH_CALIPTRA_MBOX_ST_BUSY;
    s_mbox.req_ready = 1;
    pthread_cond_signal(&s_mbox.req_cond);
    pthread_mutex_unlock(&s_mbox.mutex);

    /* Poll until STATUS transitions away from BUSY (firmware has finished
     * processing and set STATUS to a terminal value).
     *
     * The loop is bounded: if the firmware thread stalls or crashes, the
     * test aborts with a clear message rather than hanging indefinitely. */
    do {
        sched_yield();
        pthread_mutex_lock(&s_mbox.mutex);
        status = s_mbox.status;
        pthread_mutex_unlock(&s_mbox.mutex);
        iters++;
    } while (status == (uint32_t)WH_CALIPTRA_MBOX_ST_BUSY &&
             iters < INJECT_POLL_MAX_ITERS);

    WH_TEST_ASSERT_MSG(iters < INJECT_POLL_MAX_ITERS,
        "firmware stalled: STATUS still BUSY after %u poll iterations",
        INJECT_POLL_MAX_ITERS);

    return status;
}

/** Simulate the SoC client writing EXECUTE=0 to release the mailbox after
 *  reading STATUS=CMD_FAILURE.  Must be called after every
 *  inject_request_and_get_status() to restore the mailbox to idle state.
 *
 *  This helper bypasses caliptra_write_u32 and writes directly to the shim
 *  struct.  It must also reset dataout_data_len so that any spurious
 *  Read(DATAOUT) before the next transaction returns 0, not stale bytes. */
static void release_mailbox_after_error(void)
{
    pthread_mutex_lock(&s_mbox.mutex);
    s_mbox.execute          = 0U;
    s_mbox.locked           = 0U;
    s_mbox.dataout_data_len = 0U;
    pthread_mutex_unlock(&s_mbox.mutex);
}

/** Drain a pending wolfHSM server request that was left un-served by an error
 *  path test.  Sends a zero-byte response (which clears req_pending) then
 *  discards the response via GetResponse, leaving the transport context clean.
 *
 *  This is necessary when HandleRequestMessage fails before reaching ServerSend,
 *  because ServerRecv does not clear req_pending.
 *
 *  Precondition: ctx->req_pending == 1 and ctx is initialized.  Both calls
 *  must succeed; failure indicates a bug in the test setup, not the transport. */
static void drain_pending_server_request(
        whTransportCaliptraServerContext *ctx)
{
    uint8_t  buf[WH_COMM_MTU];
    uint16_t sz  = 0U;
    int      rc;

    /* ServerSend(size=0, data=NULL) is valid: the NULL-data guard only fires
     * when size > 0.  req_pending must be 1 at this call site (precondition). */
    rc = wh_TransportCaliptra_ServerSend(ctx, 0U, NULL);
    WH_TEST_ASSERT_MSG(rc == WH_ERROR_OK,
        "drain_pending_server_request: ServerSend failed: %d", rc);

    /* GetResponse with data=NULL is valid when resp_size==0, which is always
     * the case after a zero-byte Send.  Pass a real buffer anyway so that an
     * unexpected non-zero resp_size triggers a write to a valid destination
     * rather than a NULL dereference. */
    rc = wh_TransportCaliptra_ServerGetResponse(ctx, buf, &sz);
    WH_TEST_ASSERT_MSG(rc == WH_ERROR_OK,
        "drain_pending_server_request: ServerGetResponse failed: %d", rc);
    WH_TEST_ASSERT_MSG(sz == 0U,
        "drain_pending_server_request: expected resp_size==0, got %u",
        (unsigned)sz);
}


/* =========================================================================
 * Client thread
 * ========================================================================= */

static void* _caliptraClientTask(void *cf)
{
    WH_TEST_ASSERT(0 == whTest_ClientServerClientConfig((whClientConfig*)cf));
    return NULL;
}


/* =========================================================================
 * Test entry point
 * ========================================================================= */

int whTest_CaliptraTransport(void)
{
    int rc = WH_ERROR_OK;
#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Guards for cleanup: wolfCrypt uses a reference count; calling
     * wolfCrypt_Cleanup() without a matching wolfCrypt_Init() decrements the
     * count to -1, corrupting it for subsequent calls.  wc_FreeRng on a
     * zero-initialized WC_RNG (by value) has implementation-defined behaviour.
     * Only call each cleanup function if its matching init succeeded. */
    int wolfcrypt_initialized = 0;
    int rng_initialized       = 0;
#endif

    /* -----------------------------------------------------------------------
     * Flash / NVM setup (same parameters as wh_ClientServer_MemThreadTest)
     * --------------------------------------------------------------------- */
    static uint8_t         s_flash_mem[FLASH_RAM_SIZE]; /* static: 1 MB; avoids stack allocation */
    whFlashRamsimCtx       fc[1]     = {{0}};
    whFlashRamsimCfg       fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = (uint8_t)0xFF,
        .memory     = s_flash_mem,
    }};
    const whFlashCb        fcb[1]    = {WH_FLASH_RAMSIM_CB};
    whTestNvmBackendUnion  nvm_setup;
    whNvmConfig            n_conf[1] = {{0}};
    whNvmContext           nvm[1]    = {0};

    /* -----------------------------------------------------------------------
     * Server-side Caliptra transport
     * --------------------------------------------------------------------- */
    whTransportCaliptraConfig        srv_caliptra_cfg[1] = {{
        /* mbox_base=0 → use WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE default */
        .mbox_base = 0,
        .cmd_id    = 0,
    }};
    whTransportCaliptraServerContext srv_transport_ctx[1] = {0};
    whTransportServerCb              srv_transport_cb[1]  =
        {WH_TRANSPORT_CALIPTRA_SERVER_CB};
    whCommServerConfig               cs_conf[1] = {{
        .transport_cb      = srv_transport_cb,
        .transport_context = (void*)srv_transport_ctx,
        .transport_config  = (void*)srv_caliptra_cfg,
        .server_id         = 42, /* arbitrary; server_id and client_id are independent identifiers */
    }};

#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1] = {0};
#endif

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
#endif
    }};

    whServerContext server[1] = {0};

    /* -----------------------------------------------------------------------
     * Client-side Caliptra transport
     * --------------------------------------------------------------------- */
    whTransportCaliptraConfig        cli_caliptra_cfg[1] = {{
        .mbox_base = 0,
        .cmd_id    = 0,
    }};
    whTransportCaliptraClientContext cli_transport_ctx[1] = {0};
    whTransportClientCb              cli_transport_cb[1]  =
        {WH_TRANSPORT_CALIPTRA_CLIENT_CB};
    whCommClientConfig               cc_conf[1] = {{
        .transport_cb      = cli_transport_cb,
        .transport_context = (void*)cli_transport_ctx,
        .transport_config  = (void*)cli_caliptra_cfg,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientConfig c_conf[1] = {{
        .comm = cc_conf,
    }};

    /* -----------------------------------------------------------------------
     * Thread handles
     * --------------------------------------------------------------------- */
    pthread_t            firmware_thread = 0; /* not yet created */
    pthread_t            client_thread   = 0;
    CaliptraFirmwareArg  firmware_arg    = {
        .server         = server,
        .transport_ctx  = srv_transport_ctx,
        .stop_requested = 0,
    };

    WH_TEST_PRINT("Testing comms: (pthread) Caliptra transport...\n");

    /* -----------------------------------------------------------------------
     * Initialise the MMIO shim.  The default mbox_base matches what the
     * transport will use (WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE).
     *
     * This is the only init step that may return early without cleanup:
     * nothing has been allocated yet, so no cleanup is needed on failure.
     * All subsequent init failures must go to cleanup_server so that the
     * shim's pthread_mutex_t and pthread_cond_t are properly destroyed.
     * --------------------------------------------------------------------- */
    WH_TEST_RETURN_ON_FAIL(
        caliptra_mbox_sim_init(WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE));

    /* -----------------------------------------------------------------------
     * Initialise NVM and wolfCrypt.
     *
     * From here on, use goto cleanup_server on failure so caliptra_mbox_sim_destroy
     * is always called.  WH_TEST_RETURN_ON_FAIL would bypass it.
     * --------------------------------------------------------------------- */
    rc = whTest_NvmCfgBackend(WH_NVM_TEST_BACKEND_FLASH,
                              &nvm_setup, n_conf, fc_conf, fc, fcb);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("whTest_NvmCfgBackend: rc=%d\n", rc);
        goto cleanup_server;
    }

    rc = wh_Nvm_Init(nvm, n_conf);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("wh_Nvm_Init: rc=%d\n", rc);
        goto cleanup_server;
    }

#ifndef WOLFHSM_CFG_NO_CRYPTO
    rc = wolfCrypt_Init();
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("wolfCrypt_Init: rc=%d\n", rc);
        goto cleanup_server;
    }
    wolfcrypt_initialized = 1;

    rc = wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("wc_InitRng_ex: rc=%d\n", rc);
        goto cleanup_server;
    }
    rng_initialized = 1;
#endif

    /* -----------------------------------------------------------------------
     * Initialise the wolfHSM server.  The Caliptra server transport's Init
     * calls connectcb with WH_COMM_CONNECTED; we also call SetConnected
     * explicitly to match the pattern used by whTest_ServerCfgLoop.
     * --------------------------------------------------------------------- */
    rc = wh_Server_Init(server, s_conf);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("wh_Server_Init: rc=%d\n", rc);
        goto cleanup_server;
    }

    rc = wh_Server_SetConnected(server, WH_COMM_CONNECTED);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("wh_Server_SetConnected: rc=%d\n", rc);
        goto cleanup_server;
    }

    /* -----------------------------------------------------------------------
     * Unit tests: ServerSend argument validation (wolfHSM-tsd)
     *
     * These run single-threaded before the thread test so that any failure
     * is isolated and deterministic.  They verify the NULL-data guard added
     * to wh_TransportCaliptra_ServerSend.
     * --------------------------------------------------------------------- */
    {
        int rc_unit;
        uint8_t dummy[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        /* Case 1: size > 0 with NULL data must return BADARGS regardless of
         *         transport state.  Without the guard, resp_size would be set
         *         to a nonzero value while resp_buf is left stale. */
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx, 5, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSend(5, NULL) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 2: size == 0 with NULL data and req_pending == 0.
         *         The NULL-data guard (size > 0 && data == NULL) does not fire
         *         because size is 0.  The req_pending guard fires first and
         *         must return NOTREADY, not BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx, 0, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_NOTREADY,
            "ServerSend(0, NULL, req_pending=0) expected NOTREADY(%d), got %d",
            WH_ERROR_NOTREADY, rc_unit);

        /* Case 3: NULL context must always return BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerSend(NULL, 5, dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSend(NULL ctx) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 4a: size > MTU must return BADARGS even when req_pending==0.
         *          The MTU check precedes the req_pending check, so oversized
         *          payloads are unconditionally invalid regardless of state. */
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx,
                                                  (uint16_t)(WH_COMM_MTU + 1U),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSend(MTU+1, req_pending=0) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 4b: size > MTU also returns BADARGS when req_pending==1, and
         *          the BADARGS rejection must preserve req_pending so that a
         *          subsequent valid Send succeeds.  Set req_pending=1 via
         *          SetRequest to verify this postcondition. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(srv_transport_ctx,
                                                        dummy, sizeof(dummy));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerSetRequest(setup for 4b) expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx,
                                                  (uint16_t)(WH_COMM_MTU + 1U),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSend(MTU+1, req_pending=1) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 5: A BADARGS rejection must preserve req_pending so that a
         *         subsequent valid Send still succeeds.  Send(0, NULL) is
         *         valid (size == 0 skips the NULL-data guard), so the return
         *         must be WH_ERROR_OK — not just "not BADARGS". */
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx, 0, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "After failed Send, valid Send(0,NULL) expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        /* Consume the pending response so the context is clean for the
         * thread test below. */
        {
            uint8_t  resp_buf[WH_COMM_MTU];
            uint16_t resp_size = 0U;
            rc_unit = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                             resp_buf,
                                                             &resp_size);
            WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
                "GetResponse cleanup expected OK(%d), got %d",
                WH_ERROR_OK, rc_unit);
        }

        WH_TEST_PRINT("  ServerSend argument-validation unit tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit test: ServerRecv NULL-data rejection (wolfHSM-tf7)
     *
     * wh_TransportCaliptra_ServerRecv must return WH_ERROR_BADARGS if the
     * caller passes data==NULL when req_size > 0.  Without this guard,
     * *out_size would be set to a non-zero value while no bytes were copied,
     * and the caller would process garbage as a valid request.
     *
     * Postconditions checked:
     *   a) Returns BADARGS.
     *   b) *out_size is not written (sentinel preserved).
     *   c) req_pending remains 1 (a retry with a valid buffer succeeds).
     *   d) The retry itself returns OK and copies the correct bytes.
     * --------------------------------------------------------------------- */
    {
        uint8_t  req_data[8] = {0x10, 0x20, 0x30, 0x40,
                                 0x50, 0x60, 0x70, 0x80};
        uint8_t  recv_buf[8];
        uint16_t out_size = 0xFFFFU; /* sentinel: must not be written on BADARGS */
        int      rc_unit;

        /* Inject a request so req_pending == 1 and req_size == 8. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(srv_transport_ctx,
                                                        req_data,
                                                        sizeof(req_data));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerRecv test: SetRequest expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);

        /* Postcondition (a): NULL data with req_size > 0 → BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerRecv(srv_transport_ctx,
                                                  &out_size, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerRecv(data=NULL, req_size=8): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Postcondition (b): *out_size must not have been written. */
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "ServerRecv(data=NULL): out_size must not be written, got 0x%04X",
            (unsigned)out_size);

        /* Postcondition (c): req_pending must still be 1 so caller can retry.
         *                    Verify by calling Recv again with a valid buffer. */
        memset(recv_buf, 0, sizeof(recv_buf));
        out_size = 0U;
        rc_unit = wh_TransportCaliptra_ServerRecv(srv_transport_ctx,
                                                  &out_size, recv_buf);
        /* Postcondition (d): retry with valid buffer must succeed. */
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerRecv(retry with valid buf): expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == (uint16_t)sizeof(req_data),
            "ServerRecv(retry): out_size expected %u, got %u",
            (unsigned)sizeof(req_data), (unsigned)out_size);
        WH_TEST_ASSERT_MSG(memcmp(recv_buf, req_data, sizeof(req_data)) == 0,
            "ServerRecv(retry): received bytes do not match injected request");

        /* Clean up: ServerSend clears req_pending; GetResponse consumes resp. */
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx, 0U, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerRecv test cleanup ServerSend: expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        {
            uint8_t  resp_buf[WH_COMM_MTU];
            uint16_t resp_size = 0U;
            rc_unit = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                             resp_buf,
                                                             &resp_size);
            WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
                "ServerRecv test cleanup GetResponse: expected OK(%d), got %d",
                WH_ERROR_OK, rc_unit);
        }

        WH_TEST_PRINT("  ServerRecv NULL-data rejection unit test: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit test: ServerGetResponse NULL data accepted for zero-byte response
     *            (wolfHSM-btu)
     *
     * wh_TransportCaliptra_ServerGetResponse must accept data==NULL when
     * resp_size is 0 (the CMD_COMPLETE / no-payload case), matching the
     * ClientRecv pattern where data==NULL is only rejected when dlen>0.
     *
     * Cases verified:
     *   a) ctx==NULL              → BADARGS  (basic guard still works)
     *   b) out_size==NULL         → BADARGS  (out_size guard still works)
     *   c) data==NULL, resp_size==0 → WH_ERROR_OK, *out_size==0  (new behaviour)
     *   d) data==NULL, resp_size>0  → BADARGS  (guard fires when data needed)
     *   e) data!=NULL, resp_size>0  → WH_ERROR_OK, bytes copied  (regression)
     * --------------------------------------------------------------------- */
    {
        uint8_t  req_seed[8]  = {0xA1, 0xA2, 0xA3, 0xA4,
                                  0xA5, 0xA6, 0xA7, 0xA8};
        uint8_t  resp_payload[8] = {0xB1, 0xB2, 0xB3, 0xB4,
                                    0xB5, 0xB6, 0xB7, 0xB8};
        uint8_t  recv_buf[WH_COMM_MTU];
        uint16_t out_size;
        int      rc_unit;

        /* Case (a): NULL ctx must return BADARGS regardless of other args. */
        out_size = 0xFFFFU;
        rc_unit  = wh_TransportCaliptra_ServerGetResponse(NULL, recv_buf,
                                                          &out_size);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "GetResponse(NULL ctx): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "GetResponse(NULL ctx): out_size must not be written, got 0x%04X",
            (unsigned)out_size);

        /* Case (b): NULL out_size must return BADARGS regardless of other
         *           args.  out_size is always written on success, so NULL is
         *           never safe to ignore. */
        rc_unit = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                         recv_buf, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "GetResponse(NULL out_size): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case (c): data==NULL is OK when resp_size==0.
         *   Set up: inject a request, send a zero-byte response, then call
         *   GetResponse with data==NULL.  Postconditions:
         *     - returns WH_ERROR_OK
         *     - *out_size == 0
         *     - a second GetResponse call also returns OK with out_size==0
         *       (resp_size was consumed / reset on the first call) */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(srv_transport_ctx,
                                                        req_seed,
                                                        sizeof(req_seed));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse NULL-data setup SetRequest: expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx, 0U, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse NULL-data setup Send(0,NULL): expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);

        out_size = 0xFFFFU; /* sentinel */
        rc_unit  = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                          NULL, &out_size);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse(data=NULL, resp_size=0): expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0U,
            "GetResponse(data=NULL, resp_size=0): expected out_size=0, got %u",
            (unsigned)out_size);

        /* Second call: resp_size was consumed; must return OK with 0 again. */
        out_size = 0xFFFFU;
        rc_unit  = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                          NULL, &out_size);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse(data=NULL, 2nd call): expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0U,
            "GetResponse(data=NULL, 2nd call): expected out_size=0, got %u",
            (unsigned)out_size);

        /* Case (d): data==NULL with resp_size>0 must still return BADARGS.
         *   Set up a response with actual payload, then call with NULL data. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(srv_transport_ctx,
                                                        req_seed,
                                                        sizeof(req_seed));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse NULL-data case(d) SetRequest: expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        rc_unit = wh_TransportCaliptra_ServerSend(srv_transport_ctx,
                                                  (uint16_t)sizeof(resp_payload),
                                                  resp_payload);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse NULL-data case(d) Send: expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);

        out_size = 0xFFFFU;
        rc_unit  = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                          NULL, &out_size);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "GetResponse(data=NULL, resp_size=%u): expected BADARGS(%d), got %d",
            (unsigned)sizeof(resp_payload), WH_ERROR_BADARGS, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "GetResponse(data=NULL, resp_size>0): out_size must not be written, "
            "got 0x%04X", (unsigned)out_size);

        /* Case (e): regression — valid buffer with resp_size>0 must copy bytes.
         *   The BADARGS rejection in case(d) must not have consumed resp_size. */
        memset(recv_buf, 0, sizeof(recv_buf));
        out_size = 0U;
        rc_unit  = wh_TransportCaliptra_ServerGetResponse(srv_transport_ctx,
                                                          recv_buf, &out_size);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "GetResponse(data!=NULL, resp_size>0): expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == (uint16_t)sizeof(resp_payload),
            "GetResponse regression: expected out_size=%u, got %u",
            (unsigned)sizeof(resp_payload), (unsigned)out_size);
        WH_TEST_ASSERT_MSG(
            memcmp(recv_buf, resp_payload, sizeof(resp_payload)) == 0,
            "GetResponse regression: response bytes do not match sent payload");

        WH_TEST_PRINT(
            "  ServerGetResponse NULL-data zero-byte unit tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit tests: ServerSetRequest argument validation (wolfHSM-o7a)
     *
     * wh_TransportCaliptra_ServerSetRequest has five BADARGS entry guards and
     * one NOTREADY guard.  Only the req_pending/NOTREADY path is exercised by
     * the firmware error-path tests (wolfHSM-3k8); the BADARGS guards have no
     * coverage.  Add single-threaded unit tests for all guards.
     *
     * Guard order in ServerSetRequest:
     *   1. ctx == NULL                        → BADARGS
     *   2. !ctx->initialized                  → BADARGS
     *   3. data == NULL                       → BADARGS
     *   4. size == 0                          → BADARGS
     *   5. size > WH_COMM_MTU                 → BADARGS
     *   6. ctx->req_pending == 1              → NOTREADY
     * --------------------------------------------------------------------- */
    {
        whTransportCaliptraServerContext ss_ctx[1] = {0};
        whTransportCaliptraConfig        ss_cfg[1] = {{.mbox_base = 0,
                                                       .cmd_id    = 0}};
        uint8_t dummy[8] = {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8};
        int     rc_unit;

        /* Case 1: NULL ctx must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(NULL, dummy,
                                                        sizeof(dummy));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSetRequest(NULL ctx): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 2: zero-initialized (uninitialized) context. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(ss_ctx, dummy,
                                                        sizeof(dummy));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSetRequest(!initialized): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Initialize for the remaining cases. */
        rc_unit = wh_TransportCaliptra_ServerInit(ss_ctx, ss_cfg, NULL, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerInit for SetRequest tests failed: %d", rc_unit);

        /* Case 3: data == NULL must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(ss_ctx, NULL,
                                                        sizeof(dummy));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSetRequest(data=NULL): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 4: size == 0 must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(ss_ctx, dummy, 0U);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSetRequest(size=0): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 5: size > WH_COMM_MTU must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(
                ss_ctx, dummy, (uint16_t)(WH_COMM_MTU + 1U));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ServerSetRequest(size=MTU+1): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* All BADARGS rejections must leave req_pending == 0 so that a
         * subsequent valid SetRequest succeeds. */
        WH_TEST_ASSERT_MSG(ss_ctx->req_pending == 0,
            "ServerSetRequest BADARGS cases must leave req_pending==0, got %d",
            ss_ctx->req_pending);

        /* Case 6: NOTREADY when a previous exchange is still in progress.
         *         First SetRequest succeeds; second must return NOTREADY. */
        rc_unit = wh_TransportCaliptra_ServerSetRequest(ss_ctx, dummy,
                                                        sizeof(dummy));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerSetRequest(first, valid): expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        WH_TEST_ASSERT_MSG(ss_ctx->req_pending == 1,
            "ServerSetRequest(first): req_pending must be 1, got %d",
            ss_ctx->req_pending);

        rc_unit = wh_TransportCaliptra_ServerSetRequest(ss_ctx, dummy,
                                                        sizeof(dummy));
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_NOTREADY,
            "ServerSetRequest(req_pending=1): expected NOTREADY(%d), got %d",
            WH_ERROR_NOTREADY, rc_unit);
        /* req_pending must remain 1 — the in-flight exchange must not be
         * overwritten. */
        WH_TEST_ASSERT_MSG(ss_ctx->req_pending == 1,
            "ServerSetRequest(NOTREADY): req_pending must stay 1, got %d",
            ss_ctx->req_pending);

        /* Clean up the pending exchange before destroying the context. */
        rc_unit = wh_TransportCaliptra_ServerSend(ss_ctx, 0U, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ServerSetRequest cleanup Send: expected OK(%d), got %d",
            WH_ERROR_OK, rc_unit);
        {
            uint8_t  cleanup_buf[WH_COMM_MTU];
            uint16_t cleanup_sz = 0U;
            rc_unit = wh_TransportCaliptra_ServerGetResponse(ss_ctx,
                                                             cleanup_buf,
                                                             &cleanup_sz);
            WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
                "ServerSetRequest cleanup GetResponse: expected OK(%d), got %d",
                WH_ERROR_OK, rc_unit);
        }

        wh_TransportCaliptra_ServerCleanup(ss_ctx);

        WH_TEST_PRINT(
            "  ServerSetRequest argument-validation unit tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit tests: ClientSend argument validation (wolfHSM-lhk)
     *
     * Verify all five BADARGS entry guards in wh_TransportCaliptra_ClientSend
     * plus the two NOTREADY paths (state==PENDING, hardware lock held by
     * another agent).  Runs single-threaded before any thread is spawned.
     *
     * Guard order in ClientSend:
     *   1. ctx == NULL                              → BADARGS
     *   2. !ctx->initialized                        → BADARGS
     *   3. size == 0                                → BADARGS
     *   4. size > WH_COMM_MTU                       → BADARGS
     *   5. data == NULL                             → BADARGS
     *   6. ctx->state == WH_CALIPTRA_CLIENT_PENDING → NOTREADY
     *   7. hardware LOCK bit == 1 (held by another) → NOTREADY
     * --------------------------------------------------------------------- */
    {
        whTransportCaliptraClientContext cs_ctx[1] = {0};
        whTransportCaliptraConfig        cs_cfg[1] = {{.mbox_base = 0,
                                                       .cmd_id    = 0}};
        uint8_t dummy[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        int     rc_unit;

        /* Case 1: NULL context must always return BADARGS. */
        rc_unit = wh_TransportCaliptra_ClientSend(NULL,
                                                  (uint16_t)sizeof(dummy),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientSend(NULL ctx) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 2: zero-initialized (uninitialized) context — initialized==0. */
        rc_unit = wh_TransportCaliptra_ClientSend(cs_ctx,
                                                  (uint16_t)sizeof(dummy),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientSend(uninitialized ctx) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Initialize for the remaining cases. */
        rc_unit = wh_TransportCaliptra_ClientInit(cs_ctx, cs_cfg, NULL, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ClientInit for ClientSend tests failed: %d", rc_unit);

        /* Case 3: size == 0 must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ClientSend(cs_ctx, 0U, dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientSend(size=0) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 4: size > WH_COMM_MTU must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ClientSend(cs_ctx,
                                                  (uint16_t)(WH_COMM_MTU + 1U),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientSend(size=MTU+1) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Case 5: data == NULL with valid size must return BADARGS. */
        rc_unit = wh_TransportCaliptra_ClientSend(cs_ctx,
                                                  (uint16_t)sizeof(dummy),
                                                  NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientSend(data=NULL) expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* All BADARGS rejections must leave state IDLE so retries work. */
        WH_TEST_ASSERT_MSG(cs_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
            "ClientSend BADARGS cases must leave state IDLE, got %d",
            (int)cs_ctx->state);

        /* Case 6: state == PENDING (one request already in flight).
         *         Must return NOTREADY, not BADARGS.  State must remain
         *         PENDING — the caller will retry ClientSend later. */
        cs_ctx->state = WH_CALIPTRA_CLIENT_PENDING;
        rc_unit = wh_TransportCaliptra_ClientSend(cs_ctx,
                                                  (uint16_t)sizeof(dummy),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_NOTREADY,
            "ClientSend(state=PENDING) expected NOTREADY(%d), got %d",
            WH_ERROR_NOTREADY, rc_unit);
        WH_TEST_ASSERT_MSG(cs_ctx->state == WH_CALIPTRA_CLIENT_PENDING,
            "ClientSend(state=PENDING): state must stay PENDING, got %d",
            (int)cs_ctx->state);
        cs_ctx->state = WH_CALIPTRA_CLIENT_IDLE; /* restore */

        /* Case 7: hardware LOCK bit == 1 (held by another SoC agent).
         *         caliptra_read_u32(LOCK) returns the lock bit; when set,
         *         ClientSend must return NOTREADY without modifying state. */
        pthread_mutex_lock(&s_mbox.mutex);
        s_mbox.locked = 1U;
        pthread_mutex_unlock(&s_mbox.mutex);

        rc_unit = wh_TransportCaliptra_ClientSend(cs_ctx,
                                                  (uint16_t)sizeof(dummy),
                                                  dummy);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_NOTREADY,
            "ClientSend(lock held) expected NOTREADY(%d), got %d",
            WH_ERROR_NOTREADY, rc_unit);
        /* State must stay IDLE — lock was never acquired. */
        WH_TEST_ASSERT_MSG(cs_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
            "ClientSend(lock held): state must remain IDLE, got %d",
            (int)cs_ctx->state);

        /* Release the shim lock before cleanup. */
        pthread_mutex_lock(&s_mbox.mutex);
        s_mbox.locked = 0U;
        pthread_mutex_unlock(&s_mbox.mutex);

        wh_TransportCaliptra_ClientCleanup(cs_ctx);

        WH_TEST_PRINT("  ClientSend argument-validation unit tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit tests: ClientRecv entry-guard argument validation (wolfHSM-dod)
     *
     * wh_TransportCaliptra_ClientRecv has two BADARGS guards at function entry
     * (ctx==NULL, !ctx->initialized) plus a NOTREADY guard for the IDLE state.
     * ClientSend has equivalent explicit tests (cases 1 and 2), but ClientRecv
     * did not — this block closes that gap.
     *
     * Guard order in ClientRecv (before any hardware access):
     *   1. ctx == NULL              → BADARGS
     *   2. !ctx->initialized        → BADARGS
     *   3. ctx->state == IDLE       → NOTREADY  (no request in flight)
     *
     * Postconditions for each BADARGS/NOTREADY case:
     *   - Returns the expected error code.
     *   - ctx state is not modified (state remains IDLE for cases 1-3;
     *     the zero-initialized ctx state is unchanged for case 2).
     *   - *out_size is not written (sentinel preserved).
     * --------------------------------------------------------------------- */
    {
        whTransportCaliptraClientContext cr_ctx[1] = {0};
        whTransportCaliptraConfig        cr_cfg[1] = {{.mbox_base = 0,
                                                       .cmd_id    = 0}};
        uint8_t  data_buf[WH_COMM_MTU];
        uint16_t out_size;
        int      rc_unit;

        /* Case 1: NULL ctx must return BADARGS.  out_size and data are both
         *         valid pointers; the guard must fire before any dereference. */
        out_size = 0xFFFFU;
        rc_unit  = wh_TransportCaliptra_ClientRecv(NULL, &out_size, data_buf);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientRecv(NULL ctx): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "ClientRecv(NULL ctx): out_size must not be written, got 0x%04X",
            (unsigned)out_size);

        /* Case 2: zero-initialized (uninitialized) context — initialized==0.
         *         Must return BADARGS before accessing any hardware registers. */
        out_size = 0xFFFFU;
        rc_unit  = wh_TransportCaliptra_ClientRecv(cr_ctx, &out_size, data_buf);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientRecv(!initialized): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "ClientRecv(!initialized): out_size must not be written, got 0x%04X",
            (unsigned)out_size);

        /* Initialize for remaining cases. */
        rc_unit = wh_TransportCaliptra_ClientInit(cr_ctx, cr_cfg, NULL, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ClientInit for ClientRecv tests failed: %d", rc_unit);

        /* Case 3: state == IDLE (no request in flight) must return NOTREADY,
         *         not BADARGS.  This distinguishes "nothing to receive" from
         *         "bad arguments", which is important for retry logic. */
        WH_TEST_ASSERT_MSG(cr_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
            "ClientRecv test: expected IDLE state after Init, got %d",
            (int)cr_ctx->state);
        out_size = 0xFFFFU;
        rc_unit  = wh_TransportCaliptra_ClientRecv(cr_ctx, &out_size, data_buf);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_NOTREADY,
            "ClientRecv(state=IDLE): expected NOTREADY(%d), got %d",
            WH_ERROR_NOTREADY, rc_unit);
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "ClientRecv(state=IDLE): out_size must not be written, got 0x%04X",
            (unsigned)out_size);
        /* State must stay IDLE — NOTREADY must not corrupt transport state. */
        WH_TEST_ASSERT_MSG(cr_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
            "ClientRecv(state=IDLE): state must remain IDLE after NOTREADY, "
            "got %d", (int)cr_ctx->state);

        wh_TransportCaliptra_ClientCleanup(cr_ctx);

        WH_TEST_PRINT("  ClientRecv entry-guard unit tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit test: ClientRecv with unrecognized STATUS value (wolfHSM-6cn)
     *
     * STATUS bits [3:0] must only be 0-3 (BUSY/DATA_READY/CMD_COMPLETE/
     * CMD_FAILURE).  Any other value (4-15) must cause ClientRecv to write
     * EXECUTE=0, set state=IDLE, and return WH_ERROR_ABORTED rather than
     * silently falling through to the DATA_READY code path.
     *
     * This test runs single-threaded: it uses its own client context,
     * injects STATUS=4 directly into the MMIO shim, and verifies each
     * postcondition individually.
     * --------------------------------------------------------------------- */
    {
        whTransportCaliptraClientContext test_ctx[1]  = {0};
        whTransportCaliptraConfig        test_cfg[1]  = {{.mbox_base = 0,
                                                          .cmd_id    = 0}};
        uint8_t  data_buf[WH_COMM_MTU];
        uint16_t out_size  = 0xFFFFU; /* sentinel: must not be written on ABORTED */
        int      rc_unit;
        int      bad_status;

        rc_unit = wh_TransportCaliptra_ClientInit(test_ctx, test_cfg, NULL, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ClientInit for STATUS test failed: %d", rc_unit);

        /* Test every unrecognized status value 4-15 */
        for (bad_status = 4; bad_status <= 15; bad_status++) {
            /* Simulate a pending request: state must be PENDING for ClientRecv
             * to proceed past the idle guard. */
            test_ctx->state = WH_CALIPTRA_CLIENT_PENDING;

            /* Inject the unrecognized status and a non-zero execute flag into
             * the shim so the EXECUTE=0 write is testable. */
            pthread_mutex_lock(&s_mbox.mutex);
            s_mbox.status  = (uint32_t)bad_status;
            s_mbox.execute = 1U;
            pthread_mutex_unlock(&s_mbox.mutex);

            out_size = 0xFFFFU; /* reset sentinel each iteration */

            /* ClientRecv must return ABORTED, not OK or NOTREADY. */
            rc_unit = wh_TransportCaliptra_ClientRecv(test_ctx, &out_size,
                                                      data_buf);
            WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_ABORTED,
                "ClientRecv(status=%d): expected ABORTED(%d), got %d",
                bad_status, WH_ERROR_ABORTED, rc_unit);

            /* State must be reset to IDLE (mailbox logically released). */
            WH_TEST_ASSERT_MSG(test_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
                "ClientRecv(status=%d): state must be IDLE after unrecognized "
                "status, got %d", bad_status, (int)test_ctx->state);

            /* EXECUTE=0 must have been written (mailbox physically released). */
            pthread_mutex_lock(&s_mbox.mutex);
            WH_TEST_ASSERT_MSG(s_mbox.execute == 0U,
                "ClientRecv(status=%d): EXECUTE must be 0 after unrecognized "
                "status, got %u", bad_status, (unsigned)s_mbox.execute);
            pthread_mutex_unlock(&s_mbox.mutex);

            /* out_size must not have been written: there is no valid response. */
            WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
                "ClientRecv(status=%d): out_size must not be written on ABORTED "
                "return, got 0x%04X", bad_status, (unsigned)out_size);
        }

        wh_TransportCaliptra_ClientCleanup(test_ctx);

        WH_TEST_PRINT("  ClientRecv unrecognized-status unit tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit test: ClientRecv DATA_READY with DLEN > WH_COMM_MTU (wolfHSM-a63)
     *
     * The client-side DLEN overflow guard in wh_TransportCaliptra_ClientRecv
     * is the last line of defense if firmware claims a response larger than the
     * MTU.  It must:
     *   a) drain the DATAOUT FIFO (prevents stale data in the next transaction)
     *   b) write EXECUTE=0 (release the mailbox)
     *   c) reset state to IDLE
     *   d) return WH_ERROR_ABORTED
     *   e) not write *out_size
     *
     * This test is distinct from the firmware-side error path 1 (wolfHSM-3k8),
     * which verifies the firmware thread rejects DLEN overflow before calling
     * SetRequest.  This test exercises ClientRecv directly, single-threaded,
     * without any firmware thread running.
     * --------------------------------------------------------------------- */
    {
        whTransportCaliptraClientContext test_ctx[1]  = {0};
        whTransportCaliptraConfig        test_cfg[1]  = {{.mbox_base = 0,
                                                          .cmd_id    = 0}};
        uint8_t  data_buf[WH_COMM_MTU];
        uint16_t out_size = 0xFFFFU; /* sentinel: must not be written */
        int      rc_unit;

        rc_unit = wh_TransportCaliptra_ClientInit(test_ctx, test_cfg, NULL, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ClientInit for DLEN overflow test failed: %d", rc_unit);

        /* Force state=PENDING: ClientRecv returns NOTREADY immediately from
         * IDLE, never reaching the STATUS or DLEN reads. */
        test_ctx->state = WH_CALIPTRA_CLIENT_PENDING;

        /* Inject STATUS=DATA_READY, DLEN=WH_COMM_MTU+1, EXECUTE=1 into the
         * shim.  DATAOUT is empty (dataout_data_len=0): the drain loop will
         * read zeros, which is correct — it only needs to advance the position,
         * not return valid data. */
        pthread_mutex_lock(&s_mbox.mutex);
        s_mbox.status           = (uint32_t)WH_CALIPTRA_MBOX_ST_DATA_READY;
        s_mbox.dlen             = (uint32_t)WH_COMM_MTU + 1U;
        s_mbox.execute          = 1U;
        s_mbox.dataout_pos      = 0U;
        s_mbox.dataout_data_len = 0U;
        pthread_mutex_unlock(&s_mbox.mutex);

        rc_unit = wh_TransportCaliptra_ClientRecv(test_ctx, &out_size, data_buf);

        /* Postcondition (d): must return ABORTED. */
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_ABORTED,
            "ClientRecv(DLEN=MTU+1): expected ABORTED(%d), got %d",
            WH_ERROR_ABORTED, rc_unit);

        /* Postcondition (c): state must be IDLE. */
        WH_TEST_ASSERT_MSG(test_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
            "ClientRecv(DLEN=MTU+1): state must be IDLE after overflow, got %d",
            (int)test_ctx->state);

        pthread_mutex_lock(&s_mbox.mutex);
        /* Postcondition (b): EXECUTE=0 must have been written. */
        WH_TEST_ASSERT_MSG(s_mbox.execute == 0U,
            "ClientRecv(DLEN=MTU+1): EXECUTE must be 0 after overflow, got %u",
            (unsigned)s_mbox.execute);
        pthread_mutex_unlock(&s_mbox.mutex);

        /* Postcondition (e): out_size must not have been written. */
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "ClientRecv(DLEN=MTU+1): out_size must not be written, got 0x%04X",
            (unsigned)out_size);

        wh_TransportCaliptra_ClientCleanup(test_ctx);

        WH_TEST_PRINT("  ClientRecv DLEN overflow unit test: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Unit test: ClientRecv DATA_READY with dlen > 0 and data == NULL
     *            (wolfHSM-34h)
     *
     * When STATUS=DATA_READY and dlen > 0, passing data=NULL must:
     *   a) drain the DATAOUT FIFO (advance dataout_pos; prevents stale data)
     *   b) write EXECUTE=0 (release the mailbox)
     *   c) reset state to IDLE
     *   d) return WH_ERROR_BADARGS
     *   e) not write *out_size
     *
     * Without this guard, data would be dereferenced (NULL write) or the FIFO
     * position would remain at 0, corrupting the next transaction.
     * --------------------------------------------------------------------- */
    {
        whTransportCaliptraClientContext test_ctx[1]  = {0};
        whTransportCaliptraConfig        test_cfg[1]  = {{.mbox_base = 0,
                                                          .cmd_id    = 0}};
        const uint8_t test_payload[8] = {0x11, 0x22, 0x33, 0x44,
                                          0x55, 0x66, 0x77, 0x88};
        uint16_t out_size = 0xFFFFU; /* sentinel */
        uint32_t post_drain_pos;
        int      rc_unit;

        rc_unit = wh_TransportCaliptra_ClientInit(test_ctx, test_cfg, NULL, NULL);
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_OK,
            "ClientInit for NULL-data test failed: %d", rc_unit);

        test_ctx->state = WH_CALIPTRA_CLIENT_PENDING;

        /* Inject STATUS=DATA_READY, DLEN=8, 8 bytes of payload in DATAOUT.
         * caliptra_fifo_drain will read ceil(8/4)=2 words → dataout_pos=8. */
        pthread_mutex_lock(&s_mbox.mutex);
        s_mbox.status           = (uint32_t)WH_CALIPTRA_MBOX_ST_DATA_READY;
        s_mbox.dlen             = 8U;
        s_mbox.execute          = 1U;
        memcpy(s_mbox.dataout_buf, test_payload, sizeof(test_payload));
        s_mbox.dataout_pos      = 0U;
        s_mbox.dataout_data_len = 8U;
        pthread_mutex_unlock(&s_mbox.mutex);

        /* data=NULL with dlen=8 must trigger the NULL-data guard. */
        rc_unit = wh_TransportCaliptra_ClientRecv(test_ctx, &out_size, NULL);

        /* Postcondition (d): must return BADARGS. */
        WH_TEST_ASSERT_MSG(rc_unit == WH_ERROR_BADARGS,
            "ClientRecv(data=NULL, dlen=8): expected BADARGS(%d), got %d",
            WH_ERROR_BADARGS, rc_unit);

        /* Postcondition (c): state must be IDLE. */
        WH_TEST_ASSERT_MSG(test_ctx->state == WH_CALIPTRA_CLIENT_IDLE,
            "ClientRecv(data=NULL): state must be IDLE after BADARGS, got %d",
            (int)test_ctx->state);

        pthread_mutex_lock(&s_mbox.mutex);
        /* Postcondition (b): EXECUTE=0 must have been written. */
        WH_TEST_ASSERT_MSG(s_mbox.execute == 0U,
            "ClientRecv(data=NULL): EXECUTE must be 0 after BADARGS, got %u",
            (unsigned)s_mbox.execute);

        /* Postcondition (a): FIFO must have been drained.
         * caliptra_fifo_drain reads ceil(8/4)=2 words, each advancing
         * dataout_pos by 4.  EXECUTE=0 resets dataout_data_len but not
         * dataout_pos, so the drain is verifiable after the call. */
        post_drain_pos = s_mbox.dataout_pos;
        pthread_mutex_unlock(&s_mbox.mutex);

        WH_TEST_ASSERT_MSG(post_drain_pos == 8U,
            "ClientRecv(data=NULL): FIFO not drained; dataout_pos expected 8, "
            "got %u", (unsigned)post_drain_pos);

        /* Postcondition (e): out_size must not have been written. */
        WH_TEST_ASSERT_MSG(out_size == 0xFFFFU,
            "ClientRecv(data=NULL): out_size must not be written, got 0x%04X",
            (unsigned)out_size);

        wh_TransportCaliptra_ClientCleanup(test_ctx);

        WH_TEST_PRINT("  ClientRecv DATA_READY NULL-data unit test: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Firmware thread error path tests (wolfHSM-3k8)
     *
     * Each test injects a fault via the MMIO shim, verifies the firmware sets
     * STATUS=CMD_FAILURE, and simulates client mailbox release (EXECUTE=0).
     * These tests run before the happy-path thread test so that any failure
     * is deterministic and isolated.
     * --------------------------------------------------------------------- */
    {
        pthread_t           err_fw_thread = 0;
        CaliptraFirmwareArg err_fw_arg    = {
            .server         = server,
            .transport_ctx  = srv_transport_ctx,
            .stop_requested = 0,
        };
        uint32_t status;

        rc = pthread_create(&err_fw_thread, NULL,
                            _caliptraFirmwareTask, &err_fw_arg);
        if (rc != 0) {
            WH_ERROR_PRINT("pthread_create (error-path firmware) failed: %d\n",
                           rc);
            rc = WH_ERROR_ABORTED;
            goto cleanup_server;
        }

        /* ----- Error path 1: DLEN > MTU ---------------------------------- */
        {
            uint8_t dummy[8] = {0};
            status = inject_request_and_get_status(
                    WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID,
                    (uint32_t)WH_COMM_MTU + 1U,
                    dummy);
            WH_TEST_ASSERT_MSG(
                status == (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE,
                "DLEN overflow: expected CMD_FAILURE(%d), got %u",
                WH_CALIPTRA_MBOX_ST_CMD_FAILURE, (unsigned)status);
            /* Firmware must have reset datain_pos (FIFO is clean). */
            pthread_mutex_lock(&s_mbox.mutex);
            WH_TEST_ASSERT_MSG(s_mbox.datain_pos == 0U,
                "DLEN overflow: datain_pos not reset, got %u",
                (unsigned)s_mbox.datain_pos);
            pthread_mutex_unlock(&s_mbox.mutex);
            release_mailbox_after_error();
        }

        /* ----- Error path 2: Unknown CMD ID ------------------------------ */
        {
            uint8_t dummy[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            status = inject_request_and_get_status(
                    0xDEADBEEFUL, 8U, dummy);
            WH_TEST_ASSERT_MSG(
                status == (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE,
                "Bad CMD: expected CMD_FAILURE(%d), got %u",
                WH_CALIPTRA_MBOX_ST_CMD_FAILURE, (unsigned)status);
            release_mailbox_after_error();
        }

        /* ----- Error path 3: ServerSetRequest failure (req_pending busy) - */
        {
            uint8_t dummy[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            int rc_pre;

            /* Pre-occupy the transport so the next SetRequest returns
             * NOTREADY (simulates a previous exchange not yet completed). */
            rc_pre = wh_TransportCaliptra_ServerSetRequest(srv_transport_ctx,
                                                           dummy, sizeof(dummy));
            WH_TEST_ASSERT_MSG(rc_pre == WH_ERROR_OK,
                "SetRequest(pre-occupy) expected OK(%d), got %d",
                WH_ERROR_OK, rc_pre);

            /* Inject another request; firmware will call SetRequest and get
             * NOTREADY because req_pending is already 1. */
            status = inject_request_and_get_status(
                    WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID, 8U, dummy);
            WH_TEST_ASSERT_MSG(
                status == (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE,
                "Double SetRequest: expected CMD_FAILURE(%d), got %u",
                WH_CALIPTRA_MBOX_ST_CMD_FAILURE, (unsigned)status);
            release_mailbox_after_error();

            /* Drain the pre-occupied request so the transport ctx is clean
             * for subsequent tests. */
            drain_pending_server_request(srv_transport_ctx);
        }

        /* ----- Error path 4: HandleRequestMessage failure (short packet) - */
        {
            /* A 4-byte payload passes ServerSetRequest (size > 0 && <= MTU)
             * but is smaller than the 8-byte wolfHSM comm header.
             * wh_CommServer_RecvRequest returns WH_ERROR_ABORTED, and
             * wh_Server_HandleRequestMessage propagates it. */
            uint8_t short_pkt[4] = {0xAA, 0xBB, 0xCC, 0xDD};
            status = inject_request_and_get_status(
                    WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID, 4U, short_pkt);
            WH_TEST_ASSERT_MSG(
                status == (uint32_t)WH_CALIPTRA_MBOX_ST_CMD_FAILURE,
                "Short packet: expected CMD_FAILURE(%d), got %u",
                WH_CALIPTRA_MBOX_ST_CMD_FAILURE, (unsigned)status);
            release_mailbox_after_error();

            /* HandleRequestMessage calls ServerRecv (which does not clear
             * req_pending) and then fails.  ServerSend is never called, so
             * req_pending remains 1.  Drain it to restore clean state. */
            drain_pending_server_request(srv_transport_ctx);
        }

        /* Signal the firmware thread to exit cleanly and wait for it. */
        pthread_mutex_lock(&s_mbox.mutex);
        err_fw_arg.stop_requested = 1;
        pthread_cond_signal(&s_mbox.req_cond);
        pthread_mutex_unlock(&s_mbox.mutex);
        pthread_join(err_fw_thread, NULL);

        WH_TEST_PRINT("  Firmware error path tests: PASSED\n");
    }

    /* -----------------------------------------------------------------------
     * Spawn threads: firmware first so it is ready before the client starts.
     * --------------------------------------------------------------------- */
    rc = pthread_create(&firmware_thread, NULL,
                        _caliptraFirmwareTask, &firmware_arg);
    if (rc != 0) {
        WH_ERROR_PRINT("pthread_create (firmware) failed: %d\n", rc);
        rc = WH_ERROR_ABORTED;
        goto cleanup_server;
    }

    rc = pthread_create(&client_thread, NULL,
                        _caliptraClientTask, c_conf);
    if (rc != 0) {
        WH_ERROR_PRINT("pthread_create (client) failed: %d\n", rc);
        /* Signal the firmware thread to exit using the stop_requested pattern
         * rather than pthread_cancel.  pthread_cancel can fire while the
         * firmware thread holds s_mbox.mutex (pthread_cond_wait is a
         * cancellation point that re-acquires the mutex before returning),
         * and without a pthread_cleanup_push handler the mutex would be left
         * locked, causing undefined behaviour in caliptra_mbox_sim_destroy. */
        pthread_mutex_lock(&s_mbox.mutex);
        firmware_arg.stop_requested = 1;
        pthread_cond_signal(&s_mbox.req_cond);
        pthread_mutex_unlock(&s_mbox.mutex);
        pthread_join(firmware_thread, NULL);
        rc = WH_ERROR_ABORTED;
        goto cleanup_server;
    }

    /* -----------------------------------------------------------------------
     * Wait for the client to finish.  The client sends CommClose before
     * returning, which causes the firmware thread to exit naturally after
     * processing it (the wolfHSM server sets am_connected=DISCONNECTED).
     * --------------------------------------------------------------------- */
    pthread_join(client_thread, NULL);
    pthread_join(firmware_thread, NULL);

    rc = WH_ERROR_OK;

cleanup_server:
    wh_Server_Cleanup(server);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    if (rng_initialized) {
        wc_FreeRng(crypto->rng);
    }
    if (wolfcrypt_initialized) {
        wolfCrypt_Cleanup();
    }
#endif

    wh_Nvm_Cleanup(nvm);
    caliptra_mbox_sim_destroy();

    if (rc == WH_ERROR_OK) {
        WH_TEST_PRINT("Caliptra transport test PASSED\n");
    }

    return rc;
}

#endif /* WOLFHSM_CFG_TEST_CALIPTRA && WOLFHSM_CFG_TEST_POSIX &&
          WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
