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
 * port/caliptra/wh_transport_caliptra.c
 *
 * wolfHSM transport binding for the Caliptra hardware mailbox.
 *
 * NOTE: Unlikely to be useful without a manufacturer partnership.
 * See the deployment status note at the top of wh_transport_caliptra.h.
 *
 * See wh_transport_caliptra.h for architecture, usage, and integration notes.
 *
 * Hardware access (client side only)
 * ------------------------------------
 * All MMIO reads and writes go through the two platform-supplied functions
 * declared in caliptra_if.h:
 *
 *   int caliptra_read_u32(uint32_t address, uint32_t *data);
 *   int caliptra_write_u32(uint32_t address, uint32_t data);
 *
 * Both return 0 on success and non-zero on failure.  A non-zero return is
 * treated as WH_ERROR_ABORTED (fatal hardware error) unless noted otherwise.
 *
 * caliptra_if.h is only included when WOLFHSM_CFG_ENABLE_CLIENT is defined;
 * a server-only (Caliptra firmware) build has no MMIO dependency of its own.
 *
 * FIFO protocol
 * -------------
 * The DATAIN and DATAOUT registers are true hardware FIFOs.  Each 32-bit
 * write to DATAIN enqueues one word into the Caliptra-side buffer; each
 * 32-bit read from DATAOUT dequeues one word.  All FIFO accesses must be
 * sized to the nearest multiple of 4 bytes.  DLEN carries the true byte
 * count so that the receiver can discard the zero-padding in the final
 * partial word.
 *
 * Byte ordering contract
 * ----------------------
 * Caliptra's RISC-V core is little-endian.  This transport assumes that
 * caliptra_write_u32(addr, val) writes the uint32_t value to the DATAIN
 * register in little-endian byte order: byte 0 of the FIFO word equals
 * val & 0xFF, byte 1 equals (val >> 8) & 0xFF, and so on.  This matches
 * the reference libcaliptra HAL, which performs a byte-swap before the
 * MMIO store on big-endian SoCs.
 *
 * caliptra_fifo_write and caliptra_fifo_read therefore use explicit
 * little-endian bit-shift expressions instead of memcpy to pack and unpack
 * FIFO words.  On a little-endian host the compiler optimises the shifts
 * to a single native load/store — there is no runtime cost.  On a
 * big-endian host the shift approach produces the correct LE wire encoding
 * while a naive memcpy would silently reverse each 4-byte group, causing
 * every wolfHSM packet to arrive with garbled contents.
 *
 * The same convention applies to caliptra_read_u32 on DATAOUT: the
 * function returns the FIFO word interpreted as little-endian, so bit 0
 * of the returned value is the first byte the firmware enqueued.
 */

/* wh_settings.h must be first; it drives all other compile-time choices. */
#include "wolfhsm/wh_settings.h"

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "port/caliptra/wh_transport_caliptra.h"

/* =========================================================================
 * Client transport: MMIO helpers and implementation
 * ========================================================================= */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)

/*
 * Sentinel guard: both config fields use 0 as "use compile-time default".
 * If either compile-time default is itself 0, the sentinel is ambiguous —
 * a caller who zero-initialises the config to request the default would
 * silently get address 0 instead.  Catch this at compile time.
 *
 * NOTE: Physical address 0x00000000 and command ID 0x00000000 cannot be
 * selected at runtime via whTransportCaliptraConfig.  If your platform
 * genuinely requires one of these values, override the corresponding
 * WOLFHSM_CFG_TRANSPORT_CALIPTRA_* macro at build time.
 */
typedef char wh_caliptra_assert_mbox_base_nonzero[
    (WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE != 0U) ? 1 : -1];
typedef char wh_caliptra_assert_cmd_id_nonzero[
    (WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID != 0U) ? 1 : -1];

/** Resolve the wolfHSM command ID from a config or fall back to the
 *  compile-time default (WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID).
 *  Only the client uses the command ID; the server transport does not
 *  need it (command ID validation is done by the Caliptra runtime handler
 *  before calling ServerSetRequest).
 *
 *  @note  cmd_id == 0 selects the compile-time default.  Command ID 0x0
 *         cannot be selected at runtime; use WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID
 *         to override it at build time. */
static uint32_t resolve_cmd_id(const whTransportCaliptraConfig *cfg)
{
    if (cfg != NULL && cfg->cmd_id != 0U) {
        return cfg->cmd_id;
    }
    return (uint32_t)WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID;
}

/*
 * caliptra_if.h provides caliptra_read_u32() and caliptra_write_u32().
 * The build system must add libcaliptra/inc to the include path.
 * This header is only needed on the SoC side (ENABLE_CLIENT); a Caliptra
 * firmware build (ENABLE_SERVER only) does not require it.
 *
 * caliptra_if.h also declares caliptra_wait() (a platform yield/delay hook).
 * This transport does not call it because all polling is handled by returning
 * WH_ERROR_NOTREADY to the caller; pacing between retries is the caller's
 * responsibility, not the transport's.
 */
#include "caliptra_if.h"

/** Read one 32-bit word from a mailbox CSR register.
 *
 *  @param base    Resolved mailbox CSR base address.
 *  @param offset  Register offset (WH_CALIPTRA_REG_* constant).
 *  @param out     Receives the register value on success.
 *
 *  @return  WH_ERROR_OK on success, WH_ERROR_ABORTED on MMIO failure. */
static int caliptra_reg_read(uint32_t base, uint32_t offset, uint32_t *out)
{
    int rc = caliptra_read_u32(base + offset, out);
    return (rc == 0) ? WH_ERROR_OK : WH_ERROR_ABORTED;
}

/** Write one 32-bit word to a mailbox CSR register.
 *
 *  @return  WH_ERROR_OK on success, WH_ERROR_ABORTED on MMIO failure. */
static int caliptra_reg_write(uint32_t base, uint32_t offset, uint32_t val)
{
    int rc = caliptra_write_u32(base + offset, val);
    return (rc == 0) ? WH_ERROR_OK : WH_ERROR_ABORTED;
}

/** Write a byte array to the DATAIN FIFO in 4-byte aligned words.
 *
 *  The final partial word (when size % 4 != 0) is zero-padded before being
 *  written.  The receiver uses DLEN to determine the true byte count and
 *  ignores the padding.
 *
 *  Bytes are packed using explicit little-endian bit shifts: data[i] goes
 *  into bits [7:0], data[i+1] into bits [15:8], and so on.  This matches
 *  the caliptra_write_u32 LE contract (see "Byte ordering contract" in the
 *  file header) and is correct on both LE and BE hosts.  A memcpy approach
 *  would give the same result on a LE host but would silently reverse bytes
 *  on a BE host, corrupting every wolfHSM packet.
 *
 *  @return  WH_ERROR_OK on success, WH_ERROR_ABORTED on any MMIO failure. */
static int caliptra_fifo_write(uint32_t base,
                               const uint8_t *data, uint32_t size)
{
    uint32_t i   = 0;
    uint32_t rem = size & 3U;

    /* Write all complete 4-byte words, packing bytes as LE. */
    while (i + 4U <= size) {
        uint32_t word = (uint32_t)data[i]
                      | ((uint32_t)data[i + 1U] << 8)
                      | ((uint32_t)data[i + 2U] << 16)
                      | ((uint32_t)data[i + 3U] << 24);
        if (caliptra_reg_write(base, WH_CALIPTRA_REG_DATAIN, word)
                != WH_ERROR_OK) {
            return WH_ERROR_ABORTED;
        }
        i += 4U;
    }

    /* Write the final partial word with zero-padding in the high bytes. */
    if (rem != 0U) {
        uint32_t word = 0U;
        uint32_t j;
        for (j = 0U; j < rem; j++) {
            word |= ((uint32_t)data[i + j] << (j * 8U));
        }
        if (caliptra_reg_write(base, WH_CALIPTRA_REG_DATAIN, word)
                != WH_ERROR_OK) {
            return WH_ERROR_ABORTED;
        }
    }

    return WH_ERROR_OK;
}

/** Read ceil(size/4) words from the DATAOUT FIFO, copying only 'size'
 *  bytes into 'data'.
 *
 *  Bytes are extracted using explicit little-endian bit shifts: bits [7:0]
 *  of the returned word become data[i], bits [15:8] become data[i+1], and
 *  so on.  This matches the caliptra_read_u32 LE contract (see "Byte
 *  ordering contract" in the file header) and is correct on both LE and BE
 *  hosts.  A memcpy approach would be correct on a LE host but would
 *  silently reverse bytes on a BE host.
 *
 *  @return  WH_ERROR_OK on success, WH_ERROR_ABORTED on any MMIO failure. */
static int caliptra_fifo_read(uint32_t base,
                              uint8_t *data, uint32_t size)
{
    uint32_t i   = 0;
    uint32_t rem = size & 3U;

    /* Read all complete 4-byte words, extracting bytes as LE. */
    while (i + 4U <= size) {
        uint32_t word;
        if (caliptra_reg_read(base, WH_CALIPTRA_REG_DATAOUT, &word)
                != WH_ERROR_OK) {
            return WH_ERROR_ABORTED;
        }
        data[i]        = (uint8_t)(word);
        data[i + 1U]   = (uint8_t)(word >> 8);
        data[i + 2U]   = (uint8_t)(word >> 16);
        data[i + 3U]   = (uint8_t)(word >> 24);
        i += 4U;
    }

    /* Read the final partial word; extract only the valid bytes. */
    if (rem != 0U) {
        uint32_t word;
        uint32_t j;
        if (caliptra_reg_read(base, WH_CALIPTRA_REG_DATAOUT, &word)
                != WH_ERROR_OK) {
            return WH_ERROR_ABORTED;
        }
        for (j = 0U; j < rem; j++) {
            data[i + j] = (uint8_t)(word >> (j * 8U));
        }
    }

    return WH_ERROR_OK;
}

/** Drain up to 'words' words from DATAOUT, discarding all data.
 *
 *  Used after a DLEN overflow is detected to leave the FIFO in a clean
 *  state before writing EXECUTE = 0.  MMIO errors during drain are ignored
 *  because the primary error (overflow) has already been determined. */
static void caliptra_fifo_drain(uint32_t base, uint32_t words)
{
    uint32_t w;
    uint32_t word;
    for (w = 0; w < words; w++) {
        (void)caliptra_reg_read(base, WH_CALIPTRA_REG_DATAOUT, &word);
    }
}

/** Resolve the mailbox base address from a config or fall back to the
 *  compile-time default (WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE).
 *
 *  @note  mbox_base == 0 selects the compile-time default.  Physical address
 *         0x00000000 cannot be selected at runtime; use
 *         WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE to override at build time. */
static uint32_t resolve_mbox_base(const whTransportCaliptraConfig *cfg)
{
    if (cfg != NULL && cfg->mbox_base != 0U) {
        return cfg->mbox_base;
    }
    return (uint32_t)WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE;
}

/* -------------------------------------------------------------------------
 * Client Init / Send / Recv / Cleanup
 * ------------------------------------------------------------------------- */

int wh_TransportCaliptra_ClientInit(void *context, const void *config,
        whCommSetConnectedCb connectcb, void *connectcb_arg)
{
    whTransportCaliptraClientContext *ctx = context;
    const whTransportCaliptraConfig  *cfg = config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->mbox_base     = resolve_mbox_base(cfg);
    ctx->cmd_id        = resolve_cmd_id(cfg);
    ctx->connectcb     = connectcb;
    ctx->connectcb_arg = connectcb_arg;
    ctx->state         = WH_CALIPTRA_CLIENT_IDLE;
    ctx->initialized   = 1;

    /* The Caliptra mailbox is available as soon as the firmware is running;
     * there is no connection handshake.  Notify the comm layer immediately. */
    if (connectcb != NULL) {
        (void)connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }

    return WH_ERROR_OK;
}

/*
 * Send a wolfHSM request packet through the Caliptra mailbox.
 *
 * State machine:
 *   PENDING → return NOTREADY (only one request in flight at a time)
 *   IDLE    → try to acquire lock
 *               lock bit == 1 (held by another)  → return NOTREADY
 *               lock bit == 0 (acquired by us)   → write CMD, DLEN, DATAIN
 *                 any write fails                → return ABORTED (fatal)
 *                 all succeed                    → write EXECUTE = 1
 *                   write fails                  → return ABORTED (fatal)
 *                   write succeeds               → state = PENDING, return OK
 */
int wh_TransportCaliptra_ClientSend(void *context, uint16_t size,
        const void *data)
{
    whTransportCaliptraClientContext *ctx = context;
    uint32_t mbox_base;
    uint32_t lock_val = 0;
    int rc;

    if (    ctx == NULL ||
            !ctx->initialized ||
            size == 0U ||
            size > (uint16_t)WH_COMM_MTU ||
            data == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->state == WH_CALIPTRA_CLIENT_PENDING) {
        return WH_ERROR_NOTREADY;
    }

    mbox_base = ctx->mbox_base;

    /*
     * Try to acquire the mailbox lock.
     *
     * Reading LOCK is an atomic test-and-set in hardware:
     *   Returns 0 (bit clear) → lock was free; we now hold it.
     *   Returns 1 (bit set)   → lock is held by another agent; retry.
     *
     * caliptra_read_u32 is called directly here instead of through
     * caliptra_reg_read because the two wrappers map failures differently:
     *   caliptra_reg_read  → WH_ERROR_ABORTED (fatal, unrecoverable)
     *   caliptra_read_u32  → checked inline → WH_ERROR_NOTREADY (transient)
     * A LOCK read failure means the hardware is not yet accessible; the right
     * response is to retry, not to abort the client session.  Every other
     * register access in this file uses caliptra_reg_read/caliptra_reg_write
     * because post-lock-acquire failures are fatal; the LOCK read is the only
     * exception and must remain a direct caliptra_read_u32 call.
     */
    rc = caliptra_read_u32(mbox_base + WH_CALIPTRA_REG_LOCK, &lock_val);
    if (rc != 0) {
        return WH_ERROR_NOTREADY;
    }
    if ((lock_val & WH_CALIPTRA_LOCK_MASK) != 0U) {
        return WH_ERROR_NOTREADY;
    }

    /*
     * Lock acquired.  Any MMIO write failure from here is a fatal hardware
     * fault.  The UNLOCK register (0x020) is SoC-read-only; the SoC has no
     * mechanism to release the mailbox lock without completing the EXECUTE
     * handshake.  WH_ERROR_ABORTED must be treated as unrecoverable by the
     * caller; the mailbox state is undefined until a system reset.
     */

    if (caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_CMD, ctx->cmd_id)
            != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    if (caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_DLEN, (uint32_t)size)
            != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    if (caliptra_fifo_write(mbox_base, (const uint8_t *)data, (uint32_t)size)
            != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    if (caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 1U)
            != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    ctx->state = WH_CALIPTRA_CLIENT_PENDING;
    return WH_ERROR_OK;
}

/*
 * Poll for a wolfHSM response from the Caliptra firmware.
 *
 * State machine:
 *   IDLE    → return NOTREADY (no request in flight)
 *   PENDING → read STATUS[3:0]
 *               BUSY (0)         → return NOTREADY
 *               CMD_FAILURE (3)  → write EXECUTE=0, state=IDLE, return ABORTED
 *               CMD_COMPLETE (2) → write EXECUTE=0, state=IDLE, *out_size=0, return OK
 *               DATA_READY (1)   → read DLEN
 *                 DLEN > MTU     → drain FIFO, write EXECUTE=0, state=IDLE, return ABORTED
 *                 DLEN OK        → read response from DATAOUT FIFO
 *                   read fails   → write EXECUTE=0, state=IDLE, return ABORTED
 *                   read OK      → write EXECUTE=0, state=IDLE, return OK
 *               Unknown (4-15)   → write EXECUTE=0, state=IDLE, return ABORTED
 */
int wh_TransportCaliptra_ClientRecv(void *context, uint16_t *out_size,
        void *data)
{
    whTransportCaliptraClientContext *ctx = context;
    uint32_t mbox_base;
    uint32_t status_reg;
    uint32_t dlen;
    uint8_t  status;
    int rc;

    if (ctx == NULL || !ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->state == WH_CALIPTRA_CLIENT_IDLE) {
        return WH_ERROR_NOTREADY;
    }

    mbox_base = ctx->mbox_base;

    /* Read STATUS register; treat transient MMIO failure as not-ready. */
    rc = caliptra_reg_read(mbox_base, WH_CALIPTRA_REG_STATUS, &status_reg);
    if (rc != WH_ERROR_OK) {
        return WH_ERROR_NOTREADY;
    }
    status = (uint8_t)(status_reg & WH_CALIPTRA_STATUS_MASK);

    switch (status) {
        case WH_CALIPTRA_MBOX_ST_BUSY:
            return WH_ERROR_NOTREADY;

        case WH_CALIPTRA_MBOX_ST_CMD_FAILURE:
            /* All EXECUTE=0 writes below use (void): if the write fails there
             * is no software recovery path.  The mailbox lock is held by the
             * SoC and can only be released by completing the EXECUTE handshake;
             * the UNLOCK register (0x020) is SoC-read-only.  A failed EXECUTE=0
             * write leaves the mailbox locked until a system reset.  This is a
             * hardware limitation documented in wh_TransportCaliptra_ClientCleanup.
             * Propagating the write error to the caller would not help, since the
             * caller's only option is also a system reset.  All subsequent
             * (void) casts on EXECUTE=0 writes in this function share this
             * reasoning. */
            (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
            ctx->state = WH_CALIPTRA_CLIENT_IDLE;
            return WH_ERROR_ABORTED;

        case WH_CALIPTRA_MBOX_ST_CMD_COMPLETE:
            /* Success with no response payload. */
            (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
            ctx->state = WH_CALIPTRA_CLIENT_IDLE;
            if (out_size != NULL) {
                *out_size = 0U;
            }
            return WH_ERROR_OK;

        case WH_CALIPTRA_MBOX_ST_DATA_READY:
            break; /* break out of switch; DATA_READY handling continues below */

        default:
            /* Unrecognized status value (bits [3:0] not in {0,1,2,3}): hardware
             * fault or future spec extension.  Do not attempt to read DLEN or
             * the FIFO; release the mailbox and return a fatal error. */
            (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
            ctx->state = WH_CALIPTRA_CLIENT_IDLE;
            return WH_ERROR_ABORTED;
    }

    /* STATUS == DATA_READY (1): read the response payload. */

    rc = caliptra_reg_read(mbox_base, WH_CALIPTRA_REG_DLEN, &dlen);
    if (rc != WH_ERROR_OK) {
        (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
        ctx->state = WH_CALIPTRA_CLIENT_IDLE;
        return WH_ERROR_ABORTED;
    }

    if (dlen > (uint32_t)WH_COMM_MTU) {
        /* Protocol error: firmware sent more data than the MTU allows.
         * Drain the FIFO before releasing the mailbox to avoid leaving
         * stale data that would corrupt the next transaction.
         *
         * Use WH_COMM_MTU as the drain bound rather than dlen: dlen is
         * untrusted firmware data and can be up to UINT32_MAX.  Computing
         * (dlen + 3U) / 4U in 32-bit arithmetic wraps to near-zero for
         * dlen >= 0xFFFFFFFD, and evaluating it faithfully for large values
         * would loop for ~10^9 iterations.  The wolfHSM channel cannot carry
         * more than ceil(WH_COMM_MTU / 4) words, so draining that many words
         * is sufficient to empty any legitimately populated FIFO.
         *
         * Any FIFO words beyond that bound are released by the hardware when
         * EXECUTE is written to 0.  Per the Caliptra hardware mailbox
         * specification (see caliptra_top_reg.h and the Caliptra Architecture
         * Specification §"Mailbox Protocol"), transitioning EXECUTE from 1 to
         * 0 (the normal response-complete or abort path) resets the mailbox
         * state machine and discards any un-read DATAOUT words.  Integrators
         * on non-reference Caliptra RTL must verify this guarantee holds for
         * their implementation before relying on it. */
        caliptra_fifo_drain(mbox_base, ((uint32_t)WH_COMM_MTU + 3U) / 4U);
        (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
        ctx->state = WH_CALIPTRA_CLIENT_IDLE;
        return WH_ERROR_ABORTED;
    }

    /* When dlen == 0 the firmware sent no payload; data is not accessed and
     * NULL is acceptable.  The data == NULL check is only needed when there
     * are bytes to copy (dlen > 0). */
    if (dlen > 0U) {
        if (data == NULL) {
            /* dlen <= WH_COMM_MTU here (checked above), so
             * (dlen + 3U) / 4U cannot overflow uint32_t. */
            caliptra_fifo_drain(mbox_base, (dlen + 3U) / 4U);
            (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
            ctx->state = WH_CALIPTRA_CLIENT_IDLE;
            return WH_ERROR_BADARGS;
        }
        rc = caliptra_fifo_read(mbox_base, (uint8_t *)data, dlen);
        if (rc != WH_ERROR_OK) {
            (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
            ctx->state = WH_CALIPTRA_CLIENT_IDLE;
            return WH_ERROR_ABORTED;
        }
    }

    (void)caliptra_reg_write(mbox_base, WH_CALIPTRA_REG_EXECUTE, 0U);
    ctx->state = WH_CALIPTRA_CLIENT_IDLE;

    if (out_size != NULL) {
        *out_size = (uint16_t)dlen;
    }
    return WH_ERROR_OK;
}

int wh_TransportCaliptra_ClientCleanup(void *context)
{
    whTransportCaliptraClientContext *ctx = context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* If a request is in flight, attempt to release the mailbox so the
     * hardware is not left locked after the client tears down.
     *
     * Hardware caveat: writing EXECUTE=0 while firmware STATUS=BUSY is not
     * part of the normal Caliptra protocol and its effect is implementation-
     * defined.  The UNLOCK register (0x020) is SoC-read-only in hardware so
     * there is no clean abort path; if this write does not release the lock
     * the mailbox will remain locked until a system reset. */
    if (ctx->initialized && ctx->state == WH_CALIPTRA_CLIENT_PENDING) {
        (void)caliptra_reg_write(ctx->mbox_base,
                                 WH_CALIPTRA_REG_EXECUTE, 0U);
    }

    if (ctx->connectcb != NULL) {
        (void)ctx->connectcb(ctx->connectcb_arg, WH_COMM_DISCONNECTED);
    }

    memset(ctx, 0, sizeof(*ctx));
    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */


/* =========================================================================
 * Server transport implementation (Caliptra firmware side)
 * ========================================================================= */

#if defined(WOLFHSM_CFG_ENABLE_SERVER)

int wh_TransportCaliptra_ServerInit(void *context, const void *config,
        whCommSetConnectedCb connectcb, void *connectcb_arg)
{
    whTransportCaliptraServerContext *ctx = context;

    /* config is intentionally unused: the server transport has no hardware
     * dependencies of its own and does not need the mailbox base address or
     * command ID.  The parameter is retained for API consistency with the
     * transport callback signature. */
    (void)config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->connectcb     = connectcb;
    ctx->connectcb_arg = connectcb_arg;
    ctx->req_pending   = 0;
    ctx->req_size      = 0;
    ctx->resp_size     = 0;
    ctx->initialized   = 1;

    if (connectcb != NULL) {
        (void)connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }

    return WH_ERROR_OK;
}

/*
 * Deliver a wolfHSM request to the server comm layer.
 *
 * Called internally by wh_Server_HandleRequestMessage() via
 * wh_CommServer_RecvRequest().  Returns NOTREADY until SetRequest() has
 * been called by the Caliptra runtime handler.  req_pending is NOT cleared
 * here; it is cleared in ServerSend() when the response is produced, so
 * both buffers remain valid throughout the full Recv → Send cycle.
 */
int wh_TransportCaliptra_ServerRecv(void *context, uint16_t *out_size,
        void *data)
{
    whTransportCaliptraServerContext *ctx = context;

    if (ctx == NULL || !ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->req_pending) {
        return WH_ERROR_NOTREADY;
    }

    /* Reject NULL data when there are bytes to copy; mirrors the symmetric
     * guard in ServerSend (size > 0 && data == NULL -> BADARGS).  Without
     * this check, *out_size would report bytes that were never written. */
    if (data == NULL && ctx->req_size > 0U) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->req_size > 0U) {
        memcpy(data, ctx->req_buf, ctx->req_size);
    }

    if (out_size != NULL) {
        *out_size = ctx->req_size;
    }

    return WH_ERROR_OK;
}

/*
 * Accept the wolfHSM response from the server comm layer.
 *
 * Called internally by wh_Server_HandleRequestMessage() via
 * wh_CommServer_SendResponse().  Stores the response payload and clears
 * req_pending so ServerGetResponse() can deliver it to the Caliptra handler.
 */
int wh_TransportCaliptra_ServerSend(void *context, uint16_t size,
        const void *data)
{
    whTransportCaliptraServerContext *ctx = context;

    if (ctx == NULL || !ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    /* Reject a non-zero size with a NULL data pointer unconditionally.
     * Without this guard, resp_size would be set to a nonzero value while
     * resp_buf is left unchanged, causing ServerGetResponse to copy stale
     * bytes and report them as a valid response.  Matches the defensive
     * pattern used by wh_TransportMem_SendResponse. */
    if (size > 0U && data == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check MTU before req_pending: oversized payloads are unconditionally
     * invalid regardless of transport state.  Checking the static message
     * invariant first means callers get WH_ERROR_BADARGS (not NOTREADY) for
     * oversized sends, which is the correct error for a malformed message. */
    if (size > (uint16_t)WH_COMM_MTU) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->req_pending) {
        /* Send called without a preceding successful Recv. */
        return WH_ERROR_NOTREADY;
    }

    if (size > 0U) {
        memcpy(ctx->resp_buf, data, size);
    }
    ctx->resp_size   = size;
    ctx->req_pending = 0;

    return WH_ERROR_OK;
}

int wh_TransportCaliptra_ServerCleanup(void *context)
{
    whTransportCaliptraServerContext *ctx = context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->connectcb != NULL) {
        (void)ctx->connectcb(ctx->connectcb_arg, WH_COMM_DISCONNECTED);
    }

    memset(ctx, 0, sizeof(*ctx));
    return WH_ERROR_OK;
}


/* =========================================================================
 * Caliptra runtime integration API
 * ========================================================================= */

int wh_TransportCaliptra_ServerSetRequest(
        whTransportCaliptraServerContext *ctx,
        const uint8_t *data, uint16_t size)
{
    if (ctx == NULL || !ctx->initialized || data == NULL ||
            size == 0U || size > (uint16_t)WH_COMM_MTU) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->req_pending) {
        /* Previous exchange not yet complete: HandleRequestMessage has not
         * returned OK and GetResponse has not been called.  The Caliptra
         * mailbox hardware serialises commands, so this should not occur in
         * normal operation.  Return NOTREADY rather than silently dropping
         * or overwriting the in-progress exchange. */
        return WH_ERROR_NOTREADY;
    }

    memcpy(ctx->req_buf, data, size);
    ctx->req_size  = size;
    /* Reset resp_size to 0 so that a GetResponse call after the new exchange
     * does not return stale bytes from the previous one. */
    ctx->resp_size   = 0U;
    ctx->req_pending = 1;

    return WH_ERROR_OK;
}

int wh_TransportCaliptra_ServerGetResponse(
        whTransportCaliptraServerContext *ctx,
        uint8_t *data, uint16_t *out_size)
{
    if (ctx == NULL || !ctx->initialized || out_size == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->req_pending) {
        /* ServerSend() has not been called: the wolfHSM server has not yet
         * produced a response.  Keep calling HandleRequestMessage. */
        return WH_ERROR_NOTREADY;
    }

    /* data == NULL is only an error when there are bytes to copy.  When
     * resp_size == 0 (CMD_COMPLETE, no response payload) the caller need not
     * supply a buffer.  This mirrors the ClientRecv pattern: data is checked
     * only when dlen > 0 (lines 482-490 of this file). */
    if (ctx->resp_size > 0U) {
        if (data == NULL) {
            return WH_ERROR_BADARGS;
        }
        memcpy(data, ctx->resp_buf, ctx->resp_size);
    }
    *out_size      = ctx->resp_size;
    ctx->resp_size = 0U; /* consumed; a second call returns 0 bytes */

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
