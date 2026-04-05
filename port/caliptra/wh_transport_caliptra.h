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
 * port/caliptra/wh_transport_caliptra.h
 *
 * wolfHSM transport binding for the Caliptra hardware security module mailbox.
 *
 * Deployment status: UNLIKELY TO BE USEFUL WITHOUT A MANUFACTURER PARTNERSHIP
 * ----------------------------------------------------------------------------
 * This transport requires wolfHSM SERVER to be embedded in the Caliptra
 * runtime firmware as a custom mailbox command handler.  Standard Caliptra
 * firmware (caliptra-sw) does not include wolfHSM SERVER and cannot be
 * modified by end-users — it is supplied by the chip manufacturer.
 *
 * Deploying this transport therefore requires the chip manufacturer to:
 *   1. Integrate wolfHSM SERVER into their Caliptra RT firmware build.
 *   2. Register the "WHSM" custom command handler.
 *   3. Ship the modified firmware in their silicon.
 *
 * Without a formal partnership with a Caliptra-based chip manufacturer, this
 * transport has no viable deployment path.  If you are looking for a way to
 * use wolfHSM with a Caliptra-equipped chip running stock firmware, see
 * port/caliptra/caliptra_hwmodel.c for the host-side CryptoCb approach.
 *
 * Overview
 * --------
 * This transport connects a wolfHSM client running on the SoC to a wolfHSM
 * server running inside Caliptra's RISC-V runtime firmware.  Communication
 * occurs through the Caliptra hardware mailbox MMIO interface.  A dedicated
 * mailbox command ID ("WHSM", 0x5748534D) tunnels wolfHSM packets through the
 * mailbox without conflicting with Caliptra's native command set.
 *
 * Client side (runs on SoC)
 * -------------------------
 * wh_TransportCaliptra_ClientInit() connects immediately (the mailbox is
 * always available after Caliptra firmware is running).  Send() acquires the
 * hardware mailbox lock, writes the wolfHSM packet to the data-in FIFO using
 * 4-byte aligned writes, and triggers execution.  Recv() polls the STATUS
 * register non-blockingly and reads the response from the data-out FIFO once
 * the firmware signals completion.  Both Send() and Recv() return
 * WH_ERROR_NOTREADY if the hardware is not ready and must be retried.
 *
 * Server side (runs inside Caliptra firmware)
 * -------------------------------------------
 * The Caliptra runtime must register a custom command handler for
 * WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID.  The handler drives the exchange:
 *
 *   1. Read the request payload from the mailbox SRAM (directly mapped in the
 *      RISC-V address space at the address your platform provides).
 *   2. Call wh_TransportCaliptra_ServerSetRequest() to inject the payload.
 *   3. Call wh_Server_HandleRequestMessage() until it returns 0 or a fatal
 *      error.  The wolfHSM server calls ServerRecv/ServerSend internally.
 *   4. On success, call wh_TransportCaliptra_ServerGetResponse() to retrieve
 *      the wolfHSM response buffer.
 *   5. Write the response bytes to the mailbox output SRAM and signal
 *      DATA_READY (or CMD_COMPLETE for a zero-length response).
 *
 * The server transport has no hardware dependencies of its own; all mailbox
 * SRAM access is the caller's responsibility.
 *
 * Dependencies
 * ------------
 * Client: caliptra_if.h (caliptra_write_u32 / caliptra_read_u32).
 *         Include the libcaliptra/inc/ directory in your build.
 * Server: none beyond wolfHSM headers.
 *
 * Byte ordering contract (client side)
 * -------------------------------------
 * This transport assumes that caliptra_write_u32(addr, val) stores 'val'
 * in little-endian byte order in the DATAIN FIFO, and that
 * caliptra_read_u32(addr, &val) returns DATAOUT words encoded as
 * little-endian values (bit 0 of the returned uint32_t is the first byte
 * the Caliptra firmware enqueued).
 *
 * This matches the reference libcaliptra implementation, where the
 * platform HAL performs a byte-swap before the MMIO store on big-endian
 * SoCs.  If your platform's caliptra_write_u32 performs a raw native-
 * endian MMIO write without any byte conversion, this transport will
 * silently corrupt every wolfHSM packet on a big-endian SoC host.
 * Consult your SoC integration guide to verify which behaviour your HAL
 * implements before deploying on a BE platform.
 *
 * Configuration macros
 * --------------------
 * WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE
 *   Absolute address of the Caliptra mailbox CSR block.
 *   Default: EXTERNAL_PERIPH_BASE (0x30000000) + MBOX_CSR_BASE (0x00020000)
 *            = 0x30020000.  Override if your SoC places Caliptra differently.
 *
 * WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID
 *   Caliptra mailbox command ID used to identify wolfHSM packets.
 *   Default: 0x5748534D ("WHSM" ASCII).  Override only if this value
 *   conflicts with another handler registered on your platform.
 *
 * Example client wiring
 * ---------------------
 *   whTransportCaliptraConfig   cfg[1] = {{ .mbox_base = 0, .cmd_id = 0 }};
 *   whTransportCaliptraClientContext ctx[1];
 *   memset(ctx, 0, sizeof(*ctx));
 *
 *   whTransportClientCb cb[1] = {WH_TRANSPORT_CALIPTRA_CLIENT_CB};
 *   whCommClientConfig  cc[1] = {{
 *       .transport_cb      = cb,
 *       .transport_context = ctx,
 *       .transport_config  = cfg,
 *       .client_id         = 1,
 *   }};
 *   whClientConfig client_cfg[1] = {{ .comm = cc }};
 *   whClientContext client[1];
 *   wh_Client_Init(client, client_cfg);
 *
 * Example server wiring (Caliptra runtime)
 * ----------------------------------------
 *   // The server transport has no MMIO dependency; its ServerInit() ignores
 *   // the config argument entirely.  NULL or a zero-initialised struct both
 *   // work; the struct is shown here only for API symmetry with the client.
 *   whTransportCaliptraConfig    cfg[1] = {{ .mbox_base = 0, .cmd_id = 0 }};
 *   whTransportCaliptraServerContext ctx[1];
 *   memset(ctx, 0, sizeof(*ctx));
 *
 *   whTransportServerCb  cb[1] = {WH_TRANSPORT_CALIPTRA_SERVER_CB};
 *   whCommServerConfig   sc[1] = {{
 *       .transport_cb      = cb,
 *       .transport_context = ctx,
 *       .transport_config  = cfg,
 *       .server_id         = 1,
 *   }};
 *   // whServerContext setup omitted for brevity ...
 *
 *   // Inside the Caliptra custom command handler for WHSM:
 *   int whsm_handler(const uint8_t *req_data, uint16_t req_size) {
 *       uint8_t  resp[WH_COMM_MTU];
 *       uint16_t resp_size = 0;
 *
 *       int rc = wh_TransportCaliptra_ServerSetRequest(ctx, req_data, req_size);
 *       if (rc != WH_ERROR_OK) return rc;
 *
 *       // For this transport, SetRequest loads the buffer and ServerSend is
 *       // called synchronously inside HandleRequestMessage; NOTREADY is
 *       // never returned.  The loop is retained so this snippet can be
 *       // copied unchanged to async transports that do return NOTREADY.
 *       do {
 *           rc = wh_Server_HandleRequestMessage(server);
 *       } while (rc == WH_ERROR_NOTREADY);
 *       if (rc != WH_ERROR_OK) {
 *           // wolfHSM server error; reset transport state
 *           wh_TransportCaliptra_ServerCleanup(ctx);
 *           wh_TransportCaliptra_ServerInit(ctx, cfg, NULL, NULL);
 *           return rc;
 *       }
 *
 *       rc = wh_TransportCaliptra_ServerGetResponse(ctx, resp, &resp_size);
 *       if (rc != WH_ERROR_OK) return rc;
 *
 *       // Write resp[0..resp_size] to mailbox output SRAM and set DATA_READY
 *       return 0;
 *   }
 */

#ifndef PORT_CALIPTRA_WH_TRANSPORT_CALIPTRA_H_
#define PORT_CALIPTRA_WH_TRANSPORT_CALIPTRA_H_

#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

/*
 * Hardware constants
 * ------------------
 * Derived from caliptra_top_reg.h (Caliptra register specification):
 *   EXTERNAL_PERIPH_BASE            = 0x30000000
 *   CALIPTRA_TOP_REG_MBOX_CSR_BASE  = 0x00020000
 *   Absolute mailbox CSR base       = 0x30020000
 *
 * All register offsets are relative to the mailbox CSR base address.
 */

/** Default Caliptra mailbox CSR absolute base address.
 *  Override via WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE. */
#ifndef WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE
#define WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE  (0x30020000UL)
#endif

/** Caliptra mailbox command ID used to tunnel wolfHSM packets.
 *  "WHSM" in ASCII; absent from Caliptra's native command enumeration.
 *  Override via WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID. */
#ifndef WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID
#define WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID     (0x5748534DUL)
#endif

/* Mailbox CSR register offsets (bytes from mailbox CSR base). */
#define WH_CALIPTRA_REG_LOCK     (0x000U) /* Atomic lock acquire (read-only) */
#define WH_CALIPTRA_REG_CMD      (0x008U) /* Command register   (write-only) */
#define WH_CALIPTRA_REG_DLEN     (0x00CU) /* Data length in bytes            */
#define WH_CALIPTRA_REG_DATAIN   (0x010U) /* Data-in FIFO: SoC → Caliptra    */
#define WH_CALIPTRA_REG_DATAOUT  (0x014U) /* Data-out FIFO: Caliptra → SoC   */
#define WH_CALIPTRA_REG_EXECUTE  (0x018U) /* Write 1: trigger; write 0: done */
#define WH_CALIPTRA_REG_STATUS   (0x01CU) /* Status register (read-only)     */
#define WH_CALIPTRA_REG_UNLOCK   (0x020U) /* Force-unlock (Caliptra-RW, SoC-RO; SoC writes are ignored) */

/* LOCK register: bit 0.
 * Reading this register is an atomic test-and-set operation:
 *   bit == 0  →  lock was free; we have acquired it; proceed.
 *   bit == 1  →  lock is held by another agent; do not proceed. */
#define WH_CALIPTRA_LOCK_MASK    (0x00000001UL)

/* STATUS register: status field bits [3:0]. */
#define WH_CALIPTRA_STATUS_MASK  (0x0000000FUL)

/** Caliptra mailbox status values (STATUS register bits [3:0]). */
enum whCaliptraMboxStatus {
    WH_CALIPTRA_MBOX_ST_BUSY         = 0, /* Firmware still processing */
    WH_CALIPTRA_MBOX_ST_DATA_READY   = 1, /* Response data available   */
    WH_CALIPTRA_MBOX_ST_CMD_COMPLETE = 2, /* Success, no response data */
    WH_CALIPTRA_MBOX_ST_CMD_FAILURE  = 3, /* Firmware reported failure */
};

/*
 * Common configuration
 * --------------------
 * Shared by both client and server Init() calls.  Zero-initialise fields to
 * select defaults (mbox_base = 0 → use WOLFHSM_CFG_TRANSPORT_CALIPTRA_MBOX_BASE;
 * cmd_id = 0 → use WOLFHSM_CFG_TRANSPORT_CALIPTRA_CMD_ID).
 *
 * Sentinel limitation: 0 is reserved as "use compile-time default" for both
 * fields.  Physical address 0x00000000 and command ID 0x00000000 cannot be
 * selected at runtime.  If your SoC requires either of these values, define
 * the corresponding WOLFHSM_CFG_TRANSPORT_CALIPTRA_* macro at build time.
 */
typedef struct {
    uint32_t mbox_base; /* Caliptra MMIO base address; 0 = use compile-time default */
    uint32_t cmd_id;    /* wolfHSM mailbox command ID; 0 = use compile-time default */
} whTransportCaliptraConfig;


/* =========================================================================
 * Client transport (SoC side)
 * ========================================================================= */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)

/** Client connection state. */
typedef enum {
    WH_CALIPTRA_CLIENT_IDLE    = 0, /* Ready to send a new request  */
    WH_CALIPTRA_CLIENT_PENDING = 1, /* Request sent; awaiting reply */
} whCaliptraClientState;

/** Client transport context.  Zero-initialise before calling ClientInit(). */
typedef struct {
    whCommSetConnectedCb connectcb;     /* Stored from Init; may be NULL */
    void                *connectcb_arg;
    uint32_t             mbox_base;     /* Resolved mailbox CSR base     */
    uint32_t             cmd_id;        /* Resolved wolfHSM command ID   */
    whCaliptraClientState state;
    int                  initialized;
} whTransportCaliptraClientContext;

int wh_TransportCaliptra_ClientInit(void *context, const void *config,
        whCommSetConnectedCb connectcb, void *connectcb_arg);

int wh_TransportCaliptra_ClientSend(void *context, uint16_t size,
        const void *data);

int wh_TransportCaliptra_ClientRecv(void *context, uint16_t *out_size,
        void *data);

/** Clean up a client transport context.
 *
 *  If a request is in flight (state == PENDING), this function makes a
 *  best-effort attempt to release the mailbox by writing EXECUTE = 0.
 *
 *  @warning On real Caliptra hardware, calling this function while a request
 *           is in flight may leave the mailbox locked until a system reset.
 *           Writing EXECUTE = 0 while firmware STATUS = BUSY is not part of
 *           the Caliptra protocol and its effect is implementation-defined.
 *           The UNLOCK register (0x020) is SoC-read-only; there is no
 *           guaranteed software abort path.  Callers must not destroy the
 *           client context while a request is in flight on real hardware.
 *           The EXECUTE = 0 write is a best-effort mitigation for crash or
 *           test teardown scenarios only; do not rely on it in production. */
int wh_TransportCaliptra_ClientCleanup(void *context);

/** Callback table initialiser for whCommClientConfig.transport_cb. */
#define WH_TRANSPORT_CALIPTRA_CLIENT_CB                      \
{                                                            \
    .Init    = wh_TransportCaliptra_ClientInit,              \
    .Send    = wh_TransportCaliptra_ClientSend,              \
    .Recv    = wh_TransportCaliptra_ClientRecv,              \
    .Cleanup = wh_TransportCaliptra_ClientCleanup,           \
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */


/* =========================================================================
 * Server transport (Caliptra firmware side)
 * ========================================================================= */

#if defined(WOLFHSM_CFG_ENABLE_SERVER)

/** Server transport context.  Zero-initialise before calling ServerInit().
 *
 *  Memory note: contains two WH_COMM_MTU-sized buffers
 *  (default 2 × 1288 = 2576 bytes).  Allocate on the heap or statically;
 *  do not allocate on an interrupt stack. */
typedef struct {
    whCommSetConnectedCb connectcb;
    void                *connectcb_arg;
    int                  initialized;
    int                  req_pending;    /* Non-zero: request injected, not
                                          * yet fully served (Recv called but
                                          * Send not yet called)              */
    uint16_t             req_size;       /* Byte count of current request      */
    uint16_t             resp_size;      /* Byte count of current response     */
    uint8_t              req_buf[WH_COMM_MTU];
    uint8_t              resp_buf[WH_COMM_MTU];
} whTransportCaliptraServerContext;

int wh_TransportCaliptra_ServerInit(void *context, const void *config,
        whCommSetConnectedCb connectcb, void *connectcb_arg);

int wh_TransportCaliptra_ServerRecv(void *context, uint16_t *out_size,
        void *data);

int wh_TransportCaliptra_ServerSend(void *context, uint16_t size,
        const void *data);

int wh_TransportCaliptra_ServerCleanup(void *context);

/** Callback table initialiser for whCommServerConfig.transport_cb. */
#define WH_TRANSPORT_CALIPTRA_SERVER_CB                      \
{                                                            \
    .Init    = wh_TransportCaliptra_ServerInit,              \
    .Recv    = wh_TransportCaliptra_ServerRecv,              \
    .Send    = wh_TransportCaliptra_ServerSend,              \
    .Cleanup = wh_TransportCaliptra_ServerCleanup,           \
}

/*
 * Caliptra runtime integration API
 * ---------------------------------
 * These functions are called by the Caliptra custom command handler, not by
 * wolfHSM internals.  They bridge the mailbox SRAM read/write (done by the
 * Caliptra runtime) with the wolfHSM server's transport Recv/Send calls.
 *
 * Typical call sequence in the WHSM command handler:
 *   1. wh_TransportCaliptra_ServerSetRequest(ctx, req_bytes, req_size)
 *   2. wh_Server_HandleRequestMessage(server)   [may need one or more calls]
 *   3. wh_TransportCaliptra_ServerGetResponse(ctx, resp_buf, &resp_size)
 *   4. Write resp_buf[0..resp_size] to mailbox output SRAM.
 */

/** Inject an incoming wolfHSM request payload read from the mailbox SRAM.
 *
 *  @param ctx      Server transport context (must be initialised).
 *  @param data     Pointer to the request bytes copied from mailbox SRAM.
 *  @param size     Number of valid request bytes.  Must be > 0 and
 *                  <= WH_COMM_MTU.
 *
 *  @return WH_ERROR_OK       Request accepted; call HandleRequestMessage next.
 *  @return WH_ERROR_BADARGS  ctx or data is NULL, or size is out of range.
 *  @return WH_ERROR_NOTREADY Previous exchange not yet complete (the prior
 *                            HandleRequestMessage + GetResponse sequence has
 *                            not finished).  The handler must not submit a new
 *                            request until the current one is resolved. */
int wh_TransportCaliptra_ServerSetRequest(
        whTransportCaliptraServerContext *ctx,
        const uint8_t *data, uint16_t size);

/** Retrieve the wolfHSM response payload to be written to the mailbox SRAM.
 *
 *  Call after wh_Server_HandleRequestMessage() returns WH_ERROR_OK.
 *
 *  @param ctx       Server transport context.
 *  @param data      Caller-supplied buffer to receive the response bytes.
 *                   Must be at least WH_COMM_MTU bytes when *out_size > 0.
 *                   May be NULL when the response carries no payload
 *                   (*out_size will be set to 0 on return).
 *  @param out_size  On success, set to the response byte count.  May be 0
 *                   if the wolfHSM response carries no payload.
 *
 *  @return WH_ERROR_OK       Response retrieved; *out_size is valid.
 *                            If *out_size > 0, data[0..*out_size] contains
 *                            the response bytes.
 *  @return WH_ERROR_BADARGS  ctx or out_size is NULL; or data is NULL and
 *                            the response carries a non-zero payload.
 *  @return WH_ERROR_NOTREADY HandleRequestMessage has not yet produced a
 *                            response (Send has not been called).  Keep
 *                            calling HandleRequestMessage. */
int wh_TransportCaliptra_ServerGetResponse(
        whTransportCaliptraServerContext *ctx,
        uint8_t *data, uint16_t *out_size);

#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#endif /* PORT_CALIPTRA_WH_TRANSPORT_CALIPTRA_H_ */
