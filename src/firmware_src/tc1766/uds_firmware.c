/*
 * uds_firmware.c - ICSim UDS target for Infineon TriCore TC1766
 *
 * Build:   tricore-elf-gcc -mcpu=tc1766 -Os -ffunction-sections -fdata-sections \
 *                      -T tc1766_flash.ld -nostdlib -Wl,--gc-sections \
 *                      -o uds_firmware.elf uds_firmware.c
 */

#include "uds_firmware.h"

/* ========================================================================
 *  Minimal libc stubs - required when -nostdlib; GCC may lower struct
 *  copies or loop-fills into calls to these even with -Os.
 * ====================================================================== */
void *memcpy(void *dst, const void *src, __SIZE_TYPE__ n) {
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memset(void *dst, int c, __SIZE_TYPE__ n) {
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}

/* ========================================================================
 *  .rodata - firmware header, tables, constants.  Lives in PFLASH0.
 * ====================================================================== */

/* ECU identification - DID 0xF190 (VIN) matches ICSim's VIN macro. */
static const char  VIN_STRING[17]          = "WBARBHACKFA149850";
static const char  ECU_HW_NUMBER[11]       = "TC1766-ECU";
static const char  ECU_SW_VERSION[8]       = "1.07.00";
static const char  ECU_SUPPLIER_ID[5]      = "BBK24";
static const char  PART_NUMBER[12]         = "IC-SIM-ECU1";
static const char  MANUFACTURER_NAME[9]    = "Barbhack";

/* Secret XOR key used by SecurityAccess (level 0x01/0x02).
 * ICSim uses a 2-byte sessionKey; we mirror that here so the
 * generated binary has a reproducible key for RE exercises. */
static const uint8_t SECURITY_KEY[2] = { 0xBB, 0x24 };

/* ========================================================================
 *  .data / .bss - runtime state, linker copies from PFLASH to LDRAM.
 * ====================================================================== */

static uds_session_t g_session        = SESSION_DEFAULT;
static uds_sec_level_t g_sec_level    = SEC_LOCKED;
static uint8_t g_seed[2];
static uint8_t g_seed_valid           = 0u;
static uint32_t g_last_tester_present = 0u;

/* Writable DID storage (only reachable via WRITE_DATA_BY_IDENTIFIER 0x2E
 * after SecurityAccess succeeds). */
static uint8_t g_did_odometer[4]      = { 0x00, 0x01, 0x86, 0xA0 }; /* 100000 km */
static uint8_t g_did_asm_cfg[2]       = { 0x00, 0x00 };

/* ========================================================================
 *  Minimal PRNG - deterministic so RE can solve the seed/key challenge.
 * ====================================================================== */
static uint32_t g_rng_state = 0xDEADBEEFu;

static uint32_t prng_next(void) {
    /* xorshift32 */
    uint32_t x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x;
    return x;
}

/* ========================================================================
 *  DID handlers - array-of-structs with per-DID read/write callbacks.
 * ====================================================================== */

static uint8_t did_read_static(uint8_t *out, uint16_t *len, const void *src, uint16_t n) {
    const uint8_t *p = (const uint8_t *)src;
    for (uint16_t i = 0; i < n; ++i) out[i] = p[i];
    *len = n;
    return 0u; /* 0 = success, else NRC */
}

static uint8_t did_read_vin(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, VIN_STRING, (uint16_t)sizeof(VIN_STRING));
}
static uint8_t did_read_hwnum(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, ECU_HW_NUMBER, (uint16_t)sizeof(ECU_HW_NUMBER));
}
static uint8_t did_read_swver(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, ECU_SW_VERSION, (uint16_t)sizeof(ECU_SW_VERSION));
}
static uint8_t did_read_supplier(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, ECU_SUPPLIER_ID, (uint16_t)sizeof(ECU_SUPPLIER_ID));
}
static uint8_t did_read_partnum(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, PART_NUMBER, (uint16_t)sizeof(PART_NUMBER));
}
static uint8_t did_read_manufacturer(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, MANUFACTURER_NAME, (uint16_t)sizeof(MANUFACTURER_NAME));
}
static uint8_t did_read_odometer(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, g_did_odometer, sizeof(g_did_odometer));
}
static uint8_t did_read_asm_cfg(uint8_t *out, uint16_t *len) {
    return did_read_static(out, len, g_did_asm_cfg, sizeof(g_did_asm_cfg));
}

static uint8_t did_write_odometer(const uint8_t *in, uint16_t len) {
    if (len != sizeof(g_did_odometer)) return NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT;
    for (uint16_t i = 0; i < len; ++i) g_did_odometer[i] = in[i];
    return 0u;
}
static uint8_t did_write_asm_cfg(const uint8_t *in, uint16_t len) {
    if (len != sizeof(g_did_asm_cfg)) return NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT;
    for (uint16_t i = 0; i < len; ++i) g_did_asm_cfg[i] = in[i];
    return 0u;
}

/* DID table - kept const so it lands in PFLASH.
 * Order is arbitrary; lookup is linear to keep the binary compact. */
const did_entry_t g_did_table[] = {
    { 0xF190u, 17u, DID_ACC_READ,                              0u,
      did_read_vin,          NULL,               NULL,            "VIN"           },
    { 0xF191u, 11u, DID_ACC_READ,                              0u,
      did_read_hwnum,        NULL,               NULL,            "ECU_HW_NUMBER" },
    { 0xF189u,  8u, DID_ACC_READ,                              0u,
      did_read_swver,        NULL,               NULL,            "ECU_SW_VERSION"},
    { 0xF18Au,  5u, DID_ACC_READ,                              0u,
      did_read_supplier,     NULL,               NULL,            "SUPPLIER_ID"   },
    { 0xF187u, 12u, DID_ACC_READ,                              0u,
      did_read_partnum,      NULL,               NULL,            "PART_NUMBER"   },
    { 0xF18Bu,  9u, DID_ACC_READ,                              0u,
      did_read_manufacturer, NULL,               NULL,            "MANUFACTURER"  },
    { 0x0101u,  4u, DID_ACC_READ | DID_ACC_WRITE | DID_ACC_SEC_REQUIRED,  0u,
      did_read_odometer,     did_write_odometer, g_did_odometer,  "ODOMETER"      },
    { 0x0202u,  2u, DID_ACC_READ | DID_ACC_WRITE | DID_ACC_EXT_SESSION,   0u,
      did_read_asm_cfg,      did_write_asm_cfg,  g_did_asm_cfg,   "ASM_CFG"       },
};
const size_t g_did_table_size = sizeof(g_did_table) / sizeof(g_did_table[0]);

static const did_entry_t *did_lookup(uint16_t did) {
    for (size_t i = 0; i < g_did_table_size; ++i) {
        if (g_did_table[i].did == did) return &g_did_table[i];
    }
    return NULL;
}

/* ========================================================================
 *  Response helpers
 * ====================================================================== */

static uint8_t make_positive(uds_msg_t *resp, uint8_t sid) {
    resp->data[0] = (uint8_t)(sid | SID_POSITIVE_RESPONSE_MASK);
    resp->len = 1u;
    return 0u;
}

static uint8_t make_negative(uds_msg_t *resp, uint8_t sid, uint8_t nrc) {
    resp->data[0] = SID_NEGATIVE_RESPONSE;
    resp->data[1] = sid;
    resp->data[2] = nrc;
    resp->len = 3u;
    return nrc;
}

/* ========================================================================
 *  Service handlers - one per SID.
 * ====================================================================== */

static uint8_t svc_session_control(const uds_msg_t *req, uds_msg_t *resp) {
    if (req->len != 2u) {
        return make_negative(resp, SID_DIAGNOSTIC_SESSION_CONTROL,
                             NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    uint8_t sub = req->data[1];
    if (sub != SESSION_DEFAULT && sub != SESSION_PROGRAMMING && sub != SESSION_EXTENDED) {
        return make_negative(resp, SID_DIAGNOSTIC_SESSION_CONTROL,
                             NRC_SUB_FUNCTION_NOT_SUPPORTED);
    }
    g_session    = (uds_session_t)sub;
    g_sec_level  = SEC_LOCKED;
    g_seed_valid = 0u;

    (void)make_positive(resp, SID_DIAGNOSTIC_SESSION_CONTROL);
    resp->data[1] = sub;
    /* P2/P2* timing (50ms / 5000ms) - cosmetic but realistic in an ECU image */
    resp->data[2] = 0x00u; resp->data[3] = 0x32u;   /* P2    = 50 ms    */
    resp->data[4] = 0x01u; resp->data[5] = 0xF4u;   /* P2*   = 5000 ms  */
    resp->len = 6u;
    return 0u;
}

static uint8_t svc_ecu_reset(const uds_msg_t *req, uds_msg_t *resp) {
    if (req->len != 2u) {
        return make_negative(resp, SID_ECU_RESET, NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    uint8_t sub = req->data[1];
    if (sub == 0u || sub > 0x03u) {
        return make_negative(resp, SID_ECU_RESET, NRC_SUB_FUNCTION_NOT_SUPPORTED);
    }
    g_session    = SESSION_DEFAULT;
    g_sec_level  = SEC_LOCKED;
    g_seed_valid = 0u;

    (void)make_positive(resp, SID_ECU_RESET);
    resp->data[1] = sub;
    resp->len     = 2u;
    /* Real ECU would now pet WDT until window expires; left as TODO for the RE. */
    return 0u;
}

static uint8_t svc_tester_present(const uds_msg_t *req, uds_msg_t *resp) {
    if (req->len != 2u) {
        return make_negative(resp, SID_TESTER_PRESENT, NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    g_last_tester_present = STM_TIM0;
    uint8_t sub = req->data[1];
    (void)make_positive(resp, SID_TESTER_PRESENT);
    resp->data[1] = sub;
    resp->len     = 2u;
    return 0u;
}

static uint8_t svc_read_did(const uds_msg_t *req, uds_msg_t *resp) {
    if (req->len < 3u || ((req->len - 1u) % 2u) != 0u) {
        return make_negative(resp, SID_READ_DATA_BY_IDENTIFIER,
                             NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    resp->data[0] = SID_READ_DATA_BY_IDENTIFIER | SID_POSITIVE_RESPONSE_MASK;
    resp->len     = 1u;

    uint16_t n_ids = (uint16_t)((req->len - 1u) / 2u);
    for (uint16_t i = 0u; i < n_ids; ++i) {
        uint16_t did = (uint16_t)((req->data[1u + i*2u] << 8) | req->data[2u + i*2u]);
        const did_entry_t *e = did_lookup(did);
        if (!e || !(e->access_flags & DID_ACC_READ)) {
            return make_negative(resp, SID_READ_DATA_BY_IDENTIFIER,
                                 NRC_REQUEST_OUT_OF_RANGE);
        }
        if ((e->access_flags & DID_ACC_EXT_SESSION) && g_session == SESSION_DEFAULT) {
            return make_negative(resp, SID_READ_DATA_BY_IDENTIFIER,
                                 NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
        }
        if ((e->access_flags & DID_ACC_SEC_REQUIRED) && g_sec_level < SEC_LEVEL_1) {
            return make_negative(resp, SID_READ_DATA_BY_IDENTIFIER,
                                 NRC_SECURITY_ACCESS_DENIED);
        }
        if ((resp->len + 2u + e->length) > UDS_MAX_PAYLOAD) {
            return make_negative(resp, SID_READ_DATA_BY_IDENTIFIER,
                                 NRC_REQUEST_OUT_OF_RANGE);
        }
        resp->data[resp->len++] = (uint8_t)(did >> 8);
        resp->data[resp->len++] = (uint8_t)(did & 0xFFu);

        uint16_t n = 0u;
        uint8_t nrc = e->read(&resp->data[resp->len], &n);
        if (nrc != 0u) {
            return make_negative(resp, SID_READ_DATA_BY_IDENTIFIER, nrc);
        }
        resp->len = (uint16_t)(resp->len + n);
    }
    return 0u;
}

static uint8_t svc_write_did(const uds_msg_t *req, uds_msg_t *resp) {
    if (req->len < 4u) {
        return make_negative(resp, SID_WRITE_DATA_BY_IDENTIFIER,
                             NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    uint16_t did = (uint16_t)((req->data[1] << 8) | req->data[2]);
    const did_entry_t *e = did_lookup(did);
    if (!e || !(e->access_flags & DID_ACC_WRITE) || !e->write) {
        return make_negative(resp, SID_WRITE_DATA_BY_IDENTIFIER,
                             NRC_REQUEST_OUT_OF_RANGE);
    }
    if ((e->access_flags & DID_ACC_EXT_SESSION) && g_session == SESSION_DEFAULT) {
        return make_negative(resp, SID_WRITE_DATA_BY_IDENTIFIER,
                             NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if ((e->access_flags & DID_ACC_SEC_REQUIRED) && g_sec_level < SEC_LEVEL_1) {
        return make_negative(resp, SID_WRITE_DATA_BY_IDENTIFIER,
                             NRC_SECURITY_ACCESS_DENIED);
    }
    uint16_t data_len = (uint16_t)(req->len - 3u);
    if (data_len != e->length) {
        return make_negative(resp, SID_WRITE_DATA_BY_IDENTIFIER,
                             NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    uint8_t nrc = e->write(&req->data[3], data_len);
    if (nrc != 0u) {
        return make_negative(resp, SID_WRITE_DATA_BY_IDENTIFIER, nrc);
    }
    resp->data[0] = SID_WRITE_DATA_BY_IDENTIFIER | SID_POSITIVE_RESPONSE_MASK;
    resp->data[1] = (uint8_t)(did >> 8);
    resp->data[2] = (uint8_t)(did & 0xFFu);
    resp->len     = 3u;
    return 0u;
}

static uint8_t svc_security_access(const uds_msg_t *req, uds_msg_t *resp) {
    if (g_session != SESSION_EXTENDED) {
        return make_negative(resp, SID_SECURITY_ACCESS,
                             NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (req->len < 2u) {
        return make_negative(resp, SID_SECURITY_ACCESS,
                             NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    uint8_t sub = req->data[1];
    switch (sub) {
    case 0x01u: /* request seed */
        if (req->len != 2u) {
            return make_negative(resp, SID_SECURITY_ACCESS,
                                 NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
        }
        {
            uint32_t r = prng_next();
            g_seed[0] = (uint8_t)(r & 0xFFu);
            g_seed[1] = (uint8_t)((r >> 8) & 0xFFu);
            g_seed_valid = 1u;
            resp->data[0] = SID_SECURITY_ACCESS | SID_POSITIVE_RESPONSE_MASK;
            resp->data[1] = sub;
            resp->data[2] = g_seed[0];
            resp->data[3] = g_seed[1];
            resp->len     = 4u;
        }
        return 0u;

    case 0x02u: /* send key */
        if (req->len != 4u) {
            return make_negative(resp, SID_SECURITY_ACCESS,
                                 NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
        }
        if (!g_seed_valid) {
            return make_negative(resp, SID_SECURITY_ACCESS,
                                 NRC_REQUEST_SEQUENCE_ERROR);
        }
        {
            uint8_t exp0 = (uint8_t)(g_seed[0] ^ SECURITY_KEY[0]);
            uint8_t exp1 = (uint8_t)(g_seed[1] ^ SECURITY_KEY[1]);
            g_seed_valid = 0u;
            if (req->data[2] != exp0 || req->data[3] != exp1) {
                g_sec_level = SEC_LOCKED;
                return make_negative(resp, SID_SECURITY_ACCESS, NRC_INVALID_KEY);
            }
            g_sec_level   = SEC_LEVEL_1;
            resp->data[0] = SID_SECURITY_ACCESS | SID_POSITIVE_RESPONSE_MASK;
            resp->data[1] = sub;
            resp->len     = 2u;
        }
        return 0u;

    default:
        return make_negative(resp, SID_SECURITY_ACCESS,
                             NRC_SUB_FUNCTION_NOT_SUPPORTED);
    }
}

static uint8_t svc_routine_control(const uds_msg_t *req, uds_msg_t *resp) {
    if (req->len < 4u) {
        return make_negative(resp, SID_ROUTINE_CONTROL,
                             NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
    }
    if (g_session != SESSION_PROGRAMMING) {
        return make_negative(resp, SID_ROUTINE_CONTROL,
                             NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    uint8_t  sub = req->data[1];
    uint16_t rid = (uint16_t)((req->data[2] << 8) | req->data[3]);

    if (sub != 0x01u && sub != 0x02u && sub != 0x03u) {
        return make_negative(resp, SID_ROUTINE_CONTROL,
                             NRC_SUB_FUNCTION_NOT_SUPPORTED);
    }
    /* Accept two well-known RIDs matching the ICSim workshop:
     *   0x4110 - normal diagnostic routine
     *   0x4122 - hidden / scored "secret" routine (challenge target) */
    if (rid != 0x4110u && rid != 0x4122u) {
        return make_negative(resp, SID_ROUTINE_CONTROL, NRC_REQUEST_OUT_OF_RANGE);
    }
    resp->data[0] = SID_ROUTINE_CONTROL | SID_POSITIVE_RESPONSE_MASK;
    resp->data[1] = sub;
    resp->data[2] = (uint8_t)(rid >> 8);
    resp->data[3] = (uint8_t)(rid & 0xFFu);
    resp->data[4] = 0x00u;  /* routine status = completed */
    resp->len     = 5u;
    return 0u;
}

/* ========================================================================
 *  Service table - ordered by SID, searched linearly by dispatcher.
 *  Lives in .rodata so a RE can see names/function pointers inline.
 * ====================================================================== */
const uds_service_t g_service_table[] = {
    { SID_DIAGNOSTIC_SESSION_CONTROL, 2u, SESSION_MASK_ALL,     0u,
      svc_session_control,  "DiagnosticSessionControl" },
    { SID_ECU_RESET,                  2u, SESSION_MASK_ALL,     0u,
      svc_ecu_reset,        "ECUReset"                 },
    { SID_READ_DATA_BY_IDENTIFIER,    3u, SESSION_MASK_ALL,     0u,
      svc_read_did,         "ReadDataByIdentifier"     },
    { SID_SECURITY_ACCESS,            2u, SESSION_MASK_EXT_ONLY,0u,
      svc_security_access,  "SecurityAccess"           },
    { SID_WRITE_DATA_BY_IDENTIFIER,   4u, SESSION_MASK_PROG_EXT,1u,
      svc_write_did,        "WriteDataByIdentifier"    },
    { SID_ROUTINE_CONTROL,            4u, SESSION_MASK_PROG_EXT,0u,
      svc_routine_control,  "RoutineControl"           },
    { SID_TESTER_PRESENT,             2u, SESSION_MASK_ALL,     0u,
      svc_tester_present,   "TesterPresent"            },
};
const size_t g_service_table_size =
    sizeof(g_service_table) / sizeof(g_service_table[0]);

static const uds_service_t *service_lookup(uint8_t sid) {
    for (size_t i = 0; i < g_service_table_size; ++i) {
        if (g_service_table[i].sid == sid) return &g_service_table[i];
    }
    return NULL;
}

/* ========================================================================
 *  Top-level UDS dispatcher
 * ====================================================================== */
static void uds_dispatch(const uds_msg_t *req, uds_msg_t *resp) {
    resp->len = 0u;
    if (req->len == 0u) return;

    uint8_t sid = req->data[0];
    const uds_service_t *svc = service_lookup(sid);
    if (!svc) {
        (void)make_negative(resp, sid, NRC_SERVICE_NOT_SUPPORTED);
        return;
    }
    if (req->len < svc->min_len) {
        (void)make_negative(resp, sid, NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT);
        return;
    }
    if (!(svc->session_mask & (uint8_t)(1u << (g_session - 1u)))) {
        (void)make_negative(resp, sid, NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
        return;
    }
    if (svc->requires_security && g_sec_level < SEC_LEVEL_1) {
        (void)make_negative(resp, sid, NRC_SECURITY_ACCESS_DENIED);
        return;
    }
    (void)svc->handler(req, resp);
}

/* ========================================================================
 *  ISO-TP (single-frame only) - sufficient for RDBI/WDBI up to 7 bytes
 *  of payload. Responses longer than 7 bytes fall back to first-frame
 *  + consecutive-frame flow.
 * ====================================================================== */
static uds_msg_t g_req_buf;
static uds_msg_t g_resp_buf;

static void iso_tp_handle_rx(const can_frame_t *f) {
    if (f->dlc == 0u) return;
    uint8_t pci_type = (uint8_t)(f->data[0] >> 4);
    if (pci_type != 0x0u) return;          /* only SF supported on RX */
    uint8_t len = (uint8_t)(f->data[0] & 0x0Fu);
    if (len == 0u || len > 7u) return;

    g_req_buf.len = len;
    for (uint8_t i = 0; i < len; ++i) {
        g_req_buf.data[i] = f->data[1u + i];
    }
    uds_dispatch(&g_req_buf, &g_resp_buf);

    can_frame_t tx;
    uint8_t i;
    tx.id  = CAN_ID_DIAG_RESP;
    tx.dlc = 8u;
    for (i = 0u; i < 8u; ++i) tx.data[i] = 0u;

    if (g_resp_buf.len <= 7u) {
        /* Single frame */
        tx.data[0] = (uint8_t)(g_resp_buf.len & 0x0Fu);
        for (i = 0u; i < (uint8_t)g_resp_buf.len; ++i) {
            tx.data[1u + i] = g_resp_buf.data[i];
        }
        can_tx(&tx);
    } else {
        /* First frame, then consecutive frames. */
        tx.data[0] = (uint8_t)(0x10u | ((g_resp_buf.len >> 8) & 0x0Fu));
        tx.data[1] = (uint8_t)(g_resp_buf.len & 0xFFu);
        for (i = 0u; i < 6u; ++i) {
            tx.data[2u + i] = g_resp_buf.data[i];
        }
        can_tx(&tx);
        uint16_t off = 6u;
        uint8_t  sn  = 1u;
        while (off < g_resp_buf.len) {
            can_frame_t cf;
            cf.id  = CAN_ID_DIAG_RESP;
            cf.dlc = 8u;
            for (i = 0u; i < 8u; ++i) cf.data[i] = 0u;
            cf.data[0] = (uint8_t)(0x20u | (sn & 0x0Fu));
            uint8_t n = 7u;
            if ((uint16_t)(g_resp_buf.len - off) < n) n = (uint8_t)(g_resp_buf.len - off);
            for (i = 0u; i < n; ++i) cf.data[1u + i] = g_resp_buf.data[off + i];
            can_tx(&cf);
            off = (uint16_t)(off + n);
            sn  = (uint8_t)(sn + 1u);
        }
    }
}

/* ========================================================================
 *  MultiCAN driver - minimal stubs. The register writes reflect the
 *  TC1766 MultiCAN layout enough for static analysis; real silicon
 *  would additionally need node enable + bit-timing config.
 * ====================================================================== */
void can_init(void) {
    CAN_CLC  = 0x00000000u;              /* enable module */
    CAN_FDR  = 0x0000047Fu;              /* fractional divider ~500kbps */

    /* RX message object: accept 0x7E0 (phys) and 0x7DF (functional) */
    CAN_MOAR(RX_MSG_OBJ)   = (CAN_ID_DIAG_PHYS_REQ << 18) | 0x20000000u;
    CAN_MOAMR(RX_MSG_OBJ)  = 0xE0000000u;      /* mask low bit so 0x7DF/0x7E0 both match */
    CAN_MOFCR(RX_MSG_OBJ)  = 0x00000050u;      /* RX, message valid, ext=0 */
    CAN_MOCTR(RX_MSG_OBJ)  = 0x00005555u;      /* set MSGVAL, RXEN */

    /* TX message object for 0x7E8 */
    CAN_MOAR(TX_MSG_OBJ)   = (CAN_ID_DIAG_RESP << 18);
    CAN_MOFCR(TX_MSG_OBJ)  = 0x00000080u;
    CAN_MOCTR(TX_MSG_OBJ)  = 0x00005540u;
}

int can_rx_poll(can_frame_t *frame) {
    if ((CAN_MSPND0 & (1u << RX_MSG_OBJ)) == 0u) return 0;
    uint32_t lo = CAN_MODATAL(RX_MSG_OBJ);
    uint32_t hi = CAN_MODATAH(RX_MSG_OBJ);
    uint32_t ar = CAN_MOAR(RX_MSG_OBJ);

    frame->id  = (ar >> 18) & 0x7FFu;
    frame->dlc = 8u;
    frame->data[0] = (uint8_t)(lo      );
    frame->data[1] = (uint8_t)(lo >>  8);
    frame->data[2] = (uint8_t)(lo >> 16);
    frame->data[3] = (uint8_t)(lo >> 24);
    frame->data[4] = (uint8_t)(hi      );
    frame->data[5] = (uint8_t)(hi >>  8);
    frame->data[6] = (uint8_t)(hi >> 16);
    frame->data[7] = (uint8_t)(hi >> 24);

    CAN_MSPND0 = ~(1u << RX_MSG_OBJ);   /* ack */
    return 1;
}

void can_tx(const can_frame_t *frame) {
    uint32_t lo = ((uint32_t)frame->data[0])        |
                  ((uint32_t)frame->data[1] <<  8)  |
                  ((uint32_t)frame->data[2] << 16)  |
                  ((uint32_t)frame->data[3] << 24);
    uint32_t hi = ((uint32_t)frame->data[4])        |
                  ((uint32_t)frame->data[5] <<  8)  |
                  ((uint32_t)frame->data[6] << 16)  |
                  ((uint32_t)frame->data[7] << 24);
    CAN_MODATAL(TX_MSG_OBJ) = lo;
    CAN_MODATAH(TX_MSG_OBJ) = hi;
    CAN_MOAR(TX_MSG_OBJ)    = (frame->id << 18);
    CAN_MOCTR(TX_MSG_OBJ)   = 0x01000000u;   /* TXRQ */
}

/* ========================================================================
 *  Top-level init + poll loop
 * ====================================================================== */
void uds_init(void) {
    g_session      = SESSION_DEFAULT;
    g_sec_level    = SEC_LOCKED;
    g_seed_valid   = 0u;
    g_rng_state    = FW_BUILD_ID ^ FW_SIGNATURE;
    can_init();
}

void uds_poll(void) {
    can_frame_t f;
    if (can_rx_poll(&f)) {
        if (f.id == CAN_ID_DIAG_PHYS_REQ || f.id == CAN_ID_DIAG_FUNC_REQ) {
            iso_tp_handle_rx(&f);
        }
    }
    /* Session timeout (S3 = 5s) - tester-present keep-alive */
    uint32_t now = STM_TIM0;
    if (g_session != SESSION_DEFAULT &&
        (uint32_t)(now - g_last_tester_present) > 5u * 1000u * 1000u) {
        g_session    = SESSION_DEFAULT;
        g_sec_level  = SEC_LOCKED;
        g_seed_valid = 0u;
    }
}

/* ========================================================================
 *  Reset entry - placed at 0x80000000 (.startup) by the linker script.
 *  No inline asm, no naked: plain C is sufficient for a RE target binary.
 *  On real silicon the Boot ROM has already set A10; for Ghidra/binbloom
 *  analysis we just need a valid _start symbol at the load base.
 * ====================================================================== */
extern uint32_t __data_load_start, __data_start, __data_end;
extern uint32_t __bss_start, __bss_end;

__attribute__((section(".startup"), noreturn))
void _start(void) {
    /* Copy initialised data from PFLASH load address to LDRAM VMA */
    uint32_t *src = &__data_load_start;
    uint32_t *dst = &__data_start;
    while (dst < &__data_end) *dst++ = *src++;

    /* Zero BSS */
    for (uint32_t *p = &__bss_start; p < &__bss_end; ++p) *p = 0u;

    /* Disable watchdog before touching any peripheral */
    WDT_CON0 = 0x00000008u;

    uds_init();
    for (;;) uds_poll();
}

/* Firmware header - keep at a fixed offset from link base so binbloom/
 * anyone eyeballing a hexdump immediately sees magic + build info. */
__attribute__((section(".fw_header"), used))
const struct {
    uint32_t signature;
    uint32_t version;
    uint32_t build_id;
    uint32_t load_addr;
    const char *vin;
    const uds_service_t *services;
    uint32_t service_count;
    const did_entry_t *dids;
    uint32_t did_count;
} g_fw_header = {
    .signature     = FW_SIGNATURE,
    .version       = ((uint32_t)FW_VERSION_MAJOR << 16) | FW_VERSION_MINOR,
    .build_id      = FW_BUILD_ID,
    .load_addr     = 0x80000000u,
    .vin           = VIN_STRING,
    .services      = g_service_table,
    .service_count = sizeof(g_service_table) / sizeof(g_service_table[0]),
    .dids          = g_did_table,
    .did_count     = sizeof(g_did_table) / sizeof(g_did_table[0]),
};
