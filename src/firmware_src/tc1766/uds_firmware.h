/*
 * uds_firmware.h - ICSim UDS target for Infineon TriCore TC1766
 * Barbhack 2024 ICSim reverse-engineering workshop target image.
 */
#ifndef UDS_FIRMWARE_H
#define UDS_FIRMWARE_H

#include <stdint.h>
#include <stddef.h>

#define FW_SIGNATURE      0xA5C31766u
#define FW_VERSION_MAJOR  0x01u
#define FW_VERSION_MINOR  0x07u
#define FW_BUILD_ID       0x20240607u

/* ---- CAN identifiers (match ICSim src/data.h & icsim.c) ---- */
#define CAN_ID_DIAG_PHYS_REQ     0x7E0u   /* DEFAULT_ECU_ID = 2016 */
#define CAN_ID_DIAG_FUNC_REQ     0x7DFu   /* diagId - 1 (functional) */
#define CAN_ID_DIAG_RESP         0x7E8u

/* ---- UDS Service IDs (ISO 14229) ---- */
#define SID_DIAGNOSTIC_SESSION_CONTROL   0x10u
#define SID_ECU_RESET                    0x11u
#define SID_READ_DATA_BY_IDENTIFIER      0x22u
#define SID_SECURITY_ACCESS              0x27u
#define SID_WRITE_DATA_BY_IDENTIFIER     0x2Eu
#define SID_ROUTINE_CONTROL              0x31u
#define SID_TESTER_PRESENT               0x3Eu
#define SID_POSITIVE_RESPONSE_MASK       0x40u
#define SID_NEGATIVE_RESPONSE            0x7Fu

/* ---- Negative Response Codes ---- */
#define NRC_SERVICE_NOT_SUPPORTED                0x11u
#define NRC_SUB_FUNCTION_NOT_SUPPORTED           0x12u
#define NRC_INCORRECT_MESSAGE_LEN_OR_FORMAT      0x13u
#define NRC_CONDITIONS_NOT_CORRECT               0x22u
#define NRC_REQUEST_SEQUENCE_ERROR               0x24u
#define NRC_REQUEST_OUT_OF_RANGE                 0x31u
#define NRC_SECURITY_ACCESS_DENIED               0x33u
#define NRC_INVALID_KEY                          0x35u
#define NRC_SUB_FUNC_NOT_SUPPORTED_IN_SESSION    0x7Eu
#define NRC_SERVICE_NOT_SUPPORTED_IN_SESSION     0x7Fu

/* ---- Diagnostic sessions ---- */
typedef enum {
    SESSION_DEFAULT     = 0x01u,
    SESSION_PROGRAMMING = 0x02u,
    SESSION_EXTENDED    = 0x03u,
} uds_session_t;

/* ---- Security levels ---- */
typedef enum {
    SEC_LOCKED    = 0x00u,
    SEC_LEVEL_1   = 0x01u,   /* unlocked via subfunc 0x01/0x02 */
} uds_sec_level_t;

/* ---- DID access flags ---- */
#define DID_ACC_READ            0x01u
#define DID_ACC_WRITE           0x02u
#define DID_ACC_SEC_REQUIRED    0x10u
#define DID_ACC_EXT_SESSION     0x20u

/* ---- ISO-TP single-frame buffer (classic CAN, 8-byte) ---- */
#define UDS_MAX_PAYLOAD  64u
#define CAN_DLC_MAX      8u

typedef struct {
    uint32_t id;
    uint8_t  dlc;
    uint8_t  data[CAN_DLC_MAX];
} can_frame_t;

typedef struct {
    uint8_t  data[UDS_MAX_PAYLOAD];
    uint16_t len;
} uds_msg_t;

/* ---- DID descriptor: classic array-of-structs pattern ---- */
typedef uint8_t (*did_reader_fn)(uint8_t *out, uint16_t *out_len);
typedef uint8_t (*did_writer_fn)(const uint8_t *in, uint16_t in_len);

typedef struct {
    uint16_t        did;
    uint16_t        length;       /* fixed length for this DID */
    uint8_t         access_flags; /* DID_ACC_* bitmask */
    uint8_t         _pad;
    did_reader_fn   read;
    did_writer_fn   write;
    void           *storage;      /* backing store, may be NULL */
    const char     *name;         /* debug string, kept in .rodata */
} did_entry_t;

/* ---- Service descriptor ---- */
typedef uint8_t (*service_handler_fn)(const uds_msg_t *req, uds_msg_t *resp);

typedef struct {
    uint8_t             sid;
    uint8_t             min_len;         /* minimum SDU length incl. SID */
    uint8_t             session_mask;    /* bit = 1<<(session-1) */
    uint8_t             requires_security;
    service_handler_fn  handler;
    const char         *name;
} uds_service_t;

#define SESSION_MASK_ALL        ((1u<<0) | (1u<<1) | (1u<<2))
#define SESSION_MASK_EXT_ONLY   (1u<<2)
#define SESSION_MASK_PROG_EXT   ((1u<<1) | (1u<<2))

/* ---- TriCore TC1766 peripheral base addresses (subset) ---- */
#define TC1766_STM_BASE     0xF0000200u   /* System Timer Module */
#define TC1766_CAN_BASE     0xF0000300u   /* MultiCAN module */
#define TC1766_SCU_BASE     0xF0000500u   /* System Control Unit */
#define TC1766_WDT_BASE     0xF0000530u   /* Watchdog Timer */

#define REG32(addr)         (*(volatile uint32_t *)(addr))

/* MultiCAN control offsets (abridged, only what the stub touches) */
#define CAN_CLC             REG32(TC1766_CAN_BASE + 0x00u)
#define CAN_FDR             REG32(TC1766_CAN_BASE + 0x08u)
#define CAN_LIST            REG32(TC1766_CAN_BASE + 0x100u)
#define CAN_MSPND0          REG32(TC1766_CAN_BASE + 0x140u)
#define CAN_MSID0           REG32(TC1766_CAN_BASE + 0x180u)
#define CAN_MOFCR(n)        REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x00u)
#define CAN_MOFGPR(n)       REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x04u)
#define CAN_MOIPR(n)        REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x08u)
#define CAN_MOAMR(n)        REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x0Cu)
#define CAN_MODATAL(n)      REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x10u)
#define CAN_MODATAH(n)      REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x14u)
#define CAN_MOAR(n)         REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x18u)
#define CAN_MOCTR(n)        REG32(TC1766_CAN_BASE + 0x1000u + ((n)*0x20u) + 0x1Cu)

#define STM_TIM0            REG32(TC1766_STM_BASE + 0x10u)
#define WDT_CON0            REG32(TC1766_WDT_BASE + 0x00u)

#define RX_MSG_OBJ          0u
#define TX_MSG_OBJ          1u

/* ---- Public API exported to startup code ---- */
void  uds_init(void);
void  uds_poll(void);
void  can_init(void);
int   can_rx_poll(can_frame_t *frame);
void  can_tx(const can_frame_t *frame);

extern const uds_service_t g_service_table[];
extern const size_t        g_service_table_size;
extern const did_entry_t   g_did_table[];
extern const size_t        g_did_table_size;

#endif /* UDS_FIRMWARE_H */
