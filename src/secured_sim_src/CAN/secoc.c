/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 Xpert <ahmad.pc.saad@gmail.com> - IMT Atlantique, IoV Security Lab
 *
 * secoc.c - SecOC implementation (AES-128-CMAC) for the ICSim security lab.
 *
 * See secoc.h for the wire format and threat model.  The MAC is computed with
 * OpenSSL's EVP_MAC "CMAC" over AES-128, which is the AUTOSAR SecOC primitive.
 */
#include "secoc.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>   /* CRYPTO_memcmp */

/* ---------------------------------------------------------------------------
 * Shared secret.
 *
 * In a real vehicle this 128-bit key is provisioned per ECU and stored in an
 * HSM / secure flash, never in source.  For the lab the controller (sender)
 * and the instrument cluster (receiver) compile in the SAME key; the attacker
 * tooling does NOT have it, so it cannot forge a valid MAC.  Rotating the key
 * is a one-line change here.
 * ------------------------------------------------------------------------- */
static const uint8_t SECOC_KEY[16] = {
    0x49, 0x4D, 0x54, 0x2D, 0x49, 0x43, 0x53, 0x69,   /* "IMT-ICSi" */
    0x6D, 0x2D, 0x53, 0x65, 0x63, 0x4F, 0x43, 0x21,   /* "m-SecOC!" */
};

/* IDs we authenticate: every signal the controller legitimately transmits.
 * Diagnostics (0x7E0/0x7E8) are intentionally NOT here (out of scope). */
#define SECOC_N_IDS 6
static struct {
    canid_t  id;
    uint32_t tx_fv;   /* sender's next-counter state          */
    uint32_t rx_fv;   /* receiver's last-accepted counter     */
} g_state[SECOC_N_IDS] = {
    { 0x007, 0, 0 },  /* control / shared-data channel */
    { 0x188, 0, 0 },  /* turn signal                   */
    { 0x19B, 0, 0 },  /* door locks                    */
    { 0x244, 0, 0 },  /* speed                         */
    { 0x39C, 0, 0 },  /* luminosity                    */
    { 0x42A, 0, 0 },  /* warning                       */
};

static int slot_of(canid_t id) {
    for (int i = 0; i < SECOC_N_IDS; i++)
        if (g_state[i].id == (id & CAN_SFF_MASK))
            return i;
    return -1;
}

int secoc_is_protected(canid_t id) {
    return slot_of(id) >= 0;
}

/* AES-128-CMAC; writes the full 16-byte tag to out16. */
static int cmac_full(const uint8_t *msg, size_t msg_len, uint8_t out16[16]) {
    static EVP_MAC *mac = NULL;     /* fetched once, reused */
    if (mac == NULL) {
        mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
        if (mac == NULL) return -1;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) return -1;

    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher, 0),
        OSSL_PARAM_construct_end(),
    };

    size_t  out_len = 0;
    int ok = EVP_MAC_init(ctx, SECOC_KEY, sizeof(SECOC_KEY), params)
          && EVP_MAC_update(ctx, msg, msg_len)
          && EVP_MAC_final(ctx, out16, &out_len, 16);
    EVP_MAC_CTX_free(ctx);

    return (ok && out_len == 16) ? 0 : -1;
}

/* AES-128-CMAC; writes the first SECOC_MAC_LEN bytes of the tag to out. */
static int cmac8(const uint8_t *msg, size_t msg_len, uint8_t *out) {
    uint8_t full[16];
    if (cmac_full(msg, msg_len, full) != 0) return -1;
    memcpy(out, full, SECOC_MAC_LEN);
    return 0;
}

int secoc_sec_response(const uint8_t *seed, size_t seed_len,
                       uint8_t *out, size_t out_len) {
    if (out_len > 16) return -1;
    uint8_t full[16];
    if (cmac_full(seed, seed_len, full) != 0) return -1;
    memcpy(out, full, out_len);
    return 0;
}

/* Build the MAC input: id (2B, big-endian 11-bit) || data[0..7] || FV (4B BE). */
static void mac_input(canid_t id, const uint8_t *data8, uint32_t fv, uint8_t out[14]) {
    out[0] = (id >> 8) & 0x07;
    out[1] =  id       & 0xFF;
    memcpy(out + 2, data8, 8);
    out[10] = (fv >> 24) & 0xFF;
    out[11] = (fv >> 16) & 0xFF;
    out[12] = (fv >>  8) & 0xFF;
    out[13] =  fv        & 0xFF;
}

int secoc_sign(struct canfd_frame *cf) {
    int slot = slot_of(cf->can_id);
    if (slot < 0) return -1;

    uint32_t fv = ++g_state[slot].tx_fv;   /* first transmitted FV is 1 */

    uint8_t input[14];
    mac_input(cf->can_id, cf->data, fv, input);

    uint8_t mac[SECOC_MAC_LEN];
    if (cmac8(input, sizeof(input), mac) != 0) return -1;

    cf->data[SECOC_FV_OFFSET + 0] = (fv >> 24) & 0xFF;
    cf->data[SECOC_FV_OFFSET + 1] = (fv >> 16) & 0xFF;
    cf->data[SECOC_FV_OFFSET + 2] = (fv >>  8) & 0xFF;
    cf->data[SECOC_FV_OFFSET + 3] =  fv        & 0xFF;
    memcpy(cf->data + SECOC_MAC_OFFSET, mac, SECOC_MAC_LEN);

    cf->len = SECOC_FRAME_LEN;
    return CANFD_MTU;
}

int secoc_verify(struct canfd_frame *cf) {
    int slot = slot_of(cf->can_id);
    if (slot < 0) return 1;                 /* not protected -> nothing to check */
    if (cf->len < SECOC_FRAME_LEN) return 0; /* too short: unauthenticated frame */

    uint32_t fv = ((uint32_t)cf->data[SECOC_FV_OFFSET + 0] << 24)
                | ((uint32_t)cf->data[SECOC_FV_OFFSET + 1] << 16)
                | ((uint32_t)cf->data[SECOC_FV_OFFSET + 2] <<  8)
                |  (uint32_t)cf->data[SECOC_FV_OFFSET + 3];

    uint8_t input[14];
    mac_input(cf->can_id, cf->data, fv, input);

    uint8_t mac[SECOC_MAC_LEN];
    if (cmac8(input, sizeof(input), mac) != 0) return 0;

    /* constant-time compare so a bad MAC leaks no timing about the key */
    if (CRYPTO_memcmp(mac, cf->data + SECOC_MAC_OFFSET, SECOC_MAC_LEN) != 0)
        return 0;

    if (fv <= g_state[slot].rx_fv) return 0;  /* replay or stale */
    g_state[slot].rx_fv = fv;
    return 1;
}
