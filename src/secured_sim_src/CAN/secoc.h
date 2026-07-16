/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 Xpert <ahmad.pc.saad@gmail.com> - IMT Atlantique, IoV Security Lab
 *
 * secoc.h - Secure Onboard Communication (SecOC) for the ICSim security lab
 *
 * >>> This file is the engine behind SECURITY BLOCK 1 (message authentication).
 *     The sender calls secoc_sign() in controls.c; the receiver calls
 *     secoc_verify() in icsim.c. See SECURITY_LAYER.md for the friendly tour.
 *
 * Adds AUTOSAR-style message authentication to the simulator's CAN traffic so
 * that spoofed / replayed frames from an attacker on the bus are rejected.
 *
 * Threat model
 * ------------
 * Classic CAN has no authentication: any node can transmit any arbitration ID,
 * and a frame never says who sent it.  SecOC closes that gap by appending, to
 * each protected frame, a Freshness Value (a monotonic counter, for replay
 * protection) and a truncated MAC computed with a key the ECUs share.  A
 * receiver recomputes the MAC and drops anything that does not verify.
 *
 * What this gives you (and what it does NOT)
 * ------------------------------------------
 *   + integrity + authenticity  -> spoofing and replay are prevented
 *   + freshness                 -> a captured frame cannot be re-injected
 *   - confidentiality           -> NOT provided.  CAN is a broadcast bus; an
 *                                  attacker can still SNIFF every frame.  SecOC
 *                                  stops forgery, not eavesdropping.  (Real
 *                                  cars do not encrypt CAN.)
 *
 * Wire format (CAN FD, 20-byte frame)
 * -----------------------------------
 *   data[0..7]   original signal payload (byte offsets unchanged vs the
 *                unsecured sim, so existing decoders keep working)
 *   data[8..11]  Freshness Value, uint32 big-endian
 *   data[12..19] MAC = AES-128-CMAC( key, id || data[0..7] || FV )[0..7]
 *
 * The MAC primitive is AES-128-CMAC, exactly the SecOC profile, via OpenSSL.
 */
#ifndef SECOC_H
#define SECOC_H

#include <linux/can.h>   /* struct canfd_frame, canid_t, CANFD_MTU */
#include <stdint.h>
#include <stddef.h>      /* size_t */

/* Trailer layout inside the CAN FD data field. */
#define SECOC_FV_OFFSET   8     /* Freshness Value starts here (4 bytes) */
#define SECOC_MAC_OFFSET  12    /* truncated MAC starts here (8 bytes)   */
#define SECOC_MAC_LEN     8
#define SECOC_FRAME_LEN   20    /* valid CAN FD DLC; covers payload+FV+MAC */

/* Is this arbitration ID one we authenticate? */
int secoc_is_protected(canid_t id);

/*
 * Sign in place: compute the Freshness Value + MAC for cf and write them into
 * the trailer, set cf->len = SECOC_FRAME_LEN.  Returns the number of bytes to
 * write to the socket (CANFD_MTU) on success, or -1 on error / unprotected ID.
 *
 * Intended use in the sender:  sendPkt(secoc_sign(&cf));
 */
int secoc_sign(struct canfd_frame *cf);

/*
 * Verify a received frame: returns 1 if the MAC is valid AND the Freshness
 * Value is strictly newer than the last one accepted for this ID (replay
 * protection), 0 otherwise.  On success the per-ID freshness state is advanced.
 */
int secoc_verify(struct canfd_frame *cf);

/*
 * UDS SecurityAccess key derivation (defense-in-depth, reusing the SecOC key).
 *
 * Computes the expected key for a given seed as the first out_len bytes of
 * AES-128-CMAC( key, seed ).  Because the key lives only in the ECUs, an
 * attacker on the bus cannot compute the response for a fresh random seed:
 * the legacy "seed XOR constant" challenge is replaced by a real keyed MAC.
 *
 * Returns 0 on success (out filled with out_len bytes), -1 on error.
 * out_len must be <= 16.
 */
int secoc_sec_response(const uint8_t *seed, size_t seed_len,
                       uint8_t *out, size_t out_len);

#endif /* SECOC_H */
