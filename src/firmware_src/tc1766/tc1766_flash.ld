/* ------------------------------------------------------------------
 * tc1766_flash.ld - GNU ld script for Infineon TriCore TC1766
 *
 * TC1766 on-chip memory layout (relevant to this firmware):
 *
 *   PFLASH0 cached   : 0x80000000 .. 0x8017FFFF   (1.5 MiB, XIP code)
 *   PFLASH0 uncached : 0xA0000000 .. 0xA017FFFF   (same physical flash)
 *   DFLASH           : 0xAFE00000 .. 0xAFE0FFFF   (64 KiB, EEPROM emul.)
 *   PSPR (prog SPR)  : 0xC0000000 .. 0xC0003FFF   (16 KiB scratch code)
 *   LDRAM (data SPR) : 0xD0000000 .. 0xD000DFFF   (56 KiB RW)
 *   MMIO (Peripheral): 0xF0000000 .. 0xF00FFFFF
 *
 * The cached alias at 0x80000000 is the canonical XIP base.  Images
 * linked here light up binbloom's pointer-anchor base detector: every
 * absolute pointer in the service/DID tables lands inside the linked
 * range, and no other region yields self-consistent anchors.
 * ------------------------------------------------------------------ */

OUTPUT_FORMAT("elf32-tricore", "elf32-tricore", "elf32-tricore")
OUTPUT_ARCH(tricore)
ENTRY(_start)

MEMORY
{
    PFLASH (rx) : ORIGIN = 0x80000000, LENGTH = 1536K
    DFLASH (r)  : ORIGIN = 0xAFE00000, LENGTH = 64K
    PSPR   (rx) : ORIGIN = 0xC0000000, LENGTH = 16K
    LDRAM  (rw) : ORIGIN = 0xD0000000, LENGTH = 56K
}

/* 8 KiB stack at the top of LDRAM. Grows downward (TriCore A10/SP). */
__stack_size = 0x2000;
__stack_top  = ORIGIN(LDRAM) + LENGTH(LDRAM);

SECTIONS
{
    /* ---------- Reset vector + firmware header at 0x80000000 ------ */
    .startup 0x80000000 : ALIGN(16)
    {
        KEEP(*(.startup))
        KEEP(*(.fw_header))
    } > PFLASH

    /* ---------- Code ------------------------------------------------ */
    .text : ALIGN(16)
    {
        *(.text .text.*)
        *(.gnu.linkonce.t.*)
    } > PFLASH

    /* ---------- Read-only data (service/DID tables, VIN, etc.) ----- */
    .rodata : ALIGN(8)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.gnu.linkonce.r.*)
        . = ALIGN(4);
        /* Explicit anchors so RE tooling can spot table bounds */
        PROVIDE(__service_table = ADDR(.rodata));
        __rodata_end = .;
    } > PFLASH

    /* ---------- Initialised RAM data (load-addressed in PFLASH) --- */
    .data : ALIGN(8)
    {
        __data_start = .;
        *(.data .data.*)
        *(.gnu.linkonce.d.*)
        . = ALIGN(4);
        __data_end = .;
    } > LDRAM AT > PFLASH

    __data_load_start = LOADADDR(.data);

    /* ---------- Zero-init RAM ------------------------------------- */
    .bss (NOLOAD) : ALIGN(8)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > LDRAM

    /* ---------- Stack reservation -------------------------------- */
    .stack (NOLOAD) :
    {
        . = ALIGN(16);
        . = . + __stack_size;
    } > LDRAM

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame*)
    }
}

/* Convenience symbols for the RE — resolved to absolute PFLASH addrs */
PROVIDE(__fw_signature_addr = ADDR(.startup));
PROVIDE(__did_table_addr    = ADDR(.rodata));
