/* startup.S - TriCore TC1766 reset vector
 *
 * Placed at 0x80000000 (.startup section) by the linker script.
 * Sets A10 (stack pointer), copies .data from PFLASH to LDRAM,
 * zeroes .bss, then calls c_main().
 *
 * Pure asm avoids every warning that tricore-elf-gcc emits when
 * 'naked' or address-register clobbers appear in a C function.
 */

    .section .startup, "ax", @progbits
    .global  _start
    .type    _start, @function
    .align   4

_start:
    /* ---- Set stack pointer (A10) to top of LDRAM ---- */
    movh.a  %a10, hi:__stack_top
    lea     %a10, [%a10]lo:__stack_top

    /* ---- Copy initialised .data: PFLASH (AT) -> LDRAM ---- */
    movh.a  %a2,  hi:__data_load_start
    lea     %a2,  [%a2]lo:__data_load_start   /* src */
    movh.a  %a3,  hi:__data_start
    lea     %a3,  [%a3]lo:__data_start         /* dst */
    movh.a  %a4,  hi:__data_end
    lea     %a4,  [%a4]lo:__data_end           /* end */
.Lcopy:
    jge.a   %a3, %a4, .Lbss
    ld.w    %d0, [%a2+]4
    st.w    [%a3+]4, %d0
    j       .Lcopy

    /* ---- Zero .bss ---- */
.Lbss:
    movh.a  %a3,  hi:__bss_start
    lea     %a3,  [%a3]lo:__bss_start
    movh.a  %a4,  hi:__bss_end
    lea     %a4,  [%a4]lo:__bss_end
    mov     %d0,  0
.Lzero:
    jge.a   %a3, %a4, .Lcall
    st.w    [%a3+]4, %d0
    j       .Lzero

    /* ---- Call C entry point (never returns) ---- */
.Lcall:
    call    c_main
    /* safety halt if c_main somehow returns */
.Lhalt:
    j       .Lhalt

    .size _start, .-_start
