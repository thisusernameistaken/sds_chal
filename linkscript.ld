OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_Reset)

MEMORY
{
    ROM (rx) : ORIGIN = 0x60010000, LENGTH = 1M
    PROTECTED (rwx) : ORIGIN = 0x61000000, LENGTH = 1M
    RAM (rwx): ORIGIN = 0x70000000, LENGTH = 1M
}

SECTIONS
{   
    .text : {
        *(.vector_table)
        *(.text*)
        *(.rodata*)
     } > ROM
     _text_end = .;
    .data : AT(ADDR(.text) + SIZEOF(.text))
    {
        _data_start = .;
        *(.data)
        . = ALIGN(8);
        _data_end = .;
    } > RAM
    .bss : {
        _bss_start = .;
        *(.bss)
        . = ALIGN(8);
        _bss_end = .;
    } > RAM
    .ARM.exidx : {
        __exidx_start = .;
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        __exidx_end = .;
    } >RAM

    .protected : {
        *(.protected*)
    } >PROTECTED

    _fiq_stack_start = ADDR(.bss) + SIZEOF(.bss);
    _fiq_stack_end = _fiq_stack_start + 0x1000; /* 64 KB */

    _irq_stack_start = _fiq_stack_end;
    _irq_stack_end = _irq_stack_start + 0x1000; /* 64 KB */

    _stack_start = _irq_stack_end;
    _stack_end = _stack_start + 0x1000; /* 64 KB */

    _irq_stack_size = _irq_stack_end - _irq_stack_start;
    _fiq_stack_size = _fiq_stack_end - _fiq_stack_start;
}
