/* Linker script for QEMU's lm3s6965evb machine (TI/Stellaris LM3S6965,
 * Cortex-M3): 256KB flash at 0x00000000, 64KB SRAM at 0x20000000 -- the
 * real memory map QEMU emulates for this board, not an arbitrary choice.
 * See rtos/README.md for why this board (over a full Zephyr/FreeRTOS
 * target) is what Stretch B actually delivers. */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector : {
    KEEP(*(.isr_vector))
  } > FLASH

  .text : {
    *(.text*)
    *(.rodata*)
  } > FLASH

  _sidata = LOADADDR(.data);
  .data : {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM AT> FLASH

  .bss : {
    _sbss = .;
    *(.bss*)
    *(COMMON)
    _ebss = .;
  } > RAM

  _estack = ORIGIN(RAM) + LENGTH(RAM);

  /DISCARD/ : { *(.comment) *(.ARM.attributes) }
}
