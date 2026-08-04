/* Minimal Cortex-M3 startup: vector table (just enough entries to be a
 * valid image -- initial SP, Reset_Handler, and a handful of fault/IRQ
 * slots so a stray exception doesn't jump into undefined flash), the
 * .data/.bss initialization every C runtime needs before main() can safely
 * touch a global, and nothing else. No RTOS, no HAL, no libc startup file
 * -- see rtos/README.md for why this is deliberately smaller than a real
 * Zephyr/FreeRTOS port. */
#include <stdint.h>

extern uint32_t _estack;
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

int main(void);

static void Default_Handler(void) {
    while (1) {
    }
}

void Reset_Handler(void);

/* 16 entries: SP + 15 exception vectors (Reset, NMI, HardFault, MemManage,
 * BusFault, UsageFault, 4 reserved, SVCall, DebugMon, reserved,
 * PendSV, SysTick) -- the fixed Cortex-M exception table shape, before any
 * device-specific IRQ vectors (which this program never enables/uses). */
__attribute__((section(".isr_vector"))) void (*const vector_table[16])(void) = {
    (void (*)(void))(&_estack),
    Reset_Handler,
    Default_Handler, /* NMI */
    Default_Handler, /* HardFault */
    Default_Handler, /* MemManage */
    Default_Handler, /* BusFault */
    Default_Handler, /* UsageFault */
    0,
    0,
    0,
    0, /* reserved */
    Default_Handler, /* SVCall */
    Default_Handler, /* DebugMon */
    0, /* reserved */
    Default_Handler, /* PendSV */
    Default_Handler, /* SysTick */
};

void Reset_Handler(void) {
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;

    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0;

    main();
    while (1) {
    }
}
