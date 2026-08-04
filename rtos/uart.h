#ifndef ND_RTOS_UART_H
#define ND_RTOS_UART_H
/* UART0 on the QEMU lm3s6965evb machine model (TI/Stellaris LM3S6965 SoC),
 * memory-mapped at the SoC's real base address -- enough of the register
 * set (data register + TX-FIFO-full flag) to print status text with
 * `-nographic -serial mon:stdio`, no DMA/interrupts/baud-rate setup (QEMU's
 * model doesn't require it to already show output on the emulated wire). */
#include <stdint.h>

void uart_putc(char c);
void uart_puts(const char *s);
void uart_put_hex32(uint32_t v);

#endif /* ND_RTOS_UART_H */
