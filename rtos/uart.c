#include "uart.h"

#define UART0_BASE 0x4000C000u
#define UART0_DR (*(volatile uint32_t *)(UART0_BASE + 0x000u))
#define UART0_FR (*(volatile uint32_t *)(UART0_BASE + 0x018u))
#define UART_FR_TXFF (1u << 5)

void uart_putc(char c) {
    while (UART0_FR & UART_FR_TXFF) {
    }
    UART0_DR = (uint32_t)(uint8_t)c;
}

void uart_puts(const char *s) {
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}

void uart_put_hex32(uint32_t v) {
    static const char digits[] = "0123456789abcdef";
    uart_puts("0x");
    for (int i = 7; i >= 0; --i) uart_putc(digits[(v >> (i * 4)) & 0xFu]);
}
