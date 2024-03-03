#ifndef UART_PL011_H
#define UART_PL011_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef volatile struct __attribute__((packed)) {
        uint32_t DR;                            /* 0x0 Data Register */
        uint32_t RSRECR;                        /* 0x4 Receive status / error clear register */
        uint32_t _reserved0[4];                 /* 0x8 - 0x14 reserved */
        const uint32_t FR;                      /* 0x18 Flag register */
        uint32_t _reserved1;                    /* 0x1C reserved */
        uint32_t ILPR;                          /* 0x20 Low-power counter register */
        uint32_t IBRD;                          /* 0x24 Integer baudrate register */
        uint32_t FBRD;                          /* 0x28 Fractional baudrate register */
        uint32_t LCRH;                          /* 0x2C Line control register */
        uint32_t CR;                            /* 0x30 Control register */
	uint32_t IFLS;				/* 0x34 FIFO level select register */
	uint32_t IMSC;				/* 0x38 Interrupt mask set/clear register */
	uint32_t RIS;				/* 0x3C Raw interrupt status register */
	uint32_t MIS;				/* 0x40 Masked interrupt status register */
	uint32_t ICR;				/* 0x44 Interrupt clear register */

} uart_registers;

typedef enum {
        UART_OK = 0,
        UART_INVALID_ARGUMENT_BAUDRATE,
        UART_INVALID_ARGUMENT_WORDSIZE,
        UART_INVALID_ARGUMENT_STOP_BITS,
        UART_RECEIVE_ERROR,
        UART_NO_DATA
} uart_error;

typedef struct {
    uint8_t     data_bits;
    uint8_t     stop_bits;
    bool        parity;
    uint32_t    baudrate;
} uart_config;

#define UART0_INTERRUPT (37u)

#define DR_DATA_MASK    (0xFFu)

#define ECR_BE		(1 << 2u)

#define FR_BUSY         (1 << 3u)
#define FR_RXFE         (1 << 4u)
#define FR_TXFF         (1 << 5u)

#define RSRECR_ERR_MASK (0xFu)

#define LCRH_FEN        (1 << 4u)
#define LCRH_PEN        (1 << 1u)
#define LCRH_EPS        (1 << 2u)
#define LCRH_STP2       (1 << 3u)
#define LCRH_SPS        (1 << 7u)
#define CR_UARTEN       (1 << 0u)

#define LCRH_WLEN_5BITS (0u << 5u)
#define LCRH_WLEN_6BITS (1u << 5u)
#define LCRH_WLEN_7BITS (2u << 5u)
#define LCRH_WLEN_8BITS (3u << 5u)

#define IFLS_RXFL_1_8	(0u << 5u)
#define IFLS_TXFL_1_8	(0u << 2u)

#define IMSC_RXIM	(1u << 4u)
#define IMSC_TXIM	(1u << 5u)

#define RX_INTERRUPT	(1u << 4u)
#define BE_INTERRUPT	(1u << 9u)

#define ICR_ALL_MASK	(0x7FFu)

uart_error uart_configure(uart_config* config);
void uart_putchar(char c);
void uart_write(const char* data);
uart_error uart_getchar(char* c);
void uart_isr(void);

#endif
