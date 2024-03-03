#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "uart_pl011.h"
#include "cpu_a9.h"
#include "gic.h"

int main() {
        uart_config config = {
            .data_bits = 8,
            .stop_bits = 1,
            .parity = false,
            .baudrate = 9600
        };
        uart_configure(&config);
        uart_write("Starting ECU\n");
	gic_init();
	gic_enable_interrupt(UART0_INTERRUPT);
	cpu_enable_interrupts();

        while (1) { }

        return 0;
}

