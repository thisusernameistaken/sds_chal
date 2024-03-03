arm-none-eabi-as -o startup.o startup.s
arm-none-eabi-gcc -c -DCPU_A9 -mthumb -mcpu=cortex-a9 -nostdlib -nostartfiles -lgcc -o cstart.o cstart.c
arm-none-eabi-gcc -c -DCPU_A9 -mthumb -mcpu=cortex-a9 -nostdlib -nostartfiles -lgcc -o irq.o irq.c
arm-none-eabi-gcc -c -DCPU_A9 -mthumb -mcpu=cortex-a9 -nostdlib -nostartfiles -lgcc -o gic.o gic.c
arm-none-eabi-gcc -c -DCPU_A9 -mthumb -mcpu=cortex-a9 -nostdlib -nostartfiles -lgcc -o uart_pl011.o uart_pl011.c
arm-none-eabi-gcc -c -DCPU_A9 -mthumb -mcpu=cortex-a9 -nostdlib -nostartfiles -lgcc -o can.o can.c
arm-none-eabi-gcc -c -DCPU_A9 -mthumb -mcpu=cortex-a9 -nostdlib -nostartfiles -lgcc -o protected.o protected.c
arm-none-eabi-ld -T linkscript.ld -L/usr/lib/arm-none-eabi/newlib -L/usr/lib/gcc/arm-none-eabi/9.2.1  -o sds_chall.elf  startup.o cstart.o uart_pl011.o gic.o irq.o can.o protected.o  -lc -lgcc
arm-none-eabi-objcopy -O binary sds_chall.elf sds_chall.bin