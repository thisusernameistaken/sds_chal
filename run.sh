qemu-system-arm -M vexpress-a9 -m 512M  -no-reboot -nographic -monitor telnet:127.0.0.1:1235,server,nowait  -kernel sds_chall.bin -serial stdio