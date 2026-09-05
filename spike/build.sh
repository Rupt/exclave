#!/bin/sh
exec gcc -static -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin -O2 -fpie -no-pie -fcf-protection=none -fno-asynchronous-unwind-tables -Wall -Wextra -Wno-unused-parameter -Wl,-Ttext-segment=0x1000000000 -Wl,--build-id=none -Wl,-z,noexecstack -Wl,--no-relax -fno-plt -fvisibility=hidden -o spike spike.c "$@"
