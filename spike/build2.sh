#!/bin/sh
# ET_DYN, no PT_INTERP, self-relocating: usable as a program, as an ELF interpreter, and by itself.
exec gcc -shared -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin -O2 -fPIC -fvisibility=hidden -fno-plt \
  -fcf-protection=none -fno-asynchronous-unwind-tables -Wall -Wextra -Wno-unused-parameter \
  -Wl,-e,_start -Wl,--no-relax -Wl,-z,noexecstack -Wl,-z,nopack-relative-relocs -Wl,-Bsymbolic -Wl,--build-id=none \
  -o spike2 spike2.c "$@"
