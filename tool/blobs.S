/* blobs.S — the files the exclave command carries: this architecture's launcher, which wrap installs and relink puts
 * behind every wrapper unless given another, and the README every exclave gets (DESIGN.md 6.1, 10). scripts/build
 * names the launcher, LAUNCHER, built before the command. */
    .section .rodata
    .globl launcher_blob, launcher_size, readme_blob, readme_size
    .balign 8
launcher_size:
    .8byte 1f - launcher_blob
readme_size:
    .8byte 2f - readme_blob
launcher_blob:
    .incbin LAUNCHER
1:
readme_blob:
    .incbin "tool/README.txt"
2:
    .section .note.GNU-stack, "", %progbits
