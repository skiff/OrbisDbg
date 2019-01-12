.section .rodata

    .global OrbisDbgElf
    .type   OrbisDbgElf, @object
    .align  4
OrbisDbgElf:
    .incbin "../ELF/OrbisDbg.elf"
OrbisDbgElfEnd:
    .global OrbisDbgElfSize
    .type   OrbisDbgElfSize, @object
    .align  4
OrbisDbgElfSize:
    .int    OrbisDbgElfEnd - OrbisDbgElf
    