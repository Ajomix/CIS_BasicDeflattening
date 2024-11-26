nasm -f elf32 asm.s -o asm.o
ld -melf_i386  -N asm.o -o asm
