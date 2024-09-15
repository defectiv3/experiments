#!/bin/sh
set -ex

nasm -f elf64 -o infector.o infector.asm
ld -o infector infector.o
