#!/bin/sh
set -ex

nasm -O0 -g -f elf64 -o infector.o infector.asm
ld -o infector infector.o
