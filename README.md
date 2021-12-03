# SysFlow

This is the PoC implementation of SysFlow, which implements the concept of syscall-flow-integrity protection.

## Description

Syscall-flow-integrity protection (SFIP) is a concept that restricts the interaction of a userspace application with the kernel and complements CFI. SysFlow automatically extracts syscall sequences and syscall origins during the compilation of an application, which are then enforced by our modified Linux kernel (based on v5.13).

## Warnings
**Warning #1**: We are providing this code as-is. You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. This code may cause unexpected and undesirable behavior to occur on your machine.

**Warning #2**: This code is only a proof-of-concept and developed for testing purposes. Do not run it on any productive systems. Do not run it on any system that might be used by another person or entity.