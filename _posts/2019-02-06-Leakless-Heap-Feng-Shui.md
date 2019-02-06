---
layout: post
title: Leakless Heap Feng Shui
tags: pwn, ctf, heap, fengshui, glibc
---

# Description:
This blog post will explain how to achieve a leak or full rce in leakless binaries, using Heap FengShui combined with other heap exploitation techniques.

# Assumptions:

*   The exploit will be developped in glibc2.24 _(it can work in tcache as well)_.
*   We will have someway to control size of a chunk , off by one bug or double free can work.
*   We will be using a double free attack _(fastbin dup)_ .
*   The binary has only the option to malloc and free.
*   Malloc size limit is 0x80.
*   We can at maximum allocate 15 chunks in total.

# The exploit: 