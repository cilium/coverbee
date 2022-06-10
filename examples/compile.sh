#!/bin/bash

clang -target bpf -Wall -O2 -g -c bpf-to-bpf.c -I/usr/include -o bpf-to-bpf
