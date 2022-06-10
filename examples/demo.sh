#!/bin/bash

# Remove any existing pins
sudo rm -Rf /sys/fs/bpf/covertest
sudo mkdir -p /sys/fs/bpf/covertest

# Compile the latests coverbee version
go build -o coverbee ../cmd/coverbee/main.go 

# Load our program
sudo ./coverbee load \
    --elf bpf-to-bpf \
    --covermap-pin /sys/fs/bpf/covertest/bpf-to-bpf-coverage \
    --prog-pin-dir /sys/fs/bpf/covertest \
    --block-list ./bpf-to-bpf-blocklist.json

# Run the program 2 times with a test packet
sudo bpftool prog run pinned /sys/fs/bpf/covertest/firewall_prog data_in ./datain repeat 2

# Collect coverage information
sudo ./coverbee cover \
    --covermap-pin /sys/fs/bpf/covertest/bpf-to-bpf-coverage \
    --block-list ./bpf-to-bpf-blocklist.json \
    --output bpf-to-bpf.html

# Clean up after ourselfs
sudo rm -Rf /sys/fs/bpf/covertest
