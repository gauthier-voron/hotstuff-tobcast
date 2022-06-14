#!/bin/bash

set -e

n=4
b=1

tmpdir="$(mktemp -d --suffix='.d' 'run_tob.XXXXXX')"
echo "create work directory '${tmpdir}'"
pids=()

atexit() {
    local pid

    for pid in ${pids[@]} ; do
	echo "terminate process ${pid}"
	kill ${pid} 2> '/dev/null' || true
    done

    echo "delete work directory '${tmpdir}'"
    rm -rf "${tmpdir}" 2> '/dev/null' || true
}

trap atexit 'TERM'
trap atexit 'INT'


consensus_port=8000
args=()

for i in $(seq 0 $(( n - 1 ))) ; do
    echo "generate identity ${i}"
    ./examples/hotstuff-tobcast "${tmpdir}/sk-${i}.bin:${tmpdir}/pk-${i}.bin" \
				> "${tmpdir}/log-${i}.txt" 2>&1
    args+=("localhost:${consensus_port}:${tmpdir}/pk-${i}.bin")
    consensus_port=$(( consensus_port + 1 ))
done


client_port=7000

for i in $(seq 0 $(( n - 1 ))) ; do
    printf "start replica ${i} -> "
    ./examples/hotstuff-tobcast ${i} ${b} \
				${client_port}:"${tmpdir}/sk-${i}.bin" \
				"${args[@]}" \
				> "${tmpdir}/log-${i}.txt" 2>&1 &
    pids+=($!)
    echo $!
    client_port=$(( client_port + 1 ))
done


wait
