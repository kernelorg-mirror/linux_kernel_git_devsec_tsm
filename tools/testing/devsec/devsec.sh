#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2025 Intel Corporation. All rights reserved.

# Checkout PCI/TSM sysfs and driver-core mechanics with the
# devsec_link_tsm and devsec_tsm sample modules from samples/devsec/.

set -ex

trap 'err $LINENO' ERR
err() {
        echo $(basename $0): failed at line $1
        [ -n "$2" ] && "$2"
        exit 1
}

ORDER=""

setup_modules() {
	if [[ $ORDER == "bus" ]]; then
		modprobe devsec_bus
		modprobe devsec_link_tsm
		modprobe devsec_tsm
	else
		modprobe devsec_tsm
		modprobe devsec_link_tsm
		modprobe devsec_bus
	fi
}

teardown_modules() {
	if [[ $ORDER == "bus" ]]; then
		modprobe -r devsec_tsm
		modprobe -r devsec_link_tsm
		modprobe -r devsec_bus
	else
		modprobe -r devsec_bus
		modprobe -r devsec_link_tsm
		modprobe -r devsec_tsm
	fi
}

pci_dev="/sys/bus/pci/devices/10000:01:00.0"
tsm_devsec=""
tsm_link=""
devsec_pci="/sys/bus/pci/drivers/devsec_pci"

tdisp_test() {
	# with the device disconnected from the link TSM validate that
	# the devsec_pci driver fails to claim the device, and that the
	# device is registered in the deferred probe queue
	echo "devsec_pci" > $pci_dev/driver_override
	modprobe devsec_pci

	cat /sys/kernel/debug/devices_deferred | grep -q $(basename $pci_dev) || err "$LINENO"

	# grab the device's resource from /proc/iomem
	resource=$(cat /proc/iomem | grep -m1 $(basename $pci_dev) | awk -F ' :' '{print $1}' | tr -d ' ')
	[[ -n $resource ]] || err "$LINENO"

	# lock and accept the device, validate that the resource is now
	# marked encrypted
	echo $(basename $tsm_devsec) > $pci_dev/tsm/lock
	echo $(basename $tsm_devsec) > $pci_dev/tsm/accept

	cat /proc/iomem | grep "$resource" | grep -q -m1 "PCI MMIO Encrypted" || err "$LINENO"

	# validate that the driver now fails with -EINVAL when trying to
	# bind
	expect="echo: write error: Invalid argument"
	echo $(basename $pci_dev) 2>&1 > $devsec_pci/bind | grep -q "$expect" || err "$LINENO"

	# unlock and validate that the encrypted mmio is removed
	echo $(basename $tsm_devsec) > $pci_dev/tsm/unlock
	cat /proc/iomem | grep "$resource" | grep -q "PCI MMIO Encrypted" && err "$LINENO"

	modprobe -r devsec_pci
}

ide_test() {
	# validate that all of the secure streams are idle by default
	host_bridge=$(dirname $(dirname $(readlink -f $pci_dev)))
	nr=$(cat $host_bridge/available_secure_streams)
	[[ $nr == 4 ]] || err "$LINENO"

	# connect a stream and validate that the stream link shows up at
	# the host bridge and the TSM
	echo $(basename $tsm_link) > $pci_dev/tsm/connect
	nr=$(cat $host_bridge/available_secure_streams)
	[[ $nr == 3 ]] || err "$LINENO"

	[[ $(cat $pci_dev/tsm/connect) == $(basename $tsm_link) ]] || err "$LINENO"
	[[ -e $host_bridge/stream0.0.0 ]] || err "$LINENO"
	[[ -e $tsm_link/stream0.0.0 ]] || err "$LINENO"

	# check that the links disappear at disconnect and the stream
	# pool is refilled
	echo $(basename $tsm_link) > $pci_dev/tsm/disconnect
	nr=$(cat $host_bridge/available_secure_streams)
	[[ $nr == 4 ]] || err "$LINENO"

	[[ $(cat $pci_dev/tsm/connect) == "" ]] || err "$LINENO"
	[[ ! -e $host_bridge/stream0.0.0 ]] || err "$LINENO"
	[[ ! -e $tsm_link/stream0.0.0 ]] || err "$LINENO"
}

devsec_test() {
	setup_modules

	# find the tsm devices by personality
	for tsm in /sys/class/tsm/tsm*; do
		mode=$(cat $tsm/pci_mode)
		[[ $mode == "devsec" ]] && tsm_devsec=$tsm
		[[ $mode == "link" ]] && tsm_link=$tsm
	done
	[[ -n $tsm_devsec ]] || err "$LINENO"
	[[ -n $tsm_link ]] || err "$LINENO"

	# check that devsec bus loads correctly and the TSM is detected
	[[ -e $pci_dev ]] || err "$LINENO"
	[[ -e $pci_dev/tsm ]] || err "$LINENO"

	ide_test
	tdisp_test

	# reconnect and test surprise removal of the TSM or device
	echo $(basename $tsm_link) > $pci_dev/tsm/connect
	[[ $(cat $pci_dev/tsm/connect) == $(basename $tsm_link) ]] || err "$LINENO"
	[[ -e $host_bridge/stream0.0.0 ]] || err "$LINENO"
	[[ -e $tsm_link/stream0.0.0 ]] || err "$LINENO"

	teardown_modules
}

ORDER="bus"
devsec_test
ORDER="tsm"
devsec_test
