.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

========================================================
PCI Trusted Execution Environment Security Manager (TSM)
========================================================

Overview
========

A "TSM", as detailed by PCIe r7.0 section 11 "TEE Device Interface
Security Protocol (TDISP)", is an entity within the platform's Trusted
Computing Base (TCB) that enforces security policies on the host. It
serves to mitigate a threat model where devices may be under the control
of an adversary. The adversarial threats are:

- Identity: Device may be mimicking a legitimate device identity / firmware
- Physical: link may be under observation, or control (reorder / drop data)
- Virtual: Device MMIO presented to a guest may not actually map the
  device, device DMA may be redirected.

In Linux a "tsm" is a broader concept. It is a class device interface to
mitigate one or more of the above threats. A "tsm driver" registers a
tsm device that publishes either the 'tsm/connect' or
'tsm/{lock,accept}' set of attributes for the PCIe device. The typical
expectation is that 'tsm/{lock,accept}' is published by a guest "tsm
driver" to mitigate "Virtual" threats. The 'tsm/connect' interface is
published by a host "tsm driver" to mitigate "Identity" and/or
"Physical" threats.

Device Interface LOCK
=====================
The lock operation facilitated by tsm/lock (see
Documentation/ABI/testing/sysfs-bus-pci) places the device in a mode
where any security sensitive changes to the device configuration results
in the device transitioning to the ERROR state. The device presents
signed evidence of its LOCK state to the kernel through the tsm driver.
The relying party is responsible for verifying not only the evidence but
that the device is trusted to maintain those attested values while
locked. Accepting the locked configuration also asserts that device is
trusted to cease TCB interactions (send T=1 DMA / accept T=1 MMIO TLPs)
when it is next unlocked by STOP. The TSM is responsible for enforcing
that the device is not unlocked within the interval between evidence
collection and acceptance, by correlating the evidence from LOCK to the
subsequent RUN request.

While the PCIe specification allows for the device to operate outside
the TCB when locked, depending on the TSM architecture implementation,
T=0 DMA from the device may be blocked until the device is next
unlocked.

Maturity Map
============

Given the high number of subsystem touch points and corresponding high
degree of complexity of enabling PCIe device assignment to confidential
guests, a staging tree is needed. The tsm.git#staging tree [1] provides
an integration point for related topics to mature, gain consensus, and
graduate to mainline. What follows is a rough break down of the enabling
topics by phases, the relative maturity of those topics, and the
architecture support for those topics.

NOTE! User ABIs are not final until they ship and are consumed in a
mainline release. The tsm.git#staging may regress and break user flows
from one snapshot to the next.

NOTE2! A topic can go backwards in score based on testing, ongoing
review, or cross-vendor integration failure.

The maturity scores are:

- [3] Mature: Work on this topic is complete the support is queued in
  linux-next or is already in mainline.

- [2] Stabilizing: Major consensus on the core implementation reached.
  At least one vendor implementation consumes the functionality. Final
  bug fixing, review comments, and/or second vendor consumer needed before
  graduating.

- [1] Initial: The proposal is still in the concept phase, has
  significant review feedback to overcome, or significant test/use case
  issues to resolve. The implementation demonstrates functionality,
  but is not considered final.

- [0] Known gap: Near term future work needed for fundamental enabling.
  Note, this is also the score when patches are available, but not yet
  integrated into tsm.git#staging.

- [X]: Out of scope, or long term future work that is not needed for
  fundamental enabling.

PHASE1: Link Encryption and Secure Session Establishment (host-side)
--------------------------------------------------------------------
Description: PCI/TSM core and TSM driver support to establish PCIe CMA
             (PCIe r7.0 section 6.31 Component Measurement and
             Authentication (CMA-SPDM)), and PCIe IDE (PCIe r7.0 section
             6.33 Integrity & Data Encryption (IDE).

* [3]: PCI/TSM core library
* [3]: PCI/IDE core library
* [3]: Sample Platform TSM driver pre-requisites
* [2]: Sample Platform TSM driver implementation
* [3]: Arch Platform TSM driver implementation
* [3]: PCI/TSM: Address Association support
* [3]: PCI/IDE: Unique Stream ID vs IDE_KM quirk

Arch Support: TDX [2], TIO [3], CCA [2]

PHASE2: Device Lock and Accept (guest-side)
-------------------------------------------
Description: PCI/TSM core, TSM driver, and endpoint driver support to
             advance a device through the TDISP (PCIe r7.0 section 11
             TEE Device Interface Security Protocol (TDISP)) operational
             states (UNLOCKED => LOCKED => RUN).

* [1]: PCI/TSM lock+accept core infrastructure
* [1]: Device-core "accept" state, and TDISP aware driver infrastructure
* [1]: Sample Platform TSM driver implementation
* [0]: Arch Platform TSM driver implementation
* [1]: Sample Endpoint driver TDISP aware implementation
* [0]: Endpoint driver TDISP aware implementation
* [1]: SWIOTLB Dynamic Policy
* [1]: Trusted MMIO Setup
* [1]: Device core autprobe policy

Arch Support: None

PHASE3: Private DMA and MMIO setup (host-side)
----------------------------------------------
Description: VFIO/IOMMUFD/KVM infrastructure support to establish
             private MMIO and DMA/IOMMU mappings.

* [1]: PCI/TSM bind core infrastructure
* [1]: PCI/TSM guest request infrastructure
* [1]: Sample Platform TSM driver implementation
* [3]: VFIO DMA-BUF
* [0]: VFIO core infrastructure
* [0]: IOMMUFD bind ABI
* [0]: IOMMUFD KVM DMA-BUF for MMIO
* [0]: Arch KVM support

Arch Support: None

PHASE4: Device Attestation (guest-side)
---------------------------------------
Description: User ABI to retrieve Certificates, Measurements, and TDISP
             Interface reports for consumption by a verifier.

* [1]: "PCI-TSM Evidence" netlink ABI
* [1]: Sample Platform TSM driver implementation
* [0]: Arch Platform TSM implementation

Arch Support: None

Subsystem Interfaces
====================

.. kernel-doc:: include/linux/pci-ide.h
   :internal:

.. kernel-doc:: drivers/pci/ide.c
   :export:

.. kernel-doc:: include/linux/pci-tsm.h
   :internal:

.. kernel-doc:: drivers/pci/tsm.c
   :export:
