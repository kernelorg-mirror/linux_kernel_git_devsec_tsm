// SPDX-License-Identifier: GPL-2.0
/*
 * TEE Security Manager for the TEE Device Interface Security Protocol
 * (TDISP, PCIe r6.1 sec 11)
 *
 * Copyright(c) 2024 Intel Corporation. All rights reserved.
 */

#define dev_fmt(fmt) "PCI/TSM: " fmt

#include <linux/bitfield.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tsm.h>
#include <linux/sysfs.h>
#include <linux/tsm.h>
#include <linux/xarray.h>
#include "pci.h"

/*
 * Provide a read/write lock against the init / exit of pdev tsm
 * capabilities and arrival/departure of a TSM instance
 */
static DECLARE_RWSEM(pci_tsm_rwsem);

/*
 * Count of TSMs registered that support physical link operations vs device
 * security state management.
 */
static int pci_tsm_link_count;
static int pci_tsm_devsec_count;

static inline bool is_dsm(struct pci_dev *pdev)
{
	return pdev->tsm && pdev->tsm->dsm == pdev;
}

static inline bool has_tee(struct pci_dev *pdev)
{
	return pdev->devcap & PCI_EXP_DEVCAP_TEE;
}

/* 'struct pci_tsm_pf0' wraps 'struct pci_tsm' when ->dsm == ->pdev (self) */
static struct pci_tsm_pf0 *to_pci_tsm_pf0(struct pci_tsm *pci_tsm)
{
	struct pci_dev *pdev = pci_tsm->pdev;

	if (!is_pci_tsm_pf0(pdev) || !is_dsm(pdev)) {
		dev_WARN_ONCE(&pdev->dev, 1, "invalid context object\n");
		return NULL;
	}

	return container_of(pci_tsm, struct pci_tsm_pf0, base);
}

static inline bool is_devsec(struct pci_dev *pdev)
{
	return pdev->tsm && pdev->tsm->dsm == NULL && pdev->tsm->tdi == NULL;
}

/* 'struct pci_tsm_devsec' wraps 'struct pci_tsm' when ->tdi == ->dsm == NULL */
static struct pci_tsm_devsec *to_pci_tsm_devsec(struct pci_tsm *pci_tsm)
{
	struct pci_dev *pdev = pci_tsm->pdev;

	if (!is_devsec(pdev) || !has_tee(pdev)) {
		dev_WARN_ONCE(&pdev->dev, 1, "invalid context object\n");
		return NULL;
	}

	return container_of(pci_tsm, struct pci_tsm_devsec, base);
}

static void tsm_remove(struct pci_tsm *tsm)
{
	struct pci_dev *pdev;

	if (!tsm)
		return;

	pdev = tsm->pdev;
	tsm->ops->remove(tsm);
	pdev->tsm = NULL;
}
DEFINE_FREE(tsm_remove, struct pci_tsm *, if (_T) tsm_remove(_T))

static void pci_tsm_walk_fns(struct pci_dev *pdev,
			     int (*cb)(struct pci_dev *pdev, void *data),
			     void *data)
{
	/* Walk subordinate physical functions */
	for (int i = 0; i < 8; i++) {
		struct pci_dev *pf __free(pci_dev_put) = pci_get_slot(
			pdev->bus, PCI_DEVFN(PCI_SLOT(pdev->devfn), i));

		if (!pf)
			continue;

		/* on entry function 0 has already run @cb */
		if (i > 0)
			cb(pf, data);

		/* walk virtual functions of each pf */
		for (int j = 0; j < pci_num_vf(pf); j++) {
			struct pci_dev *vf __free(pci_dev_put) =
				pci_get_domain_bus_and_slot(
					pci_domain_nr(pf->bus),
					pci_iov_virtfn_bus(pf, j),
					pci_iov_virtfn_devfn(pf, j));

			if (!vf)
				continue;

			cb(vf, data);
		}
	}

	/*
	 * Walk downstream devices, assumes that an upstream DSM is
	 * limited to downstream physical functions
	 */
	if (pci_pcie_type(pdev) == PCI_EXP_TYPE_UPSTREAM && is_dsm(pdev))
		pci_walk_bus(pdev->subordinate, cb, data);
}

static void pci_tsm_walk_fns_reverse(struct pci_dev *pdev,
				     int (*cb)(struct pci_dev *pdev,
					       void *data),
				     void *data)
{
	/* Reverse walk downstream devices */
	if (pci_pcie_type(pdev) == PCI_EXP_TYPE_UPSTREAM && is_dsm(pdev))
		pci_walk_bus_reverse(pdev->subordinate, cb, data);

	/* Reverse walk subordinate physical functions */
	for (int i = 7; i >= 0; i--) {
		struct pci_dev *pf __free(pci_dev_put) = pci_get_slot(
			pdev->bus, PCI_DEVFN(PCI_SLOT(pdev->devfn), i));

		if (!pf)
			continue;

		/* reverse walk virtual functions */
		for (int j = pci_num_vf(pf) - 1; j >= 0; j--) {
			struct pci_dev *vf __free(pci_dev_put) =
				pci_get_domain_bus_and_slot(
					pci_domain_nr(pf->bus),
					pci_iov_virtfn_bus(pf, j),
					pci_iov_virtfn_devfn(pf, j));

			if (!vf)
				continue;
			cb(vf, data);
		}

		/* on exit, caller will run @cb on function 0 */
		if (i > 0)
			cb(pf, data);
	}
}

static int probe_fn(struct pci_dev *pdev, void *dsm)
{
	struct pci_dev *dsm_dev = dsm;
	const struct pci_tsm_ops *ops = dsm_dev->tsm->ops;

	pdev->tsm = ops->probe(pdev);
	pci_dbg(pdev, "setup TSM context: DSM: %s status: %s\n",
		pci_name(dsm_dev), pdev->tsm ? "success" : "failed");
	return 0;
}

static int pci_tsm_connect(struct pci_dev *pdev, struct tsm_dev *tsm_dev)
{
	int rc;
	struct pci_tsm_pf0 *tsm_pf0;
	const struct pci_tsm_ops *ops = tsm_pci_ops(tsm_dev);
	struct pci_tsm *pci_tsm __free(tsm_remove) = ops->probe(pdev);

	/* connect()  mutually exclusive with subfunction pci_tsm_init() */
	lockdep_assert_held_write(&pci_tsm_rwsem);

	if (!pci_tsm)
		return -ENXIO;

	pdev->tsm = pci_tsm;
	tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);

	/* mutex_intr assumes connect() is always sysfs/user driven */
	ACQUIRE(mutex_intr, lock)(&tsm_pf0->lock);
	if ((rc = ACQUIRE_ERR(mutex_intr, &lock)))
		return rc;

	rc = ops->connect(pdev);
	if (rc)
		return rc;

	pdev->tsm = no_free_ptr(pci_tsm);

	/*
	 * Now that the DSM is established, probe() all the potential
	 * dependent functions. Failure to probe a function is not fatal
	 * to connect(), it just disables subsequent security operations
	 * for that function.
	 */
	pci_tsm_walk_fns(pdev, probe_fn, pdev);
	return 0;
}

static ssize_t connect_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int rc;

	ACQUIRE(rwsem_read_intr, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &lock)))
		return rc;

	if (!pdev->tsm)
		return sysfs_emit(buf, "\n");

	return sysfs_emit(buf, "%s\n", tsm_name(pdev->tsm->ops->owner));
}

/* Is @tsm_dev managing physical link / session properties... */
static bool is_link_tsm(struct tsm_dev *tsm_dev)
{
	const struct pci_tsm_ops *ops = tsm_pci_ops(tsm_dev);

	return ops && ops->link_ops.probe;
}

/* ...or is @tsm_dev managing device security state ? */
static bool is_devsec_tsm(struct tsm_dev *tsm_dev)
{
	const struct pci_tsm_ops *ops = tsm_pci_ops(tsm_dev);

	return ops && ops->devsec_ops.lock;
}

static ssize_t connect_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct tsm_dev *tsm_dev;
	int rc, id;

	rc = sscanf(buf, "tsm%d\n", &id);
	if (rc != 1)
		return -EINVAL;

	ACQUIRE(rwsem_write_kill, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_write_kill, &lock)))
		return rc;

	if (pdev->tsm)
		return -EBUSY;

	tsm_dev = find_tsm_dev(id);
	if (!is_link_tsm(tsm_dev))
		return -ENXIO;

	rc = pci_tsm_connect(pdev, tsm_dev);
	if (rc)
		return rc;
	return len;
}
static DEVICE_ATTR_RW(connect);

static int remove_fn(struct pci_dev *pdev, void *data)
{
	tsm_remove(pdev->tsm);
	return 0;
}

/*
 * Note, this helper only returns an error code and takes an argument for
 * compatibility with the pci_walk_bus() callback prototype. pci_tsm_unbind()
 * always succeeds.
 */
static int __pci_tsm_unbind(struct pci_dev *pdev, void *data)
{
	struct pci_tdi *tdi;
	struct pci_tsm_pf0 *tsm_pf0;

	lockdep_assert_held(&pci_tsm_rwsem);

	if (!pdev->tsm)
		return 0;

	tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);
	guard(mutex)(&tsm_pf0->lock);

	tdi = pdev->tsm->tdi;
	if (!tdi)
		return 0;

	pdev->tsm->ops->unbind(tdi);
	pdev->tsm->tdi = NULL;

	return 0;
}

void pci_tsm_unbind(struct pci_dev *pdev)
{
	guard(rwsem_read)(&pci_tsm_rwsem);
	__pci_tsm_unbind(pdev, NULL);
}
EXPORT_SYMBOL_GPL(pci_tsm_unbind);

/**
 * pci_tsm_bind() - Bind @pdev as a TDI for @kvm
 * @pdev: PCI device function to bind
 * @kvm: Private memory attach context
 * @tdi_id: Identifier (virtual BDF) for the TDI as referenced by the TSM and DSM
 *
 * Returns 0 on success, or a negative error code on failure.
 *
 * Context: Caller is responsible for constraining the bind lifetime to the
 * registered state of the device. For example, pci_tsm_bind() /
 * pci_tsm_unbind() limited to the VFIO driver bound state of the device.
 */
int pci_tsm_bind(struct pci_dev *pdev, struct kvm *kvm, u32 tdi_id)
{
	const struct pci_tsm_ops *ops;
	struct pci_tsm_pf0 *tsm_pf0;
	struct pci_tdi *tdi;

	if (!kvm)
		return -EINVAL;

	guard(rwsem_read)(&pci_tsm_rwsem);

	if (!pdev->tsm)
		return -EINVAL;

	ops = pdev->tsm->ops;

	if (!is_link_tsm(ops->owner))
		return -ENXIO;

	tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);
	guard(mutex)(&tsm_pf0->lock);

	/* Resolve races to bind a TDI */
	if (pdev->tsm->tdi) {
		if (pdev->tsm->tdi->kvm == kvm)
			return 0;
		else
			return -EBUSY;
	}

	tdi = ops->bind(pdev, kvm, tdi_id);
	if (IS_ERR(tdi))
		return PTR_ERR(tdi);

	pdev->tsm->tdi = tdi;

	return 0;
}
EXPORT_SYMBOL_GPL(pci_tsm_bind);

/**
 * pci_tsm_guest_req() - helper to marshal guest requests to the TSM driver
 * @pdev: @pdev representing a bound tdi
 * @scope: security model scope for the TVM request
 * @req_in: Input payload forwarded from the guest
 * @in_len: Length of @req_in
 * @out_len: Output length of the returned response payload
 *
 * This is a common entry point for KVM service handlers in userspace responding
 * to TDI information or state change requests. The scope parameter limits
 * requests to TDISP state management, or limited debug.
 *
 * Returns a pointer to the response payload on success, @req_in if there is no
 * response to a successful request, or an ERR_PTR() on failure.
 *
 * Caller is responsible for kvfree() on the result when @ret != @req_in and
 * !IS_ERR_OR_NULL(@ret).
 *
 * Context: Caller is responsible for calling this within the pci_tsm_bind()
 * state of the TDI.
 */
void *pci_tsm_guest_req(struct pci_dev *pdev, enum pci_tsm_req_scope scope,
			void *req_in, size_t in_len, size_t *out_len)
{
	const struct pci_tsm_ops *ops;
	struct pci_tsm_pf0 *tsm_pf0;
	struct pci_tdi *tdi;
	int rc;

	/*
	 * Forbid requests that are not directly related to TDISP
	 * operations
	 */
	if (scope > PCI_TSM_REQ_STATE_CHANGE)
		return ERR_PTR(-EINVAL);

	ACQUIRE(rwsem_read_intr, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &lock)))
		return ERR_PTR(rc);

	if (!pdev->tsm)
		return ERR_PTR(-ENXIO);

	ops = pdev->tsm->ops;

	if (!is_link_tsm(ops->owner))
		return ERR_PTR(-ENXIO);

	tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);
	ACQUIRE(mutex_intr, ops_lock)(&tsm_pf0->lock);
	if ((rc = ACQUIRE_ERR(mutex_intr, &ops_lock)))
		return ERR_PTR(rc);

	tdi = pdev->tsm->tdi;
	if (!tdi)
		return ERR_PTR(-ENXIO);
	return ops->guest_req(pdev, scope, req_in, in_len, out_len);
}
EXPORT_SYMBOL_GPL(pci_tsm_guest_req);

static void pci_tsm_unbind_all(struct pci_dev *pdev)
{
	pci_tsm_walk_fns_reverse(pdev, __pci_tsm_unbind, NULL);
	__pci_tsm_unbind(pdev, NULL);
}

static void __pci_tsm_disconnect(struct pci_dev *pdev)
{
	struct pci_tsm_pf0 *tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);
	const struct pci_tsm_ops *ops = pdev->tsm->ops;

	/* disconnect() mutually exclusive with subfunction pci_tsm_init() */
	lockdep_assert_held_write(&pci_tsm_rwsem);

	pci_tsm_unbind_all(pdev);

	/*
	 * disconnect() is uninterruptible as it may be called for device
	 * teardown
	 */
	guard(mutex)(&tsm_pf0->lock);
	pci_tsm_walk_fns_reverse(pdev, remove_fn, NULL);
	ops->disconnect(pdev);
}

static void pci_tsm_disconnect(struct pci_dev *pdev)
{
	__pci_tsm_disconnect(pdev);
	tsm_remove(pdev->tsm);
}

static ssize_t disconnect_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	const struct pci_tsm_ops *ops;
	int rc;

	ACQUIRE(rwsem_write_kill, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_write_kill, &lock)))
		return rc;

	if (!pdev->tsm)
		return -ENXIO;

	ops = pdev->tsm->ops;
	if (!sysfs_streq(buf, tsm_name(ops->owner)))
		return -EINVAL;

	pci_tsm_disconnect(pdev);
	return len;
}
static DEVICE_ATTR_WO(disconnect);

static struct resource **alloc_encrypted_resources(struct pci_dev *pdev,
						   struct resource **__res)
{
	int i;

	memset(__res, 0, sizeof(struct resource *) * PCI_NUM_RESOURCES);

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		unsigned long flags = pci_resource_flags(pdev, i);
		resource_size_t len = pci_resource_len(pdev, i);

		if (!len || !(flags & IORESOURCE_MEM))
			continue;


		__res[i] = kzalloc(sizeof(struct resource), GFP_KERNEL);
		if (!__res[i])
			break;

		*__res[i] = DEFINE_RES_NAMED_DESC(pci_resource_start(pdev, i),
						  len, "PCI MMIO Encrypted",
						  flags, IORES_DESC_ENCRYPTED);

		if (insert_resource(&iomem_resource, __res[i]) != 0) {
			kfree(__res[i]);
			__res[i] = NULL;
			break;
		}
	}

	if (i >= PCI_NUM_RESOURCES)
		return __res;

	for (; i >= 0; i--) {
		if (!__res[i])
			continue;

		remove_resource(__res[i]);
		kfree(__res[i]);
		__res[i] = NULL;
	}

	return NULL;
}

static void set_encrypted_resources(struct pci_tsm_devsec *tsm,
				    struct resource **res)
{
	memcpy(tsm->resource, res, sizeof(tsm->resource));
}

static void free_encrypted_resources(struct resource **res)
{
	for (int i = PCI_NUM_RESOURCES - 1; i >= 0; i--) {
		if (!res[i])
			continue;
		remove_resource(res[i]);
		kfree(res[i]);
		res[i] = NULL;
	}
}

DEFINE_FREE(free_encrypted_resources, struct resource **,
	    if (_T) free_encrypted_resources(_T))

/**
 * pci_tsm_accept() - accept a device for private MMIO+DMA operation
 * @pdev: PCI device to accept
 *
 * "Accept" transitions a device to the run state, it is only suitable to make
 * that transition from a known DMA-idle (no active mappings) state. The "driver
 * detached" state is a coarse way to assert that requirement.
 */
static int pci_tsm_accept(struct pci_dev *pdev)
{
	struct resource *__res[PCI_NUM_RESOURCES];
	int rc;

	ACQUIRE(rwsem_read_intr, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &lock)))
		return rc;

	if (!pdev->tsm)
		return -EINVAL;

	ACQUIRE(device_intr, dev_lock)(&pdev->dev);
	if ((rc = ACQUIRE_ERR(device_intr, &dev_lock)))
		return rc;

	if (pdev->dev.driver)
		return -EBUSY;

	struct resource **res __free(free_encrypted_resources) =
		alloc_encrypted_resources(pdev, __res);
	if (!res)
		return -ENOMEM;

	rc = pdev->tsm->ops->accept(pdev);
	if (rc)
		return rc;
	device_cc_accept(&pdev->dev);
	set_encrypted_resources(to_pci_tsm_devsec(pdev->tsm), no_free_ptr(res));

	return 0;
}

static ssize_t accept_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	bool accept;
	int rc;

	rc = kstrtobool(buf, &accept);
	if (rc)
		return rc;

	/*
	 * TDISP can only go from RUN to UNLOCKED/ERROR, so there is no
	 * 'unaccept' verb.
	 */
	if (!accept)
		return -EINVAL;

	rc = pci_tsm_accept(pdev);
	if (rc)
		return rc;

	return len;
}

static ssize_t accept_show(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	return sysfs_emit(buf, "%d\n", device_cc_accepted(dev));
}
static DEVICE_ATTR_RW(accept);

/**
 * pci_tsm_unlock() - Transition TDI from LOCKED/RUN to UNLOCKED
 * @pdev: TDI device to unlock
 *
 * Returns void, requires all callers to have satisfied dependencies like making
 * sure the device is locked and detached from its driver.
 */
static void pci_tsm_unlock(struct pci_dev *pdev)
{
	struct pci_tsm_devsec *tsm = to_pci_tsm_devsec(pdev->tsm);

	lockdep_assert_held_write(&pci_tsm_rwsem);
	lockdep_assert_held(&pdev->dev.mutex);

	if (dev_WARN_ONCE(&pdev->dev, pdev->dev.driver,
			  "unlock attempted on driver attached device\n"))
		return;

	free_encrypted_resources(tsm->resource);
	device_cc_reject(&pdev->dev);
	pdev->tsm->ops->unlock(pdev);
	pdev->tsm = NULL;
}

static int pci_tsm_lock(struct pci_dev *pdev, struct tsm_dev *tsm_dev)
{
	const struct pci_tsm_ops *ops = tsm_pci_ops(tsm_dev);
	struct pci_tsm *tsm;
	int rc;

	ACQUIRE(device_intr, lock)(&pdev->dev);
	if ((rc = ACQUIRE_ERR(device_intr, &lock)))
		return rc;

	if (pdev->dev.driver)
		return -EBUSY;

	tsm = ops->lock(pdev);
	if (IS_ERR(tsm))
		return PTR_ERR(tsm);

	pdev->tsm = tsm;
	return 0;
}

static ssize_t lock_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct tsm_dev *tsm_dev;
	int rc, id;

	rc = sscanf(buf, "tsm%d\n", &id);
	if (rc != 1)
		return -EINVAL;

	ACQUIRE(rwsem_write_kill, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_write_kill, &lock)))
		return rc;

	if (pdev->tsm)
		return -EBUSY;

	tsm_dev = find_tsm_dev(id);
	if (!is_devsec_tsm(tsm_dev))
		return -ENXIO;

	rc = pci_tsm_lock(pdev, tsm_dev);
	if (rc)
		return rc;
	return len;
}

static ssize_t lock_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int rc;

	ACQUIRE(rwsem_read_intr, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &lock)))
		return rc;

	if (!pdev->tsm)
		return sysfs_emit(buf, "\n");

	return sysfs_emit(buf, "%s\n", tsm_name(pdev->tsm->ops->owner));
}
static DEVICE_ATTR_RW(lock);

static ssize_t unlock_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	const struct pci_tsm_ops *ops;
	int rc;

	ACQUIRE(rwsem_write_kill, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_write_kill, &lock)))
		return rc;

	if (!pdev->tsm)
		return -EINVAL;

	ops = pdev->tsm->ops;
	if (!sysfs_streq(buf, tsm_name(ops->owner)))
		return -EINVAL;

	ACQUIRE(device_intr, dev_lock)(&pdev->dev);
	if ((rc = ACQUIRE_ERR(device_intr, &dev_lock)))
		return rc;

	if (pdev->dev.driver)
		return -EBUSY;

	pci_tsm_unlock(pdev);

	return len;
}
static DEVICE_ATTR_WO(unlock);

/* The 'authenticated' attribute is exclusive to the presence of a 'link' TSM */
static bool pci_tsm_link_group_visible(struct kobject *kobj)
{
	struct pci_dev *pdev = to_pci_dev(kobj_to_dev(kobj));

	return pci_tsm_link_count && is_pci_tsm_pf0(pdev);
}
DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(pci_tsm_link);

static bool pci_tsm_devsec_group_visible(struct kobject *kobj)
{
	struct pci_dev *pdev = to_pci_dev(kobj_to_dev(kobj));

	return pci_tsm_devsec_count && has_tee(pdev);
}

/*
 * 'link' and 'devsec' TSMs share the same 'tsm/' sysfs group, so the TSM type
 * specific attributes need individual visibility checks.
 */
static umode_t pci_tsm_attr_visible(struct kobject *kobj,
				    struct attribute *attr, int n)
{
	if (pci_tsm_link_group_visible(kobj)) {
		if (attr == &dev_attr_connect.attr ||
		    attr == &dev_attr_disconnect.attr)
			return attr->mode;
	}

	if (pci_tsm_devsec_group_visible(kobj)) {
		if (attr == &dev_attr_accept.attr ||
		    attr == &dev_attr_lock.attr ||
		    attr == &dev_attr_unlock.attr)
			return attr->mode;
	}

	return 0;
}

static bool pci_tsm_group_visible(struct kobject *kobj)
{
	return pci_tsm_link_group_visible(kobj) ||
	       pci_tsm_devsec_group_visible(kobj);
}
DEFINE_SYSFS_GROUP_VISIBLE(pci_tsm);

static struct attribute *pci_tsm_attrs[] = {
	&dev_attr_connect.attr,
	&dev_attr_disconnect.attr,
	&dev_attr_accept.attr,
	&dev_attr_lock.attr,
	&dev_attr_unlock.attr,
	NULL
};

const struct attribute_group pci_tsm_attr_group = {
	.name = "tsm",
	.attrs = pci_tsm_attrs,
	.is_visible = SYSFS_GROUP_VISIBLE(pci_tsm),
};

static ssize_t authenticated_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	/*
	 * When the SPDM session established via TSM the 'authenticated' state
	 * of the device is identical to the connect state.
	 */
	return connect_show(dev, attr, buf);
}
static DEVICE_ATTR_RO(authenticated);

static struct attribute *pci_tsm_auth_attrs[] = {
	&dev_attr_authenticated.attr,
	NULL
};

const struct attribute_group pci_tsm_auth_attr_group = {
	.attrs = pci_tsm_auth_attrs,
	.is_visible = SYSFS_GROUP_VISIBLE(pci_tsm_link),
};

/*
 * Retrieve physical function0 device whether it has TEE capability or not
 */
static struct pci_dev *pf0_dev_get(struct pci_dev *pdev)
{
	struct pci_dev *pf_dev = pci_physfn(pdev);

	if (PCI_FUNC(pf_dev->devfn) == 0)
		return pci_dev_get(pf_dev);

	return pci_get_slot(pf_dev->bus,
			    pf_dev->devfn - PCI_FUNC(pf_dev->devfn));
}

/*
 * Find the PCI Device instance that serves as the Device Security Manager (DSM)
 * for @pdev. Note that no additional reference is held for the resulting device
 * because @pdev always has a longer registered lifetime than its DSM by virtue
 * of being a child of, or identical to, its DSM.
 */
static struct pci_dev *find_dsm_dev(struct pci_dev *pdev)
{
	struct device *grandparent;
	struct pci_dev *uport;

	if (is_pci_tsm_pf0(pdev))
		return pdev;

	struct pci_dev *pf0 __free(pci_dev_put) = pf0_dev_get(pdev);
	if (!pf0)
		return NULL;

	if (is_dsm(pf0))
		return pf0;

	/*
	 * For cases where a switch may be hosting TDISP services on behalf of
	 * downstream devices, check the first upstream port relative to this
	 * endpoint.
	 */
	if (!pdev->dev.parent)
		return NULL;
	grandparent = pdev->dev.parent->parent;
	if (!grandparent)
		return NULL;
	if (!dev_is_pci(grandparent))
		return NULL;
	uport = to_pci_dev(grandparent);
	if (!pci_is_pcie(uport) ||
	    pci_pcie_type(uport) != PCI_EXP_TYPE_UPSTREAM)
		return NULL;

	if (is_dsm(uport))
		return uport;
	return NULL;
}

/**
 * pci_tsm_link_constructor() - base 'struct pci_tsm' initialization for link TSMs
 * @pdev: The PCI device
 * @tsm: context to initialize
 * @ops: PCI link operations provided by the TSM
 */
int pci_tsm_link_constructor(struct pci_dev *pdev, struct pci_tsm *tsm,
			     const struct pci_tsm_ops *ops)
{
	if (!is_link_tsm(ops->owner))
		return -EINVAL;

	tsm->dsm = find_dsm_dev(pdev);
	if (!tsm->dsm) {
		pci_warn(pdev, "failed to find Device Security Manager\n");
		return -ENXIO;
	}
	tsm->pdev = pdev;
	tsm->ops = ops;

	return 0;
}
EXPORT_SYMBOL_GPL(pci_tsm_link_constructor);

/**
 * pci_tsm_devsec_constructor() - devsec TSM context initialization
 * @pdev: The PCI device
 * @tsm: context to initialize
 * @ops: PCI devsec operations provided by the TSM
 */
int pci_tsm_devsec_constructor(struct pci_dev *pdev, struct pci_tsm_devsec *tsm,
			       const struct pci_tsm_ops *ops)
{
	struct pci_tsm *pci_tsm = &tsm->base;

	if (!is_devsec_tsm(ops->owner))
		return -EINVAL;

	pci_tsm->dsm = NULL;
	pci_tsm->tdi = NULL;
	pci_tsm->pdev = pdev;
	pci_tsm->ops = ops;

	return 0;
}
EXPORT_SYMBOL_GPL(pci_tsm_devsec_constructor);

/**
 * pci_tsm_pf0_constructor() - common 'struct pci_tsm_pf0' (DSM) initialization
 * @pdev: Physical Function 0 PCI device (as indicated by is_pci_tsm_pf0())
 * @tsm: context to initialize
 * @ops: PCI link operations provided by the TSM
 */
int pci_tsm_pf0_constructor(struct pci_dev *pdev, struct pci_tsm_pf0 *tsm,
			    const struct pci_tsm_ops *ops)
{
	mutex_init(&tsm->lock);
	tsm->doe_mb = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
					   PCI_DOE_PROTO_CMA);
	if (!tsm->doe_mb) {
		pci_warn(pdev, "TSM init failure, no CMA mailbox\n");
		return -ENODEV;
	}

	return pci_tsm_link_constructor(pdev, &tsm->base, ops);
}
EXPORT_SYMBOL_GPL(pci_tsm_pf0_constructor);

void pci_tsm_pf0_destructor(struct pci_tsm_pf0 *pf0_tsm)
{
	mutex_destroy(&pf0_tsm->lock);
}
EXPORT_SYMBOL_GPL(pci_tsm_pf0_destructor);

static void pf0_sysfs_enable(struct pci_dev *pdev)
{
	bool tee = pdev->devcap & PCI_EXP_DEVCAP_TEE;

	pci_dbg(pdev, "Device Security Manager detected (%s%s%s)\n",
		pdev->ide_cap ? "IDE" : "", pdev->ide_cap && tee ? " " : "",
		tee ? "TEE" : "");

	sysfs_update_group(&pdev->dev.kobj, &pci_tsm_auth_attr_group);
	sysfs_update_group(&pdev->dev.kobj, &pci_tsm_attr_group);
}

static void devsec_sysfs_enable(struct pci_dev *pdev)
{
	pci_dbg(pdev, "TEE I/O Device capability detected (TDISP)\n");

	sysfs_update_group(&pdev->dev.kobj, &pci_tsm_attr_group);
}

int pci_tsm_register(struct tsm_dev *tsm_dev)
{
	struct pci_dev *pdev = NULL;

	if (!tsm_dev)
		return -EINVAL;

	/*
	 * The TSM device must have pci_ops, and only implement one of link_ops
	 * or devsec_ops.
	 */
	if (!tsm_pci_ops(tsm_dev))
		return -EINVAL;

	if (!is_link_tsm(tsm_dev) && !is_devsec_tsm(tsm_dev))
		return -EINVAL;

	if (is_link_tsm(tsm_dev) && is_devsec_tsm(tsm_dev))
		return -EINVAL;

	guard(rwsem_write)(&pci_tsm_rwsem);

	/* on first enable, update sysfs groups */
	if (is_link_tsm(tsm_dev) && pci_tsm_link_count++ == 0) {
		for_each_pci_dev(pdev)
			if (is_pci_tsm_pf0(pdev))
				pf0_sysfs_enable(pdev);
	} else if (is_devsec_tsm(tsm_dev) && pci_tsm_devsec_count++ == 0) {
		for_each_pci_dev(pdev)
			if (has_tee(pdev))
				devsec_sysfs_enable(pdev);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(pci_tsm_register);

/**
 * __pci_tsm_destroy() - destroy the TSM context for @pdev
 * @pdev: device to cleanup
 * @tsm_dev: TSM context if a TSM device is being removed, NULL if
 *	     @pdev is being removed.
 *
 * At device removal or TSM unregistration all established context
 * with the TSM is torn down. Additionally, if there are no more TSMs
 * registered, the PCI tsm/ sysfs attributes are hidden.
 */
static void __pci_tsm_destroy(struct pci_dev *pdev, struct tsm_dev *tsm_dev)
{
	struct pci_tsm *tsm = pdev->tsm;

	lockdep_assert_held_write(&pci_tsm_rwsem);

	if (is_link_tsm(tsm_dev) && is_pci_tsm_pf0(pdev) && !pci_tsm_link_count) {
		sysfs_update_group(&pdev->dev.kobj, &pci_tsm_auth_attr_group);
		sysfs_update_group(&pdev->dev.kobj, &pci_tsm_attr_group);
	}

	if (is_devsec_tsm(tsm_dev) && !pci_tsm_devsec_count)
		sysfs_update_group(&pdev->dev.kobj, &pci_tsm_attr_group);

	if (!tsm)
		return;

	if (!tsm_dev)
		tsm_dev = tsm->ops->owner;
	else if (tsm_dev != tsm->ops->owner)
		return;

	/* Disconnect DSMs, unlock assigned TDIs, or cleanup DSM subfunctions */
	if (is_link_tsm(tsm_dev)) {
		if (is_pci_tsm_pf0(pdev))
			pci_tsm_disconnect(pdev);
		else
			tsm_remove(pdev->tsm);
	}

	if (is_devsec_tsm(tsm_dev) && has_tee(pdev)) {
		guard(device)(&pdev->dev);
		pci_tsm_unlock(pdev);
	}
}

void pci_tsm_destroy(struct pci_dev *pdev)
{
	guard(rwsem_write)(&pci_tsm_rwsem);
	__pci_tsm_destroy(pdev, NULL);
}

void pci_tsm_init(struct pci_dev *pdev)
{
	guard(rwsem_read)(&pci_tsm_rwsem);

	/*
	 * Subfunctions are either probed synchronous with connect() or later
	 * when either the SR-IOV configuration is changed, or, unlikely,
	 * connect() raced initial bus scanning.
	 */
	if (pdev->tsm)
		return;

	if (pci_tsm_link_count) {
		struct pci_dev *dsm = find_dsm_dev(pdev);

		if (!dsm)
			return;

		/*
		 * The only path to init a Device Security Manager capable
		 * device is via connect().
		 */
		if (!dsm->tsm)
			return;

		probe_fn(pdev, dsm);
	}
}

void pci_tsm_unregister(struct tsm_dev *tsm_dev)
{
	struct pci_dev *pdev = NULL;

	guard(rwsem_write)(&pci_tsm_rwsem);
	if (is_link_tsm(tsm_dev))
		pci_tsm_link_count--;
	if (is_devsec_tsm(tsm_dev))
		pci_tsm_devsec_count--;
	for_each_pci_dev_reverse(pdev)
		__pci_tsm_destroy(pdev, tsm_dev);
}
