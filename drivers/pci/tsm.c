// SPDX-License-Identifier: GPL-2.0
/*
 * TEE Security Manager for the TEE Device Interface Security Protocol
 * (TDISP, PCIe r6.1 sec 11)
 *
 * Copyright(c) 2024 Intel Corporation. All rights reserved.
 */

#define dev_fmt(fmt) "TSM: " fmt

#include <linux/bitfield.h>
#include <linux/xarray.h>
#include <linux/sysfs.h>

#include <linux/tsm.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tsm.h>
#include "pci.h"

/*
 * Provide a read/write lock against the init / exit of pdev tsm
 * capabilities and arrival/departure of a tsm instance
 */
static DECLARE_RWSEM(pci_tsm_rwsem);
static int pci_tsm_count;

static inline bool is_dsm(struct pci_dev *pdev)
{
	return pdev->tsm && pdev->tsm->dsm == pdev;
}

static struct pci_tsm_pf0 *to_pci_tsm_pf0(struct pci_tsm *pci_tsm)
{
	struct pci_dev *pdev = pci_tsm->pdev;

	if (!is_pci_tsm_pf0(pdev) || !is_dsm(pdev)) {
		dev_WARN_ONCE(&pdev->dev, 1, "invalid context object\n");
		return NULL;
	}

	return container_of(pci_tsm, struct pci_tsm_pf0, tsm);
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

static int call_cb_put(struct pci_dev *pdev, void *data,
		       int (*cb)(struct pci_dev *pdev, void *data))
{
	int rc;

	if (!pdev)
		return 0;
	rc = cb(pdev, data);
	pci_dev_put(pdev);
	return rc;
}

static void pci_tsm_walk_fns(struct pci_dev *pdev,
			     int (*cb)(struct pci_dev *pdev, void *data),
			     void *data)
{
	struct pci_dev *fn;
	int i;

	/* walk virtual functions */
        for (i = 0; i < pci_num_vf(pdev); i++) {
		fn = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
						 pci_iov_virtfn_bus(pdev, i),
						 pci_iov_virtfn_devfn(pdev, i));
		if (call_cb_put(fn, data, cb))
			return;
        }

	/* walk subordinate physical functions */
	for (i = 1; i < 8; i++) {
		fn = pci_get_slot(pdev->bus,
				  PCI_DEVFN(PCI_SLOT(pdev->devfn), i));
		if (call_cb_put(fn, data, cb))
			return;
	}

	/* walk downstream devices */
        if (pci_pcie_type(pdev) != PCI_EXP_TYPE_UPSTREAM)
                return;

        if (!is_dsm(pdev))
                return;

        pci_walk_bus(pdev->subordinate, cb, data);
}

static void pci_tsm_walk_fns_reverse(struct pci_dev *pdev,
				     int (*cb)(struct pci_dev *pdev,
					       void *data),
				     void *data)
{
	struct pci_dev *fn;
	int i;

	/* reverse walk virtual functions */
	for (i = pci_num_vf(pdev) - 1; i >= 0; i--) {
		fn = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
						 pci_iov_virtfn_bus(pdev, i),
						 pci_iov_virtfn_devfn(pdev, i));
		if (call_cb_put(fn, data, cb))
			return;
	}

	/* reverse walk subordinate physical functions */
	for (i = 7; i >= 1; i--) {
		fn = pci_get_slot(pdev->bus,
				  PCI_DEVFN(PCI_SLOT(pdev->devfn), i));
		if (call_cb_put(fn, data, cb))
			return;
	}

	/* reverse walk downstream devices */
	if (pci_pcie_type(pdev) != PCI_EXP_TYPE_UPSTREAM)
		return;

	if (!is_dsm(pdev))
		return;

	pci_walk_bus_reverse(pdev->subordinate, cb, data);
}

static int probe_fn(struct pci_dev *pdev, void *dsm)
{
	struct pci_dev *dsm_dev = dsm;
	const struct pci_tsm_ops *ops = dsm_dev->tsm->ops;

	pdev->tsm = ops->probe(pdev);
	pci_dbg(pdev, "setup tsm context: dsm: %s status: %s\n",
		pci_name(dsm_dev), pdev->tsm ? "success" : "failed");
	return 0;
}

static void pci_tsm_probe_fns(struct pci_dev *dsm)
{
	pci_tsm_walk_fns(dsm, probe_fn, dsm);
}

static int pci_tsm_connect(struct pci_dev *pdev, struct tsm_dev *tsm_dev)
{
	int rc;
	struct pci_tsm_pf0 *tsm_pf0;
	const struct pci_tsm_ops *ops = tsm_pci_ops(tsm_dev);
	struct pci_tsm *pci_tsm __free(tsm_remove) = ops->probe(pdev);

	if (!pci_tsm)
		return -ENXIO;

	pdev->tsm = pci_tsm;
	tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);

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
	pci_tsm_probe_fns(pdev);
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

static ssize_t connect_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t len)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	const struct pci_tsm_ops *ops;
	struct tsm_dev *tsm_dev;
	int rc, id;

	rc = sscanf(buf, "tsm%d\n", &id);
	if (rc != 1)
		return -EINVAL;

	ACQUIRE(rwsem_read_intr, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &lock)))
		return rc;

	if (pdev->tsm)
		return -EBUSY;

	tsm_dev = find_tsm_dev(id);
	if (!tsm_dev)
		return -ENXIO;

	ops = tsm_pci_ops(tsm_dev);
	if (!ops || !ops->connect || !ops->probe)
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

static void pci_tsm_remove_fns(struct pci_dev *dsm)
{
	pci_tsm_walk_fns_reverse(dsm, remove_fn, NULL);
}

static void __pci_tsm_disconnect(struct pci_dev *pdev)
{
	struct pci_tsm_pf0 *tsm_pf0 = to_pci_tsm_pf0(pdev->tsm);
	const struct pci_tsm_ops *ops = pdev->tsm->ops;

	/* disconnect is not interruptible */
	guard(mutex)(&tsm_pf0->lock);
	pci_tsm_remove_fns(pdev);
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
	bool disconnect;
	int rc;

	rc = kstrtobool(buf, &disconnect);
	if (rc)
		return rc;
	if (!disconnect)
		return -EINVAL;

	ACQUIRE(rwsem_read_intr, lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &lock)))
		return rc;

	if (!pdev->tsm)
		return -ENXIO;

	pci_tsm_disconnect(pdev);
	return len;
}
static DEVICE_ATTR_WO(disconnect);

static bool pci_tsm_pf0_group_visible(struct kobject *kobj)
{
	struct device *dev = kobj_to_dev(kobj);
	struct pci_dev *pdev = to_pci_dev(dev);

	return pci_tsm_count && is_pci_tsm_pf0(pdev);
}
DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(pci_tsm_pf0);

static struct attribute *pci_tsm_pf0_attrs[] = {
	&dev_attr_connect.attr,
	&dev_attr_disconnect.attr,
	NULL
};

const struct attribute_group pci_tsm_pf0_attr_group = {
	.name = "tsm",
	.attrs = pci_tsm_pf0_attrs,
	.is_visible = SYSFS_GROUP_VISIBLE(pci_tsm_pf0),
};

static ssize_t authenticated_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	/*
	 * When device authentication is TSM owned, 'authenticated' is
	 * identical to the connect state.
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
	.is_visible = SYSFS_GROUP_VISIBLE(pci_tsm_pf0),
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
 * Find the PCI Device instance that serves as the Device Security
 * Manger (DSM) for @pdev. Note that no additional reference is held for
 * the resulting device because @pdev always has a longer registered
 * lifetime than its DSM by virtue of being a child of or identical to
 * its DSM.
 */
static struct pci_dev *find_dsm_dev(struct pci_dev *pdev)
{
	struct pci_dev *uport_pf0;

	if (is_pci_tsm_pf0(pdev))
		return pdev;

	struct pci_dev *pf0 __free(pci_dev_put) = pf0_dev_get(pdev);
	if (!pf0)
		return NULL;

	if (is_dsm(pf0))
		return pf0;

	/*
	 * For cases where a switch may be hosting TDISP services on
	 * behalf of downstream devices, check the first usptream port
	 * relative to this endpoint.
         */
	if (!pdev->dev.parent || !pdev->dev.parent->parent)
		return NULL;

	uport_pf0 = to_pci_dev(pdev->dev.parent->parent);
	if (is_dsm(uport_pf0))
		return uport_pf0;
	return NULL;
}

/**
 * pci_tsm_constructor() - base 'struct pci_tsm' initialization
 * @pdev: The PCI device
 * @tsm: context to initialize
 * @ops: PCI operations provided by the TSM
 */
int pci_tsm_constructor(struct pci_dev *pdev, struct pci_tsm *tsm,
			const struct pci_tsm_ops *ops)
{
	tsm->pdev = pdev;
	tsm->ops = ops;
	tsm->dsm = find_dsm_dev(pdev);
	if (!tsm->dsm) {
		pci_warn(pdev, "failed to find Device Security Manager\n");
		return -ENXIO;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(pci_tsm_constructor);

/**
 * pci_tsm_pf0_constructor() - common 'struct pci_tsm_pf0' initialization
 * @pdev: Physical Function 0 PCI device (as indicated by is_pci_tsm_pf0())
 * @tsm: context to initialize
 */
int pci_tsm_pf0_constructor(struct pci_dev *pdev, struct pci_tsm_pf0 *tsm,
			    const struct pci_tsm_ops *ops)
{
	struct tsm_dev *tsm_dev = ops->owner;

	mutex_init(&tsm->lock);
	tsm->doe_mb = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
					   PCI_DOE_PROTO_CMA);
	if (!tsm->doe_mb) {
		pci_warn(pdev, "TSM init failure, no CMA mailbox\n");
		return -ENODEV;
	}

	if (tsm_pci_group(tsm_dev))
		sysfs_merge_group(&pdev->dev.kobj, tsm_pci_group(tsm_dev));

	return pci_tsm_constructor(pdev, &tsm->tsm, ops);
}
EXPORT_SYMBOL_GPL(pci_tsm_pf0_constructor);

void pci_tsm_pf0_destructor(struct pci_tsm_pf0 *pf0_tsm)
{
	struct pci_tsm *tsm = &pf0_tsm->tsm;
	struct pci_dev *pdev = tsm->pdev;
	struct tsm_dev *tsm_dev = tsm->ops->owner;

	if (tsm_pci_group(tsm_dev))
		sysfs_unmerge_group(&pdev->dev.kobj, tsm_pci_group(tsm_dev));
	mutex_destroy(&pf0_tsm->lock);
}
EXPORT_SYMBOL_GPL(pci_tsm_pf0_destructor);

static void pf0_sysfs_enable(struct pci_dev *pdev)
{
	pci_dbg(pdev, "Device Security Manager detected (%s%s )\n",
		pdev->ide_cap ? " ide" : "",
		pdev->devcap & PCI_EXP_DEVCAP_TEE ? " tee" : "");

	sysfs_update_group(&pdev->dev.kobj, &pci_tsm_auth_attr_group);
	sysfs_update_group(&pdev->dev.kobj, &pci_tsm_pf0_attr_group);
}

int pci_tsm_register(struct tsm_dev *tsm_dev)
{
	const struct pci_tsm_ops *ops;
	struct pci_dev *pdev = NULL;

	if (!tsm_dev)
		return -EINVAL;

	/*
	 * The TSM device must have pci_ops, and only implement one of link_ops
	 * or sec_ops.
	 */
	ops = tsm_pci_ops(tsm_dev);
	if (!ops)
		return -EINVAL;

	if (!ops->probe && !ops->sec_probe)
		return -EINVAL;

	if (ops->probe && ops->sec_probe)
		return -EINVAL;

	guard(rwsem_write)(&pci_tsm_rwsem);

	pci_tsm_count++;

	/* PCI/TSM sysfs already enabled? */
	if (pci_tsm_count > 1)
		return 0;

	for_each_pci_dev(pdev)
		if (is_pci_tsm_pf0(pdev))
			pf0_sysfs_enable(pdev);
	return 0;
}
EXPORT_SYMBOL_GPL(pci_tsm_register);

/**
 * __pci_tsm_destroy() - destroy the TSM context for @pdev
 * @pdev: device to cleanup
 * @tsm_dev: TSM context if a TSM device is being removed, NULL if
 * 	     @pdev is being removed.
 *
 * At device removal or TSM unregistration all established context
 * with the TSM is torn down. Additionally, if there are no more TSMs
 * registered, the PCI tsm/ sysfs attributes are hidden.
 */
static void __pci_tsm_destroy(struct pci_dev *pdev, struct tsm_dev *tsm_dev)
{
	struct pci_tsm *tsm = pdev->tsm;

	lockdep_assert_held_write(&pci_tsm_rwsem);

	if (tsm_dev && is_pci_tsm_pf0(pdev) && !pci_tsm_count) {
		sysfs_update_group(&pdev->dev.kobj, &pci_tsm_auth_attr_group);
		sysfs_update_group(&pdev->dev.kobj, &pci_tsm_pf0_attr_group);
	}

	if (!tsm)
		return;

	if (!tsm_dev)
		tsm_dev = tsm->ops->owner;
	else if (tsm_dev != tsm->ops->owner)
		return;

	if (is_pci_tsm_pf0(pdev))
		pci_tsm_disconnect(pdev);
	else
		tsm_remove(pdev->tsm);
}

void pci_tsm_destroy(struct pci_dev *pdev)
{
	guard(rwsem_write)(&pci_tsm_rwsem);
	__pci_tsm_destroy(pdev, NULL);
}

void pci_tsm_unregister(struct tsm_dev *tsm_dev)
{
	struct pci_dev *pdev = NULL;

	guard(rwsem_write)(&pci_tsm_rwsem);
	pci_tsm_count--;
	for_each_pci_dev_reverse(pdev)
		__pci_tsm_destroy(pdev, tsm_dev);
}

int pci_tsm_doe_transfer(struct pci_dev *pdev, enum pci_doe_proto type,
			 const void *req, size_t req_sz, void *resp,
			 size_t resp_sz)
{
	struct pci_tsm_pf0 *tsm;

	if (!pdev->tsm || !is_pci_tsm_pf0(pdev))
		return -ENXIO;

	tsm = to_pci_tsm_pf0(pdev->tsm);
	if (!tsm->doe_mb)
		return -ENXIO;

	return pci_doe(tsm->doe_mb, PCI_VENDOR_ID_PCI_SIG, type, req, req_sz,
		       resp, resp_sz);
}
EXPORT_SYMBOL_GPL(pci_tsm_doe_transfer);
