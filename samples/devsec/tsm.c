// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved. */

#define dev_fmt(fmt) "devsec: " fmt
#include <linux/device/faux.h>
#include <linux/pci-tsm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/tsm.h>
#include "devsec.h"

struct devsec_dev_data {
	struct pci_tsm_devsec pci;
};

static struct devsec_dev_data *to_devsec_data(struct pci_tsm *tsm)
{
	return container_of(tsm, struct devsec_dev_data, pci.base);
}

static const struct pci_tsm_ops *__devsec_pci_ops;

static struct pci_tsm *devsec_tsm_lock(struct pci_dev *pdev)
{
	int rc;

	struct devsec_dev_data *devsec_data __free(kfree) =
		kzalloc(sizeof(*devsec_data), GFP_KERNEL);
	if (!devsec_data)
		return ERR_PTR(-ENOMEM);

	rc = pci_tsm_devsec_constructor(pdev, &devsec_data->pci,
					__devsec_pci_ops);
	if (rc)
		return ERR_PTR(rc);

	return &no_free_ptr(devsec_data)->pci.base;
}

static void devsec_tsm_unlock(struct pci_dev *pdev)
{
	struct devsec_dev_data *devsec_data = to_devsec_data(pdev->tsm);

	kfree(devsec_data);
}

static int devsec_tsm_accept(struct pci_dev *pdev)
{
	/* LGTM */
	return 0;
}

static struct pci_tsm_ops devsec_pci_ops = {
	.lock = devsec_tsm_lock,
	.unlock = devsec_tsm_unlock,
	.accept = devsec_tsm_accept,
};

static void devsec_tsm_remove(void *tsm_dev)
{
	tsm_unregister(tsm_dev);
}

static int devsec_tsm_probe(struct faux_device *fdev)
{
	struct tsm_dev *tsm_dev;

	tsm_dev = tsm_register(&fdev->dev, &devsec_pci_ops);
	if (IS_ERR(tsm_dev))
		return PTR_ERR(tsm_dev);

	return devm_add_action_or_reset(&fdev->dev, devsec_tsm_remove,
					tsm_dev);
}

static struct faux_device *devsec_tsm;

static const struct faux_device_ops devsec_device_ops = {
	.probe = devsec_tsm_probe,
};

static int __init devsec_tsm_init(void)
{
	__devsec_pci_ops = &devsec_pci_ops;
	devsec_tsm = faux_device_create("devsec_tsm", NULL, &devsec_device_ops);
	if (!devsec_tsm)
		return -ENOMEM;
	return 0;
}
module_init(devsec_tsm_init);

static void __exit devsec_tsm_exit(void)
{
	faux_device_destroy(devsec_tsm);
}
module_exit(devsec_tsm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: Device Security TSM Driver");
