// SPDX-License-Identifier: GPL-2.0+
/*
 * Sound card driver for virtio
 * Copyright (C) 2020  OpenSynergy GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/virtio_config.h>
#include <sound/initval.h>

#include "virtio_card.h"

#ifndef VIRTIO_ID_SOUND
#define VIRTIO_ID_SOUND 25
#endif

static int virtsnd_find_vqs(struct virtio_snd *snd)
{
	int rc;
	int i;
	struct virtio_device *vdev = snd->vdev;
	vq_callback_t *callbacks[VIRTIO_SND_VQ_MAX] = { 0 };
	const char *names[VIRTIO_SND_VQ_MAX] = {
		"virtsnd-ctl", "virtsnd-event", "virtsnd-tx", "virtsnd-rx"
	};
	struct virtqueue *vqs[VIRTIO_SND_VQ_MAX] = { 0 };
	unsigned int streams = 0;

	callbacks[VIRTIO_SND_VQ_CONTROL] = virtsnd_ctl_notify_cb;
	callbacks[VIRTIO_SND_VQ_EVENT] = virtsnd_event_notify_cb;

	virtio_cread(vdev, struct virtio_snd_config, streams, &streams);
	if (streams) {
		callbacks[VIRTIO_SND_VQ_TX] = virtsnd_pcm_tx_notify_cb;
		callbacks[VIRTIO_SND_VQ_RX] = virtsnd_pcm_rx_notify_cb;
	}

#if KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE
	rc = virtio_find_vqs(vdev, VIRTIO_SND_VQ_MAX, vqs, callbacks, names,
			     NULL);
#else
	rc = vdev->config->find_vqs(vdev, VIRTIO_SND_VQ_MAX, vqs, callbacks,
				    names);
#endif
	if (rc) {
		dev_err(&vdev->dev, "Failed to initialize virtqueues");
		return rc;
	}

	for (i = 0; i < VIRTIO_SND_VQ_MAX; ++i) {
		/*
		 * By default, disable callbacks for all queues except the
		 * control queue, since the device must be fully initialized
		 * first.
		 */
		if (i != VIRTIO_SND_VQ_CONTROL)
			virtqueue_disable_cb(vqs[i]);

		snd->queues[i].vqueue = vqs[i];
	}

	rc = virtsnd_event_populate(snd);
	if (rc)
		return rc;

	return 0;
}

static void virtsnd_enable_vqs(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtqueue *vqueue;

	vqueue = snd->queues[VIRTIO_SND_VQ_EVENT].vqueue;
	if (!virtqueue_enable_cb(vqueue))
		virtsnd_event_notify_cb(vqueue);

	if (snd->nsubstreams) {
		vqueue = snd->queues[VIRTIO_SND_VQ_TX].vqueue;
		if (!virtqueue_enable_cb(vqueue))
			dev_warn(&vdev->dev,
				 "Suspicious notification in the TX queue");
		vqueue = snd->queues[VIRTIO_SND_VQ_RX].vqueue;
		if (!virtqueue_enable_cb(vqueue))
			dev_warn(&vdev->dev,
				 "Suspicious notification in the RX queue");
	}
}

static void virtsnd_disable_vqs(struct virtio_snd *snd)
{
	int i;
	unsigned long flags;

	for (i = 0; i < VIRTIO_SND_VQ_MAX; ++i) {
		struct virtio_snd_queue *queue = &snd->queues[i];

		spin_lock_irqsave(&queue->lock, flags);
		virtqueue_disable_cb(queue->vqueue);
		queue->vqueue = NULL;
		spin_unlock_irqrestore(&queue->lock, flags);
	}
}

static void virtsnd_flush_vqs(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;

	if (!list_empty(&snd->ctl_msgs)) {
		struct virtio_snd_queue *queue = virtsnd_control_queue(snd);
		unsigned long flags;
		struct virtio_snd_msg *msg;
		struct virtio_snd_msg *next;

		spin_lock_irqsave(&queue->lock, flags);
		list_for_each_entry_safe(msg, next, &snd->ctl_msgs, list) {
			struct virtio_snd_hdr *response =
				sg_virt(&msg->sg_response);

			list_del(&msg->list);

			response->code = cpu_to_virtio32(vdev,
							 VIRTIO_SND_S_IO_ERR);

			complete(&msg->notify);

			virtsnd_ctl_msg_unref(vdev, msg);
		}
		spin_unlock_irqrestore(&queue->lock, flags);
	}

	if (snd->event_msgs)
		devm_kfree(&vdev->dev, snd->event_msgs);

	snd->event_msgs = NULL;
}

static void virtsnd_reset_fn(struct work_struct *work)
{
	struct virtio_snd *snd =
		container_of(work, struct virtio_snd, reset_work);
	struct virtio_device *vdev = snd->vdev;
	struct device *dev = &vdev->dev;
	int rc;

	dev_info(dev, "Sound device needs reset");

	rc = dev->bus->remove(dev);
	if (rc)
		dev_warn(dev, "bus->remove() failed: %d", rc);

	rc = dev->bus->probe(dev);
	if (rc)
		dev_err(dev, "bus->probe() failed: %d", rc);
}

static int virtsnd_card_info(struct virtio_snd *snd)
{
	if (VIRTIO_HAS_OPSY_EXTENSION(snd, DEV_EXT_INFO)) {
		int code;

		code = virtsnd_ctl_alsa_card_info(snd);
		if (!code || code != -EOPNOTSUPP)
			return code;
	}

	strlcpy(snd->card->id, "viosnd", sizeof(snd->card->id));
	strlcpy(snd->card->driver, "virtio_snd", sizeof(snd->card->driver));
	strlcpy(snd->card->shortname, "VIOSND", sizeof(snd->card->shortname));
	strlcpy(snd->card->longname, "VirtIO Sound Card",
		sizeof(snd->card->longname));

	return 0;
}

static int virtsnd_build_devs(struct virtio_snd *snd)
{
	static struct snd_device_ops ops = { 0 };
	struct virtio_device *vdev = snd->vdev;
	int rc;

	/* query supported OPSY extensions */
	if (virtio_has_feature(vdev, VIRTIO_SND_F_OPSY_EXT)) {
		rc = virtsnd_ctl_query_opsy_extensions(snd);
		if (rc)
			return rc;
	}

	rc = snd_card_new(&vdev->dev, SNDRV_DEFAULT_IDX1, SNDRV_DEFAULT_STR1,
			  THIS_MODULE, 0, &snd->card);
	if (rc < 0)
		return rc;

	snd->card->private_data = snd;

	rc = virtsnd_card_info(snd);
	if (rc)
		return rc;

	rc = snd_device_new(snd->card, SNDRV_DEV_LOWLEVEL, snd, &ops);
	if (rc < 0)
		return rc;

	rc = virtsnd_jack_parse_cfg(snd);
	if (rc)
		return rc;

	rc = virtsnd_pcm_parse_cfg(snd);
	if (rc)
		return rc;

	rc = virtsnd_chmap_parse_cfg(snd);
	if (rc)
		return rc;

	if (VIRTIO_HAS_OPSY_EXTENSION(snd, DEV_CTLS)) {
		rc = virtsnd_dc_parse_cfg(snd);
		if (rc)
			return rc;
	}

	if (snd->njacks) {
		rc = virtsnd_jack_build_devs(snd);
		if (rc)
			return rc;
	}

	if (snd->nsubstreams) {
		rc = virtsnd_pcm_build_devs(snd);
		if (rc)
			return rc;
	}

	rc = virtsnd_chmap_build_devs(snd);
	if (rc)
		return rc;

	return snd_card_register(snd->card);
}

static int virtsnd_validate(struct virtio_device *vdev)
{
	if (!vdev->config->get) {
		dev_err(&vdev->dev, "Config access disabled");
		return -EINVAL;
	}

	if (virtsnd_pcm_validate(vdev))
		return -EINVAL;

	return 0;
}

static void virtsnd_remove(struct virtio_device *vdev)
{
	struct virtio_snd *snd = vdev->priv;
	struct virtio_pcm *pcm;
	struct virtio_pcm *pcm_next;

	virtsnd_disable_vqs(snd);

	virtsnd_flush_vqs(snd);

	if (snd->card)
		snd_card_free(snd->card);

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	list_for_each_entry_safe(pcm, pcm_next, &snd->pcm_list, list) {
		unsigned int i;

		list_del(&pcm->list);

		for (i = 0; i < ARRAY_SIZE(pcm->streams); ++i) {
			struct virtio_pcm_stream *stream = &pcm->streams[i];

			if (stream->substreams)
				devm_kfree(&vdev->dev, stream->substreams);
			if (stream->chmaps)
				devm_kfree(&vdev->dev, stream->chmaps);
		}

		devm_kfree(&vdev->dev, pcm);
	}

	if (snd->jacks)
		devm_kfree(&vdev->dev, snd->jacks);

	if (snd->substreams)
		devm_kfree(&vdev->dev, snd->substreams);

	if (snd->chmaps)
		devm_kfree(&vdev->dev, snd->chmaps);

	snd->card = NULL;
	snd->jacks = NULL;
	snd->njacks = 0;
	snd->substreams = NULL;
	snd->nsubstreams = 0;
	snd->chmaps = NULL;
	snd->nchmaps = 0;
}

static int virtsnd_probe(struct virtio_device *vdev)
{
	int rc;
	unsigned int i;
	struct virtio_snd *snd = vdev->priv;

	/*
	 * if we got here because the NEEDS_RESET status was set, we do not need
	 * to create the structure of the device.
	 */
	if (!snd) {
		snd = devm_kzalloc(&vdev->dev, sizeof(*snd), GFP_KERNEL);
		if (!snd)
			return -ENOMEM;

		snd->vdev = vdev;
		INIT_WORK(&snd->reset_work, virtsnd_reset_fn);
		INIT_LIST_HEAD(&snd->ctl_msgs);
		INIT_LIST_HEAD(&snd->pcm_list);

		vdev->priv = snd;

		for (i = 0; i < VIRTIO_SND_VQ_MAX; ++i)
			spin_lock_init(&snd->queues[i].lock);
	}

	rc = virtsnd_find_vqs(snd);
	if (rc)
		goto on_failure;

	virtio_device_ready(vdev);

	rc = virtsnd_build_devs(snd);
	if (rc)
		goto on_failure;

	virtsnd_enable_vqs(snd);

on_failure:
	if (rc)
		virtsnd_remove(vdev);

	return rc;
}

static void virtsnd_config_changed(struct virtio_device *vdev)
{
	struct virtio_snd *snd = vdev->priv;
	unsigned int status = vdev->config->get_status(vdev);

	if (status & VIRTIO_CONFIG_S_NEEDS_RESET)
		schedule_work(&snd->reset_work);
	else
		dev_warn(&vdev->dev, "Sound device configuration was changed");
}

#ifdef CONFIG_PM_SLEEP
static int virtsnd_freeze(struct virtio_device *vdev)
{
	struct virtio_snd *snd = vdev->priv;

	virtsnd_disable_vqs(snd);

	virtsnd_flush_vqs(snd);

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	return 0;
}

static int virtsnd_restore(struct virtio_device *vdev)
{
	struct virtio_snd *snd = vdev->priv;
	int rc;

	rc = virtsnd_find_vqs(snd);
	if (rc)
		return rc;

	virtio_device_ready(vdev);

	/* If the configuration has been changed, reset the device. */
	if (virtsnd_jack_check_cfg(snd))
		goto on_reset;

	if (virtsnd_pcm_check_cfg(snd))
		goto on_reset;

	if (virtsnd_chmap_check_cfg(snd))
		goto on_reset;

	/* If the configuration has not been changed, continue as usual. */
	virtsnd_enable_vqs(snd);

	if (snd->nsubstreams) {
		rc = virtsnd_pcm_restore(snd);
		if (rc)
			return rc;
	}

	return 0;

on_reset:
	dev_warn(&vdev->dev, "configuration has changed -> reset device\n");

	virtsnd_disable_vqs(snd);

	schedule_work(&snd->reset_work);

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SOUND, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_SND_F_OPSY_EXT
};

static struct virtio_driver virtsnd_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.validate = virtsnd_validate,
	.probe = virtsnd_probe,
	.remove = virtsnd_remove,
	.config_changed = virtsnd_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze = virtsnd_freeze,
	.restore = virtsnd_restore,
#endif
};

static int __init init(void)
{
	return register_virtio_driver(&virtsnd_driver);
}
module_init(init);

static void __exit fini(void)
{
	unregister_virtio_driver(&virtsnd_driver);
}
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio sound card driver");
MODULE_LICENSE("GPL");
