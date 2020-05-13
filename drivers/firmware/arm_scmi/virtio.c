// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message Virtio Transport
 * driver.
 *
 * Copyright (C) 2020 OpenSynergy.
 */

#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_scmi.h>

#include "common.h"

struct scmi_vio_channel {
	spinlock_t lock;
	struct virtqueue *vqueue;
	struct scmi_chan_info *cinfo;
	bool is_rx;
};

struct scmi_vio_msg {
	uint32_t completed;
	union {
		struct virtio_scmi_request request;
		struct virtio_scmi_response response;
		struct virtio_scmi_notification notification;
		struct virtio_scmi_delayed_resp delayed_resp;
	};
};

static void scmi_vio_populate_vq_rx(struct scmi_vio_channel *vioch,
				    struct scmi_vio_msg *msg)
{
	struct scatterlist sg_in;
	struct scmi_xfer *xfer = msg_to_scmi_xfer(msg);

	msg->completed = false;

	sg_init_one(&sg_in, &msg->notification,
		    sizeof(msg->notification) + xfer->rx.len);

	if (!virtqueue_add_inbuf(vioch->vqueue, &sg_in, 1, msg, GFP_ATOMIC))
		virtqueue_kick(vioch->vqueue);
}

static void scmi_vio_complete_cb(struct virtqueue *vqueue)
{
	struct scmi_vio_channel *vioch = vqueue->priv;
	unsigned long iflags;
	unsigned int length;

	spin_lock_irqsave(&vioch->lock, iflags);

	do {
		struct scmi_vio_msg *msg;

		virtqueue_disable_cb(vqueue);

		while ((msg = virtqueue_get_buf(vqueue, &length))) {
			struct scmi_xfer *xfer = msg_to_scmi_xfer(msg);
			u8 msg_type = MSG_XTRACT_TYPE(msg->response.hdr);
			u32 msg_hdr;

			msg->completed = true;

			if (xfer->hdr.poll_completion)
				continue;

			switch (msg_type) {
			case MSG_TYPE_COMMAND:
				msg_hdr = msg->response.hdr;
				xfer->rx.buf = xfer->extra_data +
					sizeof(uint32_t) +
					sizeof(struct virtio_scmi_response);
				break;
			case MSG_TYPE_NOTIFICATION:
				msg_hdr = msg->notification.hdr;
				xfer->rx.buf = xfer->extra_data +
					sizeof(uint32_t) +
					sizeof(struct virtio_scmi_notification);
				break;
			case MSG_TYPE_DELAYED_RESP:
				msg_hdr = msg->delayed_resp.hdr;
				xfer->rx.buf = xfer->extra_data +
					sizeof(uint32_t) +
					sizeof(struct virtio_scmi_delayed_resp);
				break;
			default:
				WARN_ONCE(1, "received unknown msg_type:%d\n",
					  msg_type);
				continue;
			}

			scmi_rx_callback(vioch->cinfo, msg_hdr, xfer);
			if (vioch->is_rx)
				scmi_vio_populate_vq_rx(vioch, msg);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));

	spin_unlock_irqrestore(&vioch->lock, iflags);
}

static vq_callback_t *scmi_vio_complete_callbacks[] = {
	scmi_vio_complete_cb,
	scmi_vio_complete_cb
};

static const char * const scmi_vio_vqueue_names[] = { "vscmi-tx", "vscmi-rx" };

static bool virtio_chan_available(struct device *dev, int idx)
{
	struct platform_device *pdev;
	struct virtio_device *vdev;
	struct device_node *vioch_node;
	struct scmi_vio_channel **vioch;

	vioch_node = of_parse_phandle(dev->of_node, "virtio_transport", 0);
	if (!vioch_node)
		return false;

	pdev = of_find_device_by_node(vioch_node);
	of_node_put(vioch_node);
	if (!pdev)
		return false;

	vdev = (struct virtio_device *)pdev->dev.driver_data;
	if (!vdev)
		return false;

	vioch = vdev->priv;
	if (!vioch)
		return false;

	return !!(vioch[idx] && vioch[idx]->vqueue);
}

static int virtio_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			     bool tx, int *max_msg)
{
	struct platform_device *pdev;
	struct virtio_device *vdev;
	struct device_node *vioch_node;
	struct scmi_vio_channel **vioch;
	int vioch_index = tx ? VQ_TX : VQ_RX;

	vioch_node = of_parse_phandle(cinfo->dev->of_node,
				      "virtio_transport", 0);

	pdev = of_find_device_by_node(vioch_node);
	of_node_put(vioch_node);
	if (!pdev) {
		dev_err(dev, "Wrong virtio scmi channel dts configuration\n");
		return -1;
	}

	vdev = (struct virtio_device *)pdev->dev.driver_data;
	if (!vdev)
		return -1;

	vioch = (struct scmi_vio_channel **)vdev->priv;
	if (!vioch) {
		dev_err(dev, "Virtio scmi driver not probed successfully.\n");
		return -1;
	}
	cinfo->transport_info = vioch[vioch_index];
	vioch[vioch_index]->cinfo = cinfo;

	/*
	 * VirtIO SCMI msg consumes 2 virtual queue descriptors for TX queue,
	 * and 1 descriptor for RX queue.
	 */
	*max_msg = virtqueue_get_vring_size(vioch[vioch_index]->vqueue);
	if (tx)
		*max_msg /= 2;

	return 0;
}

static int virtio_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct scmi_vio_channel *vioch = cinfo->transport_info;

	if (vioch) {
		cinfo->transport_info = NULL;
		kfree(vioch);
	}

	scmi_free_channel(cinfo, data, id);
	return 0;
}

static int scmi_vio_send(struct scmi_vio_channel *vioch,
			 struct scmi_vio_msg *msg)
{
	struct scatterlist sg_out;
	struct scatterlist sg_in;
	struct scatterlist *sgs[2] = {&sg_out, &sg_in};
	struct scmi_xfer *xfer = msg_to_scmi_xfer(msg);
	unsigned long iflags;
	int rc;

	msg->completed = false;

	sg_init_one(&sg_out, &msg->request,
		    sizeof(msg->request) + xfer->tx.len);
	sg_init_one(&sg_in, &msg->response,
		    sizeof(msg->response) + xfer->rx.len);

	spin_lock_irqsave(&vioch->lock, iflags);
	rc =  virtqueue_add_sgs(vioch->vqueue, sgs, 1, 1, msg, GFP_ATOMIC);
	virtqueue_kick(vioch->vqueue);
	spin_unlock_irqrestore(&vioch->lock, iflags);

	return rc;
}

static int virtio_send_message(struct scmi_chan_info *cinfo,
			       struct scmi_xfer *xfer)
{
	uint32_t hdr;
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct virtio_device *vdev = vioch->vqueue->vdev;
	struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);

	hdr = pack_scmi_header(&xfer->hdr);

	if (xfer->tx.buf)
		msg->request.hdr = cpu_to_virtio32(vdev, hdr);

	return scmi_vio_send(vioch, msg);
}

static void dummy_fetch_notification(struct scmi_chan_info *cinfo,
				     size_t max_len, struct scmi_xfer *xfer)
{
	(void)cinfo;
	(void)max_len;
	(void)xfer;
}

static void dummy_clear_notification(struct scmi_chan_info *cinfo)
{
	(void)cinfo;
}

static void virtio_fetch_response(struct scmi_chan_info *cinfo,
				   struct scmi_xfer *xfer)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);

	xfer->hdr.status = virtio32_to_cpu(vioch->vqueue->vdev,
					   msg->response.status);
}

static bool
virtio_poll_done(struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);
	unsigned long iflags;
	bool completed;

	spin_lock_irqsave(&vioch->lock, iflags);
	completed = msg->completed;
	spin_unlock_irqrestore(&vioch->lock, iflags);

	return completed;
}

static void
virtio_populate_rx(struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	unsigned long iflags;
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);

	xfer->rx.len = VIRTIO_SCMI_MAX_MSG_SIZE;

	spin_lock_irqsave(&vioch->lock, iflags);
	scmi_vio_populate_vq_rx(vioch, msg);
	spin_unlock_irqrestore(&vioch->lock, iflags);
}

static struct scmi_transport_ops scmi_virtio_ops = {
	.chan_available = virtio_chan_available,
	.chan_setup = virtio_chan_setup,
	.chan_free = virtio_chan_free,
	.send_message = virtio_send_message,
	.fetch_response = virtio_fetch_response,
	.fetch_notification = dummy_fetch_notification,
	.clear_channel = dummy_clear_notification,
	.poll_done = virtio_poll_done,
	.put_rx_xfer = virtio_populate_rx,
};

const struct scmi_desc scmi_virtio_desc = {
	.ops = &scmi_virtio_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg_size = VIRTIO_SCMI_MAX_MSG_SIZE,
	.msg_extra_size = sizeof(struct scmi_vio_msg),
	.msg_tx_offset = sizeof(uint32_t) + sizeof(struct virtio_scmi_request),
};

static int scmi_vio_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct scmi_vio_channel **vioch;

	vioch = devm_kcalloc(dev, VQ_MAX_CNT, sizeof(*vioch), GFP_KERNEL);
	if (!vioch)
		return -ENOMEM;

	vioch[VQ_TX] = devm_kzalloc(dev, sizeof(struct scmi_vio_channel),
				    GFP_KERNEL);
	if (!vioch[VQ_TX])
		return -ENOMEM;

	if (virtio_has_feature(vdev, VIRTIO_SCMI_F_P2A_CHANNELS)) {
		int i;
		struct virtqueue *vqs[2];

		vioch[VQ_RX] = devm_kzalloc(dev,
					    sizeof(struct scmi_vio_channel),
					    GFP_KERNEL);
		if (!vioch[VQ_RX])
			return -ENOMEM;
		vioch[VQ_RX]->is_rx = true;

		if (virtio_find_vqs(vdev, 2, vqs,
				    scmi_vio_complete_callbacks,
				    scmi_vio_vqueue_names, NULL)) {
			dev_err(dev, "Failed to get vqs (VQ_TX, VQ_RX).\n");
			return -1;
		}

		for (i = VQ_TX; i < VQ_MAX_CNT; i++) {
			spin_lock_init(&vioch[i]->lock);
			vioch[i]->vqueue = vqs[i];
			vioch[i]->vqueue->priv = vioch[i];
		}
		dev_info(dev, "VQ_TX and VQ_RX are both found.\n");
	} else {
		if (virtio_find_vqs(vdev, 1, &vioch[VQ_TX]->vqueue,
				    scmi_vio_complete_callbacks,
				    scmi_vio_vqueue_names, NULL)) {
			dev_err(dev, "Failed to get VQ_TX.\n");
			return -1;
		}

		vioch[VQ_TX]->vqueue->priv = vioch[VQ_TX];
		spin_lock_init(&vioch[VQ_TX]->lock);
		dev_info(dev, "VQ_RX is not supported.\n");
	}

	vdev->priv = vioch;

	virtio_device_ready(vdev);

	return 0;
}

static unsigned int features[] = {
	VIRTIO_SCMI_F_P2A_CHANNELS,
};

static const struct virtio_device_id id_table[] = {
	{VIRTIO_ID_SCMI, VIRTIO_DEV_ANY_ID},
	{0}
};

static struct virtio_driver virtio_scmi_driver = {
	.driver.name = "scmi-virtio",
	.driver.owner = THIS_MODULE,
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.id_table = id_table,
	.probe = scmi_vio_probe,
};

static int __init virtio_scmi_init(void)
{
	return register_virtio_driver(&virtio_scmi_driver);
}

subsys_initcall(virtio_scmi_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtio scmi device driver");
