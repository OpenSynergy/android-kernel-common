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
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_scmi.h>

#include "common.h"

struct scmi_vio_channel {
	int id;
	spinlock_t lock;
	struct virtqueue *vqueue;
	struct scmi_chan_info *cinfo;
};

struct scmi_vio_msg {
	uint32_t completed;
	union {
		struct virtio_scmi_request request;
		struct virtio_scmi_response response;
	};
};

static void scmi_vio_complete_cb(struct virtqueue *vqueue)
{
	struct scmi_vio_channel *vioch = vqueue->vdev->priv;
	unsigned long iflags;
	unsigned int length;

	spin_lock_irqsave(&vioch->lock, iflags);

	do {
		struct scmi_vio_msg *msg;

		virtqueue_disable_cb(vqueue);

		while ((msg = virtqueue_get_buf(vqueue, &length))) {
			struct scmi_xfer *xfer = msg_to_scmi_xfer(msg);
			u8 msg_type = MSG_XTRACT_TYPE(msg->response.hdr);

			msg->completed = true;

			if (xfer->hdr.poll_completion)
				continue;

			switch (msg_type) {
			case MSG_TYPE_COMMAND:
				xfer->rx.buf = xfer->extra_data +
					sizeof(uint32_t) +
					sizeof(struct virtio_scmi_response);
				break;
			default:
				WARN_ONCE(1, "received unknown msg_type:%d\n",
					  msg_type);
				continue;
			}

			scmi_rx_callback(vioch->cinfo, msg->response.hdr, xfer);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));

	spin_unlock_irqrestore(&vioch->lock, iflags);
}

static bool virtio_chan_available(struct device *dev, int idx)
{
	struct device_node *vioch_node;

	if (idx) /* RX queue is not supported yet */
		return false;

	vioch_node = of_parse_phandle(dev->of_node, "virtio_transport", 0);
	if (!vioch_node)
		return false;

	of_node_put(vioch_node);

	return true;
}

static int virtio_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			      bool tx)
{
	struct platform_device *pdev;
	struct virtio_device *vdev;
	struct scmi_vio_channel *vioch;
	struct device_node *vioch_node;
	int idx = tx ? 0 : 1;

	vioch = devm_kzalloc(dev, sizeof(*vioch), GFP_KERNEL);
	if (!vioch)
		return -ENOMEM;

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

	vioch->id = idx;
	vioch->cinfo = cinfo;
	spin_lock_init(&vioch->lock);
	vioch->vqueue =
		virtio_find_single_vq(vdev, scmi_vio_complete_cb, "vscmi");

	if (!vioch->vqueue) {
		dev_err(dev, "Failed to get vqueue for virtio device\n");
		return -1;
	}

	vdev->priv = vioch;

	cinfo->transport_info = vioch;

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

static void scmi_vio_send(struct scmi_vio_channel *vioch,
			  struct scmi_vio_msg *msg)
{
	struct scatterlist sg_out;
	struct scatterlist sg_in;
	struct scatterlist *sgs[2] = {&sg_out, &sg_in};
	struct scmi_xfer *xfer = msg_to_scmi_xfer(msg);
	unsigned long iflags;
	bool notify = false;

	msg->completed = false;

	sg_init_one(&sg_out, &msg->request,
		    sizeof(msg->request) + xfer->tx.len);
	sg_init_one(&sg_in, &msg->response,
		    sizeof(msg->response) + xfer->rx.len);

	spin_lock_irqsave(&vioch->lock, iflags);
	if (!virtqueue_add_sgs(vioch->vqueue, sgs, 1, 1, msg, GFP_ATOMIC))
		notify = virtqueue_kick_prepare(vioch->vqueue);
	spin_unlock_irqrestore(&vioch->lock, iflags);

	if (notify)
		virtqueue_notify(vioch->vqueue);
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

	scmi_vio_send(vioch, msg);

	return 0;
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

static struct scmi_transport_ops scmi_virtio_ops = {
	.chan_available = virtio_chan_available,
	.chan_setup = virtio_chan_setup,
	.chan_free = virtio_chan_free,
	.send_message = virtio_send_message,
	.fetch_response = virtio_fetch_response,
	.poll_done = virtio_poll_done,
};

const struct scmi_desc scmi_virtio_desc = {
	.ops = &scmi_virtio_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 8,  /* VirtIO SCMI msg consumes 2 virtual queue descriptors,
			* So, maximum # of SCMI messages is 1/2 of the vqueue
			* throughput capability.
			* Our SCMI virtio-device has ring size = 16
			*/
	.max_msg_size = 128,
	.msg_extra_size = sizeof(struct scmi_vio_msg),
	.msg_tx_offset = sizeof(uint32_t) + sizeof(struct virtio_scmi_request),
};
