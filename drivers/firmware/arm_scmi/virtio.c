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
#include <linux/virtio.h>
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

union virtio_scmi_union_input {
	__virtio32 hdr;
	struct virtio_scmi_response response;
	struct virtio_scmi_notification notification;
	struct virtio_scmi_delayed_resp delayed_resp;
};

struct scmi_vio_msg {
	struct virtio_scmi_request *request;
	union virtio_scmi_union_input *input;
	bool completed;
};

static int scmi_vio_populate_vq_rx(struct scmi_vio_channel *vioch,
				    struct scmi_xfer *xfer)
{
	struct scatterlist sg_in;
	struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);
	int rc;

	msg->completed = false;

	sg_init_one(&sg_in, msg->input, sizeof(*msg->input) +
		    VIRTIO_SCMI_MAX_MSG_SIZE);

	rc = virtqueue_add_inbuf(vioch->vqueue, &sg_in, 1, xfer, GFP_ATOMIC);
	if (rc)
		dev_err(vioch->cinfo->dev, "%s() rc=%d\n", __func__, rc);
	else
		virtqueue_kick(vioch->vqueue);

	return rc;
}

static void scmi_vio_complete_cb(struct virtqueue *vqueue)
{
	struct scmi_vio_channel *vioch = vqueue->priv;
	unsigned long iflags;
	unsigned int length;

	spin_lock_irqsave(&vioch->lock, iflags);

	do {
		struct scmi_xfer *xfer;

		virtqueue_disable_cb(vqueue);

		while ((xfer = virtqueue_get_buf(vqueue, &length))) {
			struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);
			u32 msg_hdr = virtio32_to_cpu(vqueue->vdev,
						      msg->input->hdr);
			u8 msg_type = MSG_XTRACT_TYPE(msg_hdr);

			if (!vioch->is_rx) { /* TX queue - response */
				msg->completed = true;

				xfer->rx.len = length -
					sizeof(msg->input->response);

				if (xfer->hdr.poll_completion)
					continue;

				scmi_rx_callback(vioch->cinfo, msg_hdr, xfer);
				continue;
			}

			/* RX queue - notification or delayed_resp */
			switch (msg_type) {
			case MSG_TYPE_NOTIFICATION:
				xfer->rx.len = length -
					sizeof(msg->input->notification);
				xfer->rx.buf = msg->input->notification.data;
				break;
			case MSG_TYPE_DELAYED_RESP:
				xfer->rx.len = length -
					sizeof(msg->input->delayed_resp);
				xfer->rx.buf = msg->input->delayed_resp.data;
				break;
			default:
				dev_warn_once(vioch->cinfo->dev,
					      "VQ_RX: unknown msg_type:%d\n",
					      msg_type);
				scmi_vio_populate_vq_rx(vioch, xfer);
				continue;
			}

			scmi_rx_callback(vioch->cinfo, msg_hdr, xfer);
			scmi_vio_populate_vq_rx(vioch, xfer);
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

static const char * const scmi_vio_vqueue_names[] = { "VQ_TX", "VQ_RX" };

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

	return vioch[idx] && vioch[idx]->vqueue;
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

	*max_msg = virtqueue_get_vring_size(vioch[vioch_index]->vqueue);

	/* Pre-allocated messages, no more than what hdr.seq can support */
	if (WARN_ON(*max_msg > MSG_TOKEN_MAX)) {
		dev_warn(dev, "Virtqueue capacity of %d messages exceeds %ld\n",
			*max_msg, MSG_TOKEN_MAX);
		*max_msg = MSG_TOKEN_MAX;
	}
	/*
	 * VirtIO SCMI msg consumes 2 virtual queue descriptors for TX queue,
	 * and 1 descriptor for RX queue
	 */
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
			  struct scmi_xfer *xfer)
{
	struct scatterlist sg_out;
	struct scatterlist sg_in;
	struct scatterlist *sgs[2] = {&sg_out, &sg_in};
	struct scmi_vio_msg *msg = SCMI_MSG_EXTRA(xfer);
	unsigned long iflags;
	int rc;

	msg->completed = false;

	sg_init_one(&sg_out, msg->request,
		    sizeof(*msg->request) + xfer->tx.len);
	sg_init_one(&sg_in, &msg->input->response,
		    sizeof(msg->input->response) + xfer->rx.len);

	spin_lock_irqsave(&vioch->lock, iflags);
	rc = virtqueue_add_sgs(vioch->vqueue, sgs, 1, 1, xfer, GFP_ATOMIC);

	if (rc)
		dev_err(vioch->cinfo->dev, "%s() rc=%d\n", __func__, rc);
	else
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

	msg->request->hdr = cpu_to_virtio32(vdev, hdr);

	return scmi_vio_send(vioch, xfer);
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
					   msg->input->response.status);
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

int virtio_xfer_buffers_init(struct scmi_chan_info *cinfo,
			     struct scmi_xfer *xfer, int max_msg_size)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg;

	msg = devm_kzalloc(cinfo->dev, sizeof(struct scmi_vio_msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	xfer->extra_data = msg;

	if (vioch->is_rx) {
		int rc;
		unsigned long iflags;

		msg->input = devm_kzalloc(cinfo->dev, sizeof(*msg->input) +
					  max_msg_size, GFP_KERNEL);

		if (!msg->input)
			return -ENOMEM;

		/*
		 * xfer->rx.buf and xfer->rx.len will be set to
		 * notification or delayed_resp specific values in receive
		 * callback, according to the type of received message.
		 */

		spin_lock_irqsave(&vioch->lock, iflags);
		rc = scmi_vio_populate_vq_rx(vioch, xfer);
		spin_unlock_irqrestore(&vioch->lock, iflags);
		if (rc)
			return rc;
	} else {
		msg->request = devm_kzalloc(cinfo->dev,
					    sizeof(struct virtio_scmi_request) +
					    max_msg_size, GFP_KERNEL);
		if (!msg->request)
			return -ENOMEM;

		xfer->tx.buf = msg->request->data;

		msg->input = devm_kzalloc(
			cinfo->dev, sizeof(msg->input->response) + max_msg_size,
			GFP_KERNEL);

		if (!msg->input)
			return -ENOMEM;

		xfer->rx.buf = msg->input->response.data;
	}

	return 0;
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
	.xfer_buffers_init = virtio_xfer_buffers_init,
};

const struct scmi_desc scmi_virtio_desc = {
	.ops = &scmi_virtio_ops,
	.max_rx_timeout_ms = 500, /* Can be increased if required */
	.max_msg_size = VIRTIO_SCMI_MAX_MSG_SIZE,
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

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Virtio scmi device driver");
