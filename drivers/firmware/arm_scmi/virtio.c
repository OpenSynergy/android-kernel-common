// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio Transport driver for Arm System Control and Management Interface
 * (SCMI).
 *
 * Copyright (C) 2020 OpenSynergy.
 */

/**
 * DOC: Theory of Operation
 *
 * The scmi-virtio transport implements a driver for the virtio SCMI device
 * proposed in virtio spec patch v5[1].
 *
 * There is one tx channel (virtio cmdq, A2P channel) and at most one rx
 * channel (virtio eventq, P2A channel). Each channel is implemented through a
 * virtqueue. Access to each virtqueue is protected by a spinlock.
 *
 * This SCMI transport uses the scmi_xfer tx/rx buffers for data exchange with
 * the virtio device to avoid maintenance of additional buffers.
 *
 * [1] https://lists.oasis-open.org/archives/virtio-comment/202005/msg00096.html
 */

#include <linux/errno.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_scmi.h>

#include "common.h"

#define VIRTIO_SCMI_MAX_MSG_SIZE 128 /* Value may be increased. */
#define DESCR_PER_TX_MSG 2

struct scmi_vio_channel {
	spinlock_t lock;
	struct virtqueue *vqueue;
	struct scmi_chan_info *cinfo;
	u8 is_rx;
};

union virtio_scmi_input {
	__virtio32 hdr;
	struct virtio_scmi_response response;
	struct virtio_scmi_notification notification;
};

struct scmi_vio_msg {
	struct virtio_scmi_request *request;
	union virtio_scmi_input *input;
	u8 completed;
};

static int scmi_vio_populate_vq_rx(struct scmi_vio_channel *vioch,
				   struct scmi_xfer *xfer)
{
	struct scatterlist sg_in;
	struct scmi_vio_msg *msg = xfer->extra_data;
	int rc;

	msg->completed = false;

	sg_init_one(&sg_in, msg->input,
		    sizeof(*msg->input) + VIRTIO_SCMI_MAX_MSG_SIZE);

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
			struct scmi_vio_msg *msg = xfer->extra_data;
			u32 msg_hdr =
				virtio32_to_cpu(vqueue->vdev, msg->input->hdr);
			u8 msg_type = MSG_XTRACT_TYPE(msg_hdr);

			if (!vioch->is_rx) { /* tx queue response */
				msg->completed = true;
				xfer->rx.len =
					length - sizeof(msg->input->response);
				if (!xfer->hdr.poll_completion)
					scmi_rx_callback(vioch->cinfo, msg_hdr, xfer);
				continue;
			}

			/* rx queue - notification or delayed response */
			switch (msg_type) {
			case MSG_TYPE_NOTIFICATION:
				xfer->rx.len = length -
					       sizeof(msg->input->notification);
				xfer->rx.buf = msg->input->notification.data;
				break;
			case MSG_TYPE_DELAYED_RESP:
				xfer->rx.len =
					length - sizeof(msg->input->response);
				xfer->rx.buf = msg->input->response.data;
				break;
			default:
				dev_warn_once(vioch->cinfo->dev,
					      "rx: unknown message_type %d\n",
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

static const char *const scmi_vio_vqueue_names[] = { "tx", "rx" };

static vq_callback_t *scmi_vio_complete_callbacks[] = {
	scmi_vio_complete_cb,
	scmi_vio_complete_cb
};

static int scmi_vio_match_any_dev(struct device *dev, const void *data)
{
	(void)dev;
	(void)data;

	return 1;
}

static struct virtio_driver virtio_scmi_driver; /* Forward declaration */

static int virtio_link_supplier(struct device *dev)
{
	struct device *vdev = driver_find_device(
		&virtio_scmi_driver.driver, NULL, NULL, scmi_vio_match_any_dev);

	if (!vdev) {
		dev_notice_once(
			dev,
			"Deferring probe after not finding a bound scmi-virtio device\n");
		return -EPROBE_DEFER;
	}

	/*
	 * Add plain device link for completeness. It might have no effect
	 * beyond sysfs.
	 */
	if (!device_link_add(dev, vdev, DL_FLAG_AUTOREMOVE_CONSUMER)) {
		put_device(vdev);
		dev_err(dev, "Adding link to supplier virtio device failed\n");
		return -ECANCELED;
	}

	put_device(vdev);
	return scmi_set_transport_info(dev, dev_to_virtio(vdev));
}

static bool virtio_chan_available(struct device *dev, int idx)
{
	struct virtio_device *vdev;
	struct scmi_vio_channel **vioch;

	/* scmi-virtio doesn't support per-protocol channels */
	if (is_scmi_protocol_device(dev))
		return false;

	vdev = scmi_get_transport_info(dev);
	if (!vdev)
		return false;

	vioch = vdev->priv;
	if (!vioch)
		return false;

	return vioch[idx] && vioch[idx]->vqueue;
}

static int virtio_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			     bool tx)
{
	struct virtio_device *vdev;
	struct scmi_vio_channel **vioch;
	int vioch_index = tx ? VIRTIO_SCMI_VQ_TX : VIRTIO_SCMI_VQ_RX;

	/* scmi-virtio doesn't support per-protocol channels */
	if (is_scmi_protocol_device(dev))
		return -1;

	vdev = scmi_get_transport_info(dev);
	if (!vdev)
		return -1;

	vioch = vdev->priv;
	if (!vioch) {
		dev_err(dev, "Data from scmi-virtio probe not found\n");
		return -1;
	}
	cinfo->transport_info = vioch[vioch_index];
	vioch[vioch_index]->cinfo = cinfo;

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

static int virtio_get_max_msg(bool tx, struct scmi_chan_info *base_cinfo,
			      int *max_msg)
{
	struct scmi_vio_channel *vioch = base_cinfo->transport_info;

	*max_msg = virtqueue_get_vring_size(vioch->vqueue);

	/* Tx messages need multiple descriptors. */
	if (tx)
		*max_msg /= DESCR_PER_TX_MSG;

	if (*max_msg > MSG_TOKEN_MAX) {
		dev_notice(
			base_cinfo->dev,
			"Only %ld messages can be pending simultaneously, while the virtqueue could hold %d\n",
			MSG_TOKEN_MAX, *max_msg);
		*max_msg = MSG_TOKEN_MAX;
	}

	return 0;
}

static int virtio_xfer_init_buffers(struct scmi_chan_info *cinfo,
				    struct scmi_xfer *xfer, int max_msg_size)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg;

	msg = devm_kzalloc(cinfo->dev, sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	xfer->extra_data = msg;

	if (vioch->is_rx) {
		int rc;
		unsigned long iflags;

		msg->input = devm_kzalloc(cinfo->dev,
					  sizeof(*msg->input) + max_msg_size,
					  GFP_KERNEL);
		if (!msg->input)
			return -ENOMEM;

		/*
		 * xfer->rx.buf will be set to notification or delayed response
		 * specific values in the receive callback, according to the
		 * type of the received message.
		 */

		spin_lock_irqsave(&vioch->lock, iflags);
		rc = scmi_vio_populate_vq_rx(vioch, xfer);
		spin_unlock_irqrestore(&vioch->lock, iflags);
		if (rc)
			return rc;
	} else {
		msg->request =
			devm_kzalloc(cinfo->dev,
				     sizeof(*msg->request) + max_msg_size,
				     GFP_KERNEL);
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

static int scmi_vio_send(struct scmi_vio_channel *vioch, struct scmi_xfer *xfer)
{
	struct scatterlist sg_out;
	struct scatterlist sg_in;
	struct scatterlist *sgs[DESCR_PER_TX_MSG] = { &sg_out, &sg_in };
	struct scmi_vio_msg *msg = xfer->extra_data;
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
	struct scmi_vio_msg *msg = xfer->extra_data;

	hdr = pack_scmi_header(&xfer->hdr);

	msg->request->hdr = cpu_to_virtio32(vdev, hdr);

	return scmi_vio_send(vioch, xfer);
}

static void virtio_fetch_response(struct scmi_chan_info *cinfo,
				  struct scmi_xfer *xfer)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg = xfer->extra_data;

	xfer->hdr.status = virtio32_to_cpu(vioch->vqueue->vdev,
					   msg->input->response.status);
}

static void dummy_fetch_notification(struct scmi_chan_info *cinfo,
				     size_t max_len, struct scmi_xfer *xfer)
{
	(void)cinfo;
	(void)max_len;
	(void)xfer;
}

static void dummy_clear_channel(struct scmi_chan_info *cinfo)
{
	(void)cinfo;
}

static bool virtio_poll_done(struct scmi_chan_info *cinfo,
			     struct scmi_xfer *xfer)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg = xfer->extra_data;
	unsigned long iflags;
	bool completed;

	spin_lock_irqsave(&vioch->lock, iflags);
	completed = msg->completed;
	spin_unlock_irqrestore(&vioch->lock, iflags);

	return completed;
}

static const struct scmi_transport_ops scmi_virtio_ops = {
	.link_supplier = virtio_link_supplier,
	.chan_available = virtio_chan_available,
	.chan_setup = virtio_chan_setup,
	.chan_free = virtio_chan_free,
	.get_max_msg = virtio_get_max_msg,
	.send_message = virtio_send_message,
	.fetch_response = virtio_fetch_response,
	.fetch_notification = dummy_fetch_notification,
	.clear_channel = dummy_clear_channel,
	.poll_done = virtio_poll_done,
	.xfer_init_buffers = virtio_xfer_init_buffers,
};

const struct scmi_desc scmi_virtio_desc = {
	.ops = &scmi_virtio_ops,
	.max_rx_timeout_ms = 60000, /* for non-realtime virtio devices */
	.max_msg = 0, /* overridden by virtio_get_max_msg() */
	.max_msg_size = VIRTIO_SCMI_MAX_MSG_SIZE,
};

static int scmi_vio_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct scmi_vio_channel **vioch;
	bool have_vq_rx;
	int vq_cnt;
	int i;
	struct virtqueue *vqs[VIRTIO_SCMI_VQ_MAX_CNT];

	vioch = devm_kcalloc(dev, VIRTIO_SCMI_VQ_MAX_CNT, sizeof(*vioch),
			     GFP_KERNEL);
	if (!vioch)
		return -ENOMEM;

	have_vq_rx = virtio_has_feature(vdev, VIRTIO_SCMI_F_P2A_CHANNELS);
	vq_cnt = have_vq_rx ? VIRTIO_SCMI_VQ_MAX_CNT : 1;

	for (i = 0; i < vq_cnt; i++) {
		vioch[i] = devm_kzalloc(dev, sizeof(**vioch), GFP_KERNEL);
		if (!vioch[i])
			return -ENOMEM;
	}

	if (have_vq_rx)
		vioch[VIRTIO_SCMI_VQ_RX]->is_rx = true;

	if (virtio_find_vqs(vdev, vq_cnt, vqs, scmi_vio_complete_callbacks,
			    scmi_vio_vqueue_names, NULL)) {
		dev_err(dev, "Failed to get %d virtqueue(s)\n", vq_cnt);
		return -1;
	}
	dev_info(dev, "Found %d virtqueue(s)\n", vq_cnt);

	for (i = 0; i < vq_cnt; i++) {
		spin_lock_init(&vioch[i]->lock);
		vioch[i]->vqueue = vqs[i];
		vioch[i]->vqueue->priv = vioch[i];
	}

	vdev->priv = vioch;

	virtio_device_ready(vdev);

	return 0;
}

static unsigned int features[] = {
	VIRTIO_SCMI_F_P2A_CHANNELS,
};

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SCMI, VIRTIO_DEV_ANY_ID },
	{ 0 }
};

static struct virtio_driver virtio_scmi_driver = {
	.driver.name = "scmi-virtio",
	.driver.owner = THIS_MODULE,
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.id_table = id_table,
	.probe = scmi_vio_probe,
};

int __init virtio_scmi_init(void)
{
	return register_virtio_driver(&virtio_scmi_driver);
}

void __exit virtio_scmi_exit(void)
{
	unregister_virtio_driver(&virtio_scmi_driver);
}
