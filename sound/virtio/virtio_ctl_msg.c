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
#include <linux/moduleparam.h>
#include <linux/virtio_config.h>

#include "virtio_card.h"
#include "virtio_ctl_msg.h"

static int msg_timeout_ms = 1000;
module_param(msg_timeout_ms, int, 0644);
MODULE_PARM_DESC(msg_timeout_ms, "Message completion timeout in milliseconds");

struct virtio_snd_msg *virtsnd_ctl_msg_alloc(struct virtio_device *vdev,
					     size_t request_size,
					     size_t response_size, gfp_t gfp)
{
	struct virtio_snd_msg *msg;

	msg = devm_kzalloc(&vdev->dev,
			   sizeof(*msg) + request_size + response_size,
			   gfp);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	sg_init_one(&msg->sg_request, (u8 *)msg + sizeof(*msg), request_size);
	sg_init_one(&msg->sg_response, (u8 *)msg + sizeof(*msg) + request_size,
		    response_size);

	init_completion(&msg->notify);
	atomic_set(&msg->ref_count, 1);

	return msg;
}

int virtsnd_ctl_msg_send(struct virtio_snd *snd, struct virtio_snd_msg *msg)
{
	int rc;
	struct virtio_snd_queue *queue = virtsnd_control_queue(snd);
	struct scatterlist *psgs[4];
	unsigned int out_nsgs = 1;
	unsigned int in_nsgs = 1;
	unsigned int nsgs = 0;
	bool notify = false;
	unsigned long flags;

	psgs[nsgs++] = &msg->sg_request;
	if (msg->sg_request_ext) {
		psgs[nsgs++] = msg->sg_request_ext;
		out_nsgs++;
	}
	psgs[nsgs++] = &msg->sg_response;
	if (msg->sg_response_ext) {
		psgs[nsgs++] = msg->sg_response_ext;
		in_nsgs++;
	}

	spin_lock_irqsave(&queue->lock, flags);
	if (queue->vqueue)
		rc = virtqueue_add_sgs(queue->vqueue, psgs, out_nsgs, in_nsgs,
				       msg, GFP_ATOMIC);
	else
		rc = -EIO;
	if (!rc) {
		notify = virtqueue_kick_prepare(queue->vqueue);
		list_add_tail(&msg->list, &snd->ctl_msgs);
	}
	spin_unlock_irqrestore(&queue->lock, flags);

	if (rc)
		goto on_failure;

	if (notify)
		if (!virtqueue_notify(queue->vqueue))
			goto on_failure;

	return 0;

on_failure:
	virtsnd_ctl_msg_unref(snd->vdev, msg);

	return -EIO;
}

int virtsnd_ctl_msg_send_sync(struct virtio_snd *snd,
			      struct virtio_snd_msg *msg)
{
	int code;
	struct virtio_device *vdev = snd->vdev;
	unsigned int js = msecs_to_jiffies(msg_timeout_ms);
	struct virtio_snd_hdr *response;

	virtsnd_ctl_msg_ref(vdev, msg);

	code = virtsnd_ctl_msg_send(snd, msg);
	if (code)
		goto on_failure;

	code = wait_for_completion_interruptible_timeout(&msg->notify, js);
	if (code <= 0) {
		if (!code) {
			dev_err(&vdev->dev, "control message timeout");
			code = -EIO;
		}

		goto on_failure;
	}

	response = sg_virt(&msg->sg_response);

	switch (le32_to_cpu(response->code)) {
	case VIRTIO_SND_S_OK:
		code = 0;
		break;
	case VIRTIO_SND_S_BAD_MSG:
		code = -EINVAL;
		break;
	case VIRTIO_SND_S_NOT_SUPP:
		code = -EOPNOTSUPP;
		break;
	case VIRTIO_SND_S_IO_ERR:
		code = -EIO;
		break;
	default:
		code = -EPERM;
		break;
	}

on_failure:
	virtsnd_ctl_msg_unref(vdev, msg);

	return code;
}

int virtsnd_ctl_query_info(struct virtio_snd *snd, int command, int start_id,
			   int count, size_t size, void *info)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_msg *msg;
	struct virtio_snd_query_info *query;
	struct scatterlist sg_response_ext;

	msg = virtsnd_ctl_msg_alloc(vdev, sizeof(*query),
				    sizeof(struct virtio_snd_hdr), GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	query = sg_virt(&msg->sg_request);
	query->hdr.code = cpu_to_virtio32(vdev, command);
	query->start_id = cpu_to_virtio32(vdev, start_id);
	query->count = cpu_to_virtio32(vdev, count);
	query->size = cpu_to_virtio32(vdev, size);

	sg_init_one(&sg_response_ext, info, count * size);
	msg->sg_response_ext = &sg_response_ext;

	return virtsnd_ctl_msg_send_sync(snd, msg);
}

void virtsnd_ctl_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;
	struct virtio_snd_queue *queue = virtsnd_control_queue(snd);
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	while (queue->vqueue) {
		virtqueue_disable_cb(queue->vqueue);

		for (;;) {
			struct virtio_snd_msg *msg;
			u32 length;

			msg = virtqueue_get_buf(queue->vqueue, &length);
			if (!msg)
				break;

			list_del(&msg->list);
			complete(&msg->notify);

			virtsnd_ctl_msg_unref(snd->vdev, msg);
		}

		if (unlikely(virtqueue_is_broken(queue->vqueue)))
			break;

		if (virtqueue_enable_cb(queue->vqueue))
			break;
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}
