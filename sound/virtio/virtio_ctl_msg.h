/* SPDX-License-Identifier: GPL-2.0+ */
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
#ifndef VIRTIO_SND_MSG_H
#define VIRTIO_SND_MSG_H

#include <linux/atomic.h>
#include <linux/virtio.h>

struct virtio_snd;

/**
 * struct virtio_snd_msg - Device message common representation.
 * @sg_request: Scattergather element containing a device request (header).
 * @sg_request_ext: Scattergather element containing optinal request payload.
 * @sg_response: Scattergather element containing a device response (status).
 * @sg_response_ext: Scattergather element containing optinal response payload.
 * @notify: Request completed notification.
 * @ref_count: Reference count used to manage a message lifetime.
 */
struct virtio_snd_msg {
/* public: */
	struct scatterlist sg_request;
	struct scatterlist *sg_request_ext;
	struct scatterlist sg_response;
	struct scatterlist *sg_response_ext;
/* private: internal use only */
	struct list_head list;
	struct completion notify;
	atomic_t ref_count;
};

static inline void virtsnd_ctl_msg_ref(struct virtio_device *vdev,
				       struct virtio_snd_msg *msg)
{
	atomic_inc(&msg->ref_count);
}

static inline void virtsnd_ctl_msg_unref(struct virtio_device *vdev,
					 struct virtio_snd_msg *msg)
{
	if (!atomic_dec_return(&msg->ref_count))
		devm_kfree(&vdev->dev, msg);
}

struct virtio_snd_msg *virtsnd_ctl_msg_alloc(struct virtio_device *vdev,
					     size_t request_size,
					     size_t response_size, gfp_t gfp);

int virtsnd_ctl_msg_send(struct virtio_snd *snd, struct virtio_snd_msg *msg);

int virtsnd_ctl_msg_send_sync(struct virtio_snd *snd,
			      struct virtio_snd_msg *msg);

int virtsnd_ctl_query_info(struct virtio_snd *snd, int command, int start_id,
			   int count, size_t size, void *info);

void virtsnd_ctl_notify_cb(struct virtqueue *vqueue);

#endif /* VIRTIO_SND_MSG_H */
