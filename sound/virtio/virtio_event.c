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
#include "virtio_card.h"

static void virtsnd_event_dispatch(struct virtio_snd *snd,
				   struct virtio_snd_event *event)
{
	switch (le32_to_cpu(event->hdr.code)) {
	case VIRTIO_SND_EVT_JACK_CONNECTED:
	case VIRTIO_SND_EVT_JACK_DISCONNECTED: {
		virtsnd_jack_event(snd, event);
		break;
	}
	case VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED:
	case VIRTIO_SND_EVT_PCM_XRUN: {
		virtsnd_pcm_event(snd, event);
		break;
	}
	case VIRTIO_SND_EVT_DC_NOTIFY: {
		virtsnd_dc_event(snd, event);
		break;
	}
	default: {
		break;
	}
	}
}

static int virtsnd_event_send(struct virtqueue *vqueue,
			      struct virtio_snd_event *event, bool notify,
			      gfp_t gfp)
{
	int rc;
	struct scatterlist sg;
	struct scatterlist *psgs[1] = { &sg };

	/* reset event content */
	memset(event, 0, sizeof(*event));

	sg_init_one(&sg, event, sizeof(*event));

	rc = virtqueue_add_sgs(vqueue, psgs, 0, 1, event, gfp);
	if (rc)
		return rc;

	if (notify)
		if (virtqueue_kick_prepare(vqueue))
			if (!virtqueue_notify(vqueue))
				return -EIO;

	return 0;
}

int virtsnd_event_populate(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtqueue *vqueue = virtsnd_event_queue(snd)->vqueue;
	unsigned int nevents;
	unsigned int i;

	nevents = virtqueue_get_vring_size(vqueue);

	snd->event_msgs = devm_kcalloc(&vdev->dev, nevents,
				       sizeof(*snd->event_msgs), GFP_KERNEL);
	if (!snd->event_msgs)
		return -ENOMEM;

	for (i = 0; i < nevents; ++i) {
		int rc;

		rc = virtsnd_event_send(vqueue, &snd->event_msgs[i],
					false, GFP_KERNEL);
		if (rc)
			return rc;
	}

	return 0;
}

void virtsnd_event_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;
	struct virtio_snd_queue *queue = virtsnd_event_queue(snd);
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	while (queue->vqueue) {
		virtqueue_disable_cb(queue->vqueue);

		for (;;) {
			struct virtio_snd_event *event;
			u32 length;

			event = virtqueue_get_buf(queue->vqueue, &length);
			if (!event)
				break;

			virtsnd_event_dispatch(snd, event);

			virtsnd_event_send(queue->vqueue, event, true,
					   GFP_ATOMIC);
		}

		if (unlikely(virtqueue_is_broken(queue->vqueue)))
			break;

		if (virtqueue_enable_cb(queue->vqueue))
			break;
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}
