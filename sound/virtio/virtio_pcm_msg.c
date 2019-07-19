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
#include <sound/pcm_params.h>

#include "virtio_card.h"

/**
 * enum pcm_msg_sg_index - Scatter-gather element indexes for an I/O message
 * @PCM_MSG_SG_XFER: Element containing a virtio_snd_pcm_xfer structure
 * @PCM_MSG_SG_DATA: Element containing a data buffer
 * @PCM_MSG_SG_STATUS: Element containing a virtio_snd_pcm_status structure
 * @PCM_MSG_SG_MAX: The maximum number of elements in the scatter-gather table
 *
 * These values are used as the index of the scatter-gather table.
 */
enum pcm_msg_sg_index {
	PCM_MSG_SG_XFER = 0,
	PCM_MSG_SG_DATA,
	PCM_MSG_SG_STATUS,
	PCM_MSG_SG_MAX
};

/**
 * struct virtio_pcm_msg - I/O message representation
 * @list: Pending I/O message list entry
 * @stream: Pointer to virtio PCM stream structure
 * @xfer: I/O message header payload
 * @status: I/O message status payload
 * @one_shot_data: if the message should not be resent to the device, the field
 *                 contains a pointer to the optional payload that should be
 *                 released after completion
 * @sgs: I/O message payload scatter-gather table
 */
struct virtio_pcm_msg {
	struct virtio_pcm_substream *substream;
	struct virtio_snd_pcm_xfer xfer;
	struct virtio_snd_pcm_status status;
	struct scatterlist sgs[PCM_MSG_SG_MAX];
};

int virtsnd_pcm_msg_alloc(struct virtio_pcm_substream *substream,
			  unsigned int nmsg, u8 *dma_area,
			  unsigned int period_bytes)
{
	struct virtio_device *vdev = substream->snd->vdev;
	unsigned int i;

	if (substream->msgs)
		devm_kfree(&vdev->dev, substream->msgs);

	substream->msgs = devm_kcalloc(&vdev->dev, nmsg,
				       sizeof(*substream->msgs), GFP_KERNEL);
	if (!substream->msgs)
		return -ENOMEM;

	for (i = 0; i < nmsg; ++i) {
		struct virtio_pcm_msg *msg = &substream->msgs[i];

		msg->substream = substream;

		sg_init_table(msg->sgs, PCM_MSG_SG_MAX);
		sg_init_one(&msg->sgs[PCM_MSG_SG_XFER], &msg->xfer,
			    sizeof(msg->xfer));
		sg_init_one(&msg->sgs[PCM_MSG_SG_DATA],
			    dma_area + period_bytes * i, period_bytes);
		sg_init_one(&msg->sgs[PCM_MSG_SG_STATUS], &msg->status,
			    sizeof(msg->status));
	}

	return 0;
}

int virtsnd_pcm_msg_send(struct virtio_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->substream->runtime;
	struct virtio_snd *snd = substream->snd;
	struct virtio_device *vdev = snd->vdev;
	struct virtqueue *vqueue = virtsnd_pcm_queue(substream)->vqueue;
	int i;
	int n;
	bool notify = false;

	if (!vqueue)
		return -EIO;

	i = (substream->msg_last_enqueued + 1) % runtime->periods;
	n = runtime->periods - atomic_read(&substream->msg_count);

	for (; n; --n, i = (i + 1) % runtime->periods) {
		struct virtio_pcm_msg *msg = &substream->msgs[i];
		struct scatterlist *psgs[PCM_MSG_SG_MAX] = {
			[PCM_MSG_SG_XFER] = &msg->sgs[PCM_MSG_SG_XFER],
			[PCM_MSG_SG_DATA] = &msg->sgs[PCM_MSG_SG_DATA],
			[PCM_MSG_SG_STATUS] = &msg->sgs[PCM_MSG_SG_STATUS]
		};
		int rc;

		msg->xfer.stream_id = cpu_to_virtio32(vdev, substream->sid);
		memset(&msg->status, 0, sizeof(msg->status));

		atomic_inc(&substream->msg_count);

		if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK)
			rc = virtqueue_add_sgs(vqueue, psgs, 2, 1, msg,
					       GFP_ATOMIC);
		else
			rc = virtqueue_add_sgs(vqueue, psgs, 1, 2, msg,
					       GFP_ATOMIC);

		if (rc) {
			atomic_dec(&substream->msg_count);
			return -EIO;
		}

		substream->msg_last_enqueued = i;
	}

	if (!(substream->features & (1U << VIRTIO_SND_PCM_F_MSG_POLLING)))
		notify = virtqueue_kick_prepare(vqueue);

	if (notify)
		if (!virtqueue_notify(vqueue))
			return -EIO;

	return 0;
}

static void virtsnd_pcm_msg_complete(struct virtio_pcm_msg *msg, size_t size)
{
	struct virtio_pcm_substream *substream = msg->substream;
	struct snd_pcm_runtime *runtime = substream->substream->runtime;
	snd_pcm_uframes_t hw_ptr;

	/* TODO: propagate an error to upper layer? */
	if (le32_to_cpu(msg->status.status) != VIRTIO_SND_S_OK)
		return;

	hw_ptr = (snd_pcm_uframes_t)atomic_read(&substream->hw_ptr);

	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK) {
		hw_ptr += runtime->period_size;
	} else {
		if (size > sizeof(struct virtio_snd_pcm_status))
			size -= sizeof(struct virtio_snd_pcm_status);
		else
			/* TODO: propagate an error to upper layer? */
			return;

		hw_ptr += bytes_to_frames(runtime, size);
	}

	atomic_set(&substream->hw_ptr, (u32)(hw_ptr % runtime->buffer_size));
	atomic_set(&substream->xfer_xrun, 0);

	runtime->delay =
		bytes_to_frames(runtime,
				le32_to_cpu(msg->status.latency_bytes));

	snd_pcm_period_elapsed(substream->substream);
}

static inline void virtsnd_pcm_notify_cb(struct virtio_snd_queue *queue)
{
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	while (queue->vqueue) {
		virtqueue_disable_cb(queue->vqueue);

		for (;;) {
			struct virtio_pcm_substream *substream;
			struct virtio_pcm_msg *msg;
			unsigned int msg_count;
			u32 length;

			msg = virtqueue_get_buf(queue->vqueue, &length);
			if (!msg)
				break;

			substream = msg->substream;

			msg_count = atomic_dec_return(&substream->msg_count);

			if (atomic_read(&substream->xfer_enabled)) {
				virtsnd_pcm_msg_complete(msg, length);
				virtsnd_pcm_msg_send(substream);
			} else if (!msg_count) {
				wake_up_all(&substream->msg_empty);
			}
		}

		if (unlikely(virtqueue_is_broken(queue->vqueue)))
			break;

		if (virtqueue_enable_cb(queue->vqueue))
			break;
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}

void virtsnd_pcm_tx_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;

	virtsnd_pcm_notify_cb(virtsnd_tx_queue(snd));
}

void virtsnd_pcm_rx_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;

	virtsnd_pcm_notify_cb(virtsnd_rx_queue(snd));
}

struct virtio_snd_msg *
virtsnd_pcm_ctl_msg_alloc(struct virtio_pcm_substream *substream,
			  unsigned int command, gfp_t gfp)
{
	struct virtio_device *vdev = substream->snd->vdev;
	size_t request_size = sizeof(struct virtio_snd_pcm_hdr);
	size_t response_size = sizeof(struct virtio_snd_hdr);
	struct virtio_snd_msg *msg;

	switch (command) {
	case VIRTIO_SND_R_PCM_SET_PARAMS: {
		request_size = sizeof(struct virtio_snd_pcm_set_params);
		break;
	}
	}

	msg = virtsnd_ctl_msg_alloc(vdev, request_size, response_size, gfp);
	if (!IS_ERR(msg)) {
		struct virtio_snd_pcm_hdr *hdr = sg_virt(&msg->sg_request);

		hdr->hdr.code = cpu_to_virtio32(vdev, command);
		hdr->stream_id = cpu_to_virtio32(vdev, substream->sid);
	}

	return msg;
}
