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
#ifndef VIRTIO_SND_CARD_H
#define VIRTIO_SND_CARD_H

#include <linux/virtio.h>
#include <sound/core.h>

#include "virtio_snd.h"
#include "virtio_ctl_msg.h"
#include "virtio_pcm.h"

#include "virtio_opsy.h"

struct virtio_jack;
struct virtio_pcm_substream;
struct virtio_kctl_ctx;

/**
 * struct virtio_snd_queue - Virtqueue wrapper structure.
 * @lock: Used to synchronize access to a virtqueue.
 * @vqueue: Pointer to underlying virtqueue structure.
 */
struct virtio_snd_queue {
	spinlock_t lock;
	struct virtqueue *vqueue;
};

/**
 * struct virtio_snd - Virtio sound card device representation.
 * @vdev: Underlying virtio device.
 * @queues: Virtqueue wrappers.
 * @card: Kernel sound card device.
 * @pcm_list: List of virtio PCM devices.
 * @jacks: Virtio jacks.
 * @njacks: Number of jacks.
 * @substreams: Virtio PCM substreams.
 * @nsubstreams: Number of PCM stream.
 * @extensions: Supported OpSy extension bit map (1 << VIRTIO_SND_OPSY_F_XXX).
 */
struct virtio_snd {
	struct virtio_device *vdev;
	struct virtio_snd_queue queues[VIRTIO_SND_VQ_MAX];
	struct work_struct reset_work;
	struct snd_card *card;
	struct list_head ctl_msgs;
	struct virtio_snd_event *event_msgs;
	struct list_head pcm_list;
	struct virtio_jack *jacks;
	unsigned int njacks;
	struct virtio_pcm_substream *substreams;
	unsigned int nsubstreams;
	struct virtio_snd_chmap_info *chmaps;
	unsigned int nchmaps;
	u32 extensions;
	/* --- OpenSynergy extensions --------------------------------------- */
	struct virtio_kctl_ctx *kctl_ctx;
	struct work_struct kctl_work;
};

static inline void
virtsnd_strlcpy(char *dst, const char *src, size_t max_size)
{
	strlcpy(dst, src, max_size);
	dst[max_size - 1] = 0;
}

static inline struct virtio_snd_queue *
virtsnd_control_queue(struct virtio_snd *snd)
{
	return &snd->queues[VIRTIO_SND_VQ_CONTROL];
}

static inline struct virtio_snd_queue *
virtsnd_event_queue(struct virtio_snd *snd)
{
	return &snd->queues[VIRTIO_SND_VQ_EVENT];
}

static inline struct virtio_snd_queue *
virtsnd_tx_queue(struct virtio_snd *snd)
{
	return &snd->queues[VIRTIO_SND_VQ_TX];
}

static inline struct virtio_snd_queue *
virtsnd_rx_queue(struct virtio_snd *snd)
{
	return &snd->queues[VIRTIO_SND_VQ_RX];
}

static inline struct virtio_snd_queue *
virtsnd_pcm_queue(struct virtio_pcm_substream *substream)
{
	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK)
		return virtsnd_tx_queue(substream->snd);
	else
		return virtsnd_rx_queue(substream->snd);
}

/*
 * event related functions:
 */
int virtsnd_event_populate(struct virtio_snd *snd);

void virtsnd_event_notify_cb(struct virtqueue *vqueue);

/*
 * jack related functions:
 */
int virtsnd_jack_parse_cfg(struct virtio_snd *snd);

int virtsnd_jack_check_cfg(struct virtio_snd *snd);

int virtsnd_jack_build_devs(struct virtio_snd *snd);

void virtsnd_jack_event(struct virtio_snd *snd,
			struct virtio_snd_event *event);

/*
 * channel map related functions:
 */
int virtsnd_chmap_parse_cfg(struct virtio_snd *snd);

int virtsnd_chmap_check_cfg(struct virtio_snd *snd);

int virtsnd_chmap_build_devs(struct virtio_snd *snd);

/*
 * device controls related functions:
 */
int virtsnd_dc_parse_cfg(struct virtio_snd *vsnd);

void virtsnd_dc_event(struct virtio_snd *vsnd, struct virtio_snd_event *event);

#endif /* VIRTIO_SND_CARD_H */
