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
#ifndef VIRTIO_SND_PCM_H
#define VIRTIO_SND_PCM_H

#include <linux/atomic.h>
#include <linux/virtio_config.h>
#include <sound/pcm.h>

struct virtio_pcm;
struct virtio_pcm_msg;

/**
 * struct virtio_pcm_substream - virtio PCM substream representation.
 * @snd: Virtio sound card device.
 * @nid: Functional group node identifier.
 * @sid: Stream identifier.
 * @direction: Stream data flow direction (VIRTIO_SND_D_XXX).
 * @features: Stream virtio feature bit map (1 << VIRTIO_SND_PCM_F_XXX).
 * @substream: Kernel substream.
 * @hw: Kernel substream hardware descriptor.
 * @hw_ptr: Substream hardware pointer value.
 * @xfer_enabled: Data transfer state.
 * @xfer_draining: Data draining state.
 * @xfer_xrun: Data underflow/overflow state.
 * @msg_list: Pending I/O message list.
 * @msg_empty: Notify when msg_list is empty.
 */
struct virtio_pcm_substream {
	struct virtio_snd *snd;
	unsigned int nid;
	unsigned int sid;
	u32 direction;
	u32 features;
	struct snd_pcm_substream *substream;
	struct snd_pcm_hardware hw;
	atomic_t hw_ptr;
	atomic_t xfer_enabled;
	atomic_t xfer_xrun;
	struct virtio_pcm_msg *msgs;
	int msg_last_enqueued;
	atomic_t msg_count;
	wait_queue_head_t msg_empty;
};

/**
 * struct virtio_pcm_stream - virtio PCM stream representation.
 * @substreams: Virtio substreams belonging to the stream.
 * @nsubstreams: Number of substreams.
 * @chmaps: Kernel channel maps belonging to the stream.
 * @nchmaps: Number of channel maps.
 */
struct virtio_pcm_stream {
	struct virtio_pcm_substream **substreams;
	unsigned int nsubstreams;
	struct snd_pcm_chmap_elem *chmaps;
	unsigned int nchmaps;
};

/**
 * struct virtio_pcm - virtio PCM device representation.
 * @list: PCM list entry.
 * @nid: Functional group node identifier.
 * @pcm: Kernel PCM device.
 * @streams: Virtio streams (playback and capture).
 */
struct virtio_pcm {
	struct list_head list;
	unsigned int nid;
	struct snd_pcm *pcm;
	struct virtio_pcm_stream streams[SNDRV_PCM_STREAM_LAST + 1];
};

extern const struct snd_pcm_ops virtsnd_pcm_ops;

int virtsnd_pcm_validate(struct virtio_device *vdev);

int virtsnd_pcm_parse_cfg(struct virtio_snd *snd);

int virtsnd_pcm_check_cfg(struct virtio_snd *snd);

int virtsnd_pcm_build_devs(struct virtio_snd *snd);

#ifdef CONFIG_PM_SLEEP
int virtsnd_pcm_restore(struct virtio_snd *snd);
#endif /* CONFIG_PM_SLEEP */

void virtsnd_pcm_event(struct virtio_snd *snd, struct virtio_snd_event *event);

void virtsnd_pcm_tx_notify_cb(struct virtqueue *vqueue);

void virtsnd_pcm_rx_notify_cb(struct virtqueue *vqueue);

struct virtio_pcm *virtsnd_pcm_find(struct virtio_snd *snd, unsigned int nid);

struct virtio_pcm *virtsnd_pcm_find_or_create(struct virtio_snd *snd,
					      unsigned int nid);

struct virtio_snd_msg *
virtsnd_pcm_ctl_msg_alloc(struct virtio_pcm_substream *substream,
			  unsigned int command, gfp_t gfp);

int virtsnd_pcm_msg_alloc(struct virtio_pcm_substream *substream,
			  unsigned int nmsg, u8 *dma_area,
			  unsigned int period_bytes);

int virtsnd_pcm_msg_send(struct virtio_pcm_substream *substream);

#endif /* VIRTIO_SND_PCM_H */
