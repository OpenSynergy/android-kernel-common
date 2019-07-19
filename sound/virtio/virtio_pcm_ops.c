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

struct virtsnd_a2v_format {
	unsigned int alsa_bit;
	unsigned int vio_bit;
};

static const struct virtsnd_a2v_format g_a2v_format_map[] = {
	{ SNDRV_PCM_FORMAT_IMA_ADPCM, VIRTIO_SND_PCM_FMT_IMA_ADPCM },
	{ SNDRV_PCM_FORMAT_MU_LAW, VIRTIO_SND_PCM_FMT_MU_LAW },
	{ SNDRV_PCM_FORMAT_A_LAW, VIRTIO_SND_PCM_FMT_A_LAW },
	{ SNDRV_PCM_FORMAT_S8, VIRTIO_SND_PCM_FMT_S8 },
	{ SNDRV_PCM_FORMAT_U8, VIRTIO_SND_PCM_FMT_U8 },
	{ SNDRV_PCM_FORMAT_S16_LE, VIRTIO_SND_PCM_FMT_S16 },
	{ SNDRV_PCM_FORMAT_U16_LE, VIRTIO_SND_PCM_FMT_U16 },
	{ SNDRV_PCM_FORMAT_S18_3LE, VIRTIO_SND_PCM_FMT_S18_3 },
	{ SNDRV_PCM_FORMAT_U18_3LE, VIRTIO_SND_PCM_FMT_U18_3 },
	{ SNDRV_PCM_FORMAT_S20_3LE, VIRTIO_SND_PCM_FMT_S20_3 },
	{ SNDRV_PCM_FORMAT_U20_3LE, VIRTIO_SND_PCM_FMT_U20_3 },
	{ SNDRV_PCM_FORMAT_S24_3LE, VIRTIO_SND_PCM_FMT_S24_3 },
	{ SNDRV_PCM_FORMAT_U24_3LE, VIRTIO_SND_PCM_FMT_U24_3 },
#ifdef SNDRV_PCM_FORMAT_S20
	{ SNDRV_PCM_FORMAT_S20_LE, VIRTIO_SND_PCM_FMT_S20 },
#endif
#ifdef SNDRV_PCM_FORMAT_U20
	{ SNDRV_PCM_FORMAT_U20_LE, VIRTIO_SND_PCM_FMT_U20 },
#endif
	{ SNDRV_PCM_FORMAT_S24_LE, VIRTIO_SND_PCM_FMT_S24 },
	{ SNDRV_PCM_FORMAT_U24_LE, VIRTIO_SND_PCM_FMT_U24 },
	{ SNDRV_PCM_FORMAT_S32_LE, VIRTIO_SND_PCM_FMT_S32 },
	{ SNDRV_PCM_FORMAT_U32_LE, VIRTIO_SND_PCM_FMT_U32 },
	{ SNDRV_PCM_FORMAT_FLOAT_LE, VIRTIO_SND_PCM_FMT_FLOAT },
	{ SNDRV_PCM_FORMAT_FLOAT64_LE, VIRTIO_SND_PCM_FMT_FLOAT64 },
	{ SNDRV_PCM_FORMAT_DSD_U8, VIRTIO_SND_PCM_FMT_DSD_U8 },
	{ SNDRV_PCM_FORMAT_DSD_U16_LE, VIRTIO_SND_PCM_FMT_DSD_U16 },
	{ SNDRV_PCM_FORMAT_DSD_U32_LE, VIRTIO_SND_PCM_FMT_DSD_U32 },
	{ SNDRV_PCM_FORMAT_IEC958_SUBFRAME_LE,
	  VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME }
};

struct virtsnd_a2v_rate {
	unsigned int rate;
	unsigned int vio_bit;
};

static const struct virtsnd_a2v_rate g_a2v_rate_map[] = {
	{ 5512, VIRTIO_SND_PCM_RATE_5512 },
	{ 8000, VIRTIO_SND_PCM_RATE_8000 },
	{ 11025, VIRTIO_SND_PCM_RATE_11025 },
	{ 16000, VIRTIO_SND_PCM_RATE_16000 },
	{ 22050, VIRTIO_SND_PCM_RATE_22050 },
	{ 32000, VIRTIO_SND_PCM_RATE_32000 },
	{ 44100, VIRTIO_SND_PCM_RATE_44100 },
	{ 48000, VIRTIO_SND_PCM_RATE_48000 },
	{ 64000, VIRTIO_SND_PCM_RATE_64000 },
	{ 88200, VIRTIO_SND_PCM_RATE_88200 },
	{ 96000, VIRTIO_SND_PCM_RATE_96000 },
	{ 176400, VIRTIO_SND_PCM_RATE_176400 },
	{ 192000, VIRTIO_SND_PCM_RATE_192000 }
};

static inline bool virtsnd_pcm_released(struct virtio_pcm_substream *substream)
{
	return atomic_read(&substream->msg_count) == 0;
}

static int virtsnd_pcm_release(struct virtio_pcm_substream *substream)
{
	struct virtio_snd *snd = substream->snd;
	struct virtio_snd_msg *msg;
	int rc;

	msg = virtsnd_pcm_ctl_msg_alloc(substream, VIRTIO_SND_R_PCM_RELEASE,
					GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	rc = virtsnd_ctl_msg_send_sync(snd, msg);
	if (!rc)
		rc = wait_event_interruptible(substream->msg_empty,
					      virtsnd_pcm_released(substream));

	return rc;
}

static int virtsnd_pcm_open(struct snd_pcm_substream *substream)
{
	struct virtio_pcm *pcm = snd_pcm_substream_chip(substream);
	struct virtio_pcm_substream *ss = NULL;

	if (pcm) {
		switch (substream->stream) {
		case SNDRV_PCM_STREAM_PLAYBACK:
		case SNDRV_PCM_STREAM_CAPTURE: {
			struct virtio_pcm_stream *stream =
				&pcm->streams[substream->stream];

			if (substream->number < stream->nsubstreams)
				ss = stream->substreams[substream->number];
			break;
		}
		}
	}

	if (!ss)
		return -EBADFD;

	substream->runtime->hw = ss->hw;
	substream->private_data = ss;

	return 0;
}

static int virtsnd_pcm_close(struct snd_pcm_substream *substream)
{
	return 0;
}

static int virtsnd_pcm_hw_params(struct snd_pcm_substream *substream,
				 struct snd_pcm_hw_params *hw_params)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_state_t state;
	unsigned long flags;
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	struct virtio_device *vdev = ss->snd->vdev;
	struct virtio_snd_msg *msg;
	struct virtio_snd_pcm_set_params *request;
	snd_pcm_format_t format;
	unsigned int channels;
	unsigned int rate;
	unsigned int buffer_bytes;
	unsigned int period_bytes;
	unsigned int periods;
	unsigned int i;
	int vformat = -1;
	int vrate = -1;
	int rc;

	snd_pcm_stream_lock_irqsave(substream, flags);
	state = substream->runtime->status->state;
	snd_pcm_stream_unlock_irqrestore(substream, flags);

	if (state != SNDRV_PCM_STATE_SUSPENDED) {
		/*
		 * If we got here after ops->trigger() was called, the queue may
		 * still contain messages. In this case, we need to release the
		 * substream first.
		 */
		if (atomic_read(&ss->msg_count)) {
			rc = virtsnd_pcm_release(ss);
			if (rc)
				return rc;
		}
	}

	/* Set hardware parameters in device */
	if (hw_params) {
		format = params_format(hw_params);
		channels = params_channels(hw_params);
		rate = params_rate(hw_params);
		buffer_bytes = params_buffer_bytes(hw_params);
		period_bytes = params_period_bytes(hw_params);
		periods = params_periods(hw_params);
	} else {
		format = runtime->format;
		channels = runtime->channels;
		rate = runtime->rate;
		buffer_bytes = frames_to_bytes(runtime, runtime->buffer_size);
		period_bytes = frames_to_bytes(runtime, runtime->period_size);
		periods = runtime->periods;
	}

	for (i = 0; i < ARRAY_SIZE(g_a2v_format_map); ++i)
		if (g_a2v_format_map[i].alsa_bit == format) {
			vformat = g_a2v_format_map[i].vio_bit;

			break;
		}

	for (i = 0; i < ARRAY_SIZE(g_a2v_rate_map); ++i)
		if (g_a2v_rate_map[i].rate == rate) {
			vrate = g_a2v_rate_map[i].vio_bit;

			break;
		}

	if (vformat == -1 || vrate == -1)
		return -EINVAL;

	msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_SET_PARAMS,
					GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = sg_virt(&msg->sg_request);

	request->buffer_bytes = cpu_to_virtio32(vdev, buffer_bytes);
	request->period_bytes = cpu_to_virtio32(vdev, period_bytes);
	request->channels = channels;
	request->format = vformat;
	request->rate = vrate;

	if (ss->features & (1U << VIRTIO_SND_PCM_F_MSG_POLLING))
		request->features |=
			cpu_to_virtio32(vdev,
					1U << VIRTIO_SND_PCM_F_MSG_POLLING);

	if (ss->features & (1U << VIRTIO_SND_PCM_F_EVT_XRUNS))
		request->features |=
			cpu_to_virtio32(vdev,
					1U << VIRTIO_SND_PCM_F_EVT_XRUNS);

	rc = virtsnd_ctl_msg_send_sync(ss->snd, msg);
	if (rc)
		return rc;

	/* If the buffer was already allocated earlier, do nothing. */
	if (runtime->dma_area)
		return 0;

	/* Allocate hardware buffer */
	rc = snd_pcm_lib_malloc_pages(substream, buffer_bytes);
	if (rc < 0)
		return rc;

	/* Allocate and initialize I/O messages */
	rc = virtsnd_pcm_msg_alloc(ss, periods, runtime->dma_area,
				   period_bytes);
	if (rc)
		snd_pcm_lib_free_pages(substream);

	return rc;
}

static int virtsnd_pcm_hw_free(struct snd_pcm_substream *substream)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	int rc;

	rc = virtsnd_pcm_release(ss);

	/*
	 * Even if we failed to send the RELEASE message or wait for the queue
	 * flush to complete, we can safely delete the buffer. Because after
	 * receiving the STOP command, the device must stop all I/O message
	 * processing. If there are still pending messages in the queue, the
	 * next ops->hw_params() call should deal with this.
	 */
	snd_pcm_lib_free_pages(substream);

	return rc;
}

static int virtsnd_pcm_prepare(struct snd_pcm_substream *substream)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	snd_pcm_state_t state;
	struct virtio_snd_msg *msg;
	unsigned long flags;
	int rc;

	snd_pcm_stream_lock_irqsave(substream, flags);
	state = substream->runtime->status->state;
	snd_pcm_stream_unlock_irqrestore(substream, flags);

	if (state != SNDRV_PCM_STATE_SUSPENDED) {
		struct virtio_snd_queue *queue = virtsnd_pcm_queue(ss);

		/*
		 * If we got here after ops->trigger() was called, the queue may
		 * still contain messages. In this case, we need to reset the
		 * substream first.
		 */
		if (atomic_read(&ss->msg_count)) {
			rc = virtsnd_pcm_hw_params(substream, NULL);
			if (rc)
				return rc;
		}

		spin_lock_irqsave(&queue->lock, flags);
		ss->msg_last_enqueued = -1;
		spin_unlock_irqrestore(&queue->lock, flags);

		atomic_set(&ss->hw_ptr, 0);
	}

	atomic_set(&ss->xfer_xrun, 0);
	atomic_set(&ss->msg_count, 0);

	msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_PREPARE,
					GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	return virtsnd_ctl_msg_send_sync(ss->snd, msg);
}

static int virtsnd_pcm_trigger(struct snd_pcm_substream *substream, int command)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	struct virtio_snd *snd = ss->snd;
	struct virtio_snd_queue *queue = virtsnd_pcm_queue(ss);
	struct virtio_snd_msg *msg;

	switch (command) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME: {
		int rc;

		spin_lock(&queue->lock);
		rc = virtsnd_pcm_msg_send(ss);
		spin_unlock(&queue->lock);
		if (rc)
			return rc;

		atomic_set(&ss->xfer_enabled, 1);

		msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_START,
						GFP_ATOMIC);
		if (IS_ERR(msg))
			return PTR_ERR(msg);

		return virtsnd_ctl_msg_send(snd, msg);
	}
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND: {
		atomic_set(&ss->xfer_enabled, 0);

		msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_STOP,
						GFP_ATOMIC);
		if (IS_ERR(msg))
			return PTR_ERR(msg);

		return virtsnd_ctl_msg_send(snd, msg);
	}
	default: {
		return -EINVAL;
	}
	}
}

static snd_pcm_uframes_t
virtsnd_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);

	if (atomic_read(&ss->xfer_xrun))
		return SNDRV_PCM_POS_XRUN;

	return (snd_pcm_uframes_t)atomic_read(&ss->hw_ptr);
}

const struct snd_pcm_ops virtsnd_pcm_ops = {
	.open = virtsnd_pcm_open,
	.close = virtsnd_pcm_close,
	.ioctl = snd_pcm_lib_ioctl,
	.hw_params = virtsnd_pcm_hw_params,
	.hw_free = virtsnd_pcm_hw_free,
	.prepare = virtsnd_pcm_prepare,
	.trigger = virtsnd_pcm_trigger,
	.pointer = virtsnd_pcm_pointer,
};
