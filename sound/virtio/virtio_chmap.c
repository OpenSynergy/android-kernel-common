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
#include <linux/virtio_config.h>

#include "virtio_card.h"

static const u8 g_v2a_position_map[] = {
	[VIRTIO_SND_CHMAP_NONE] = SNDRV_CHMAP_UNKNOWN,
	[VIRTIO_SND_CHMAP_NA] = SNDRV_CHMAP_NA,
	[VIRTIO_SND_CHMAP_MONO] = SNDRV_CHMAP_MONO,
	[VIRTIO_SND_CHMAP_FL] = SNDRV_CHMAP_FL,
	[VIRTIO_SND_CHMAP_FR] = SNDRV_CHMAP_FR,
	[VIRTIO_SND_CHMAP_RL] = SNDRV_CHMAP_RL,
	[VIRTIO_SND_CHMAP_RR] = SNDRV_CHMAP_RR,
	[VIRTIO_SND_CHMAP_FC] = SNDRV_CHMAP_FC,
	[VIRTIO_SND_CHMAP_LFE] = SNDRV_CHMAP_LFE,
	[VIRTIO_SND_CHMAP_SL] = SNDRV_CHMAP_SL,
	[VIRTIO_SND_CHMAP_SR] = SNDRV_CHMAP_SR,
	[VIRTIO_SND_CHMAP_RC] = SNDRV_CHMAP_RC,
	[VIRTIO_SND_CHMAP_FLC] = SNDRV_CHMAP_FLC,
	[VIRTIO_SND_CHMAP_FRC] = SNDRV_CHMAP_FRC,
	[VIRTIO_SND_CHMAP_RLC] = SNDRV_CHMAP_RLC,
	[VIRTIO_SND_CHMAP_RRC] = SNDRV_CHMAP_RRC,
	[VIRTIO_SND_CHMAP_FLW] = SNDRV_CHMAP_FLW,
	[VIRTIO_SND_CHMAP_FRW] = SNDRV_CHMAP_FRW,
	[VIRTIO_SND_CHMAP_FLH] = SNDRV_CHMAP_FLH,
	[VIRTIO_SND_CHMAP_FCH] = SNDRV_CHMAP_FCH,
	[VIRTIO_SND_CHMAP_FRH] = SNDRV_CHMAP_FRH,
	[VIRTIO_SND_CHMAP_TC] = SNDRV_CHMAP_TC,
	[VIRTIO_SND_CHMAP_TFL] = SNDRV_CHMAP_TFL,
	[VIRTIO_SND_CHMAP_TFR] = SNDRV_CHMAP_TFR,
	[VIRTIO_SND_CHMAP_TFC] = SNDRV_CHMAP_TFC,
	[VIRTIO_SND_CHMAP_TRL] = SNDRV_CHMAP_TRL,
	[VIRTIO_SND_CHMAP_TRR] = SNDRV_CHMAP_TRR,
	[VIRTIO_SND_CHMAP_TRC] = SNDRV_CHMAP_TRC,
	[VIRTIO_SND_CHMAP_TFLC] = SNDRV_CHMAP_TFLC,
	[VIRTIO_SND_CHMAP_TFRC] = SNDRV_CHMAP_TFRC,
	[VIRTIO_SND_CHMAP_TSL] = SNDRV_CHMAP_TSL,
	[VIRTIO_SND_CHMAP_TSR] = SNDRV_CHMAP_TSR,
	[VIRTIO_SND_CHMAP_LLFE] = SNDRV_CHMAP_LLFE,
	[VIRTIO_SND_CHMAP_RLFE] = SNDRV_CHMAP_RLFE,
	[VIRTIO_SND_CHMAP_BC] = SNDRV_CHMAP_BC,
	[VIRTIO_SND_CHMAP_BLC] = SNDRV_CHMAP_BLC,
	[VIRTIO_SND_CHMAP_BRC] = SNDRV_CHMAP_BRC
};

int virtsnd_chmap_parse_cfg(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	int rc;
	struct virtio_pcm *pcm;
	struct virtio_pcm_stream *stream;
	unsigned int i;

	virtio_cread(vdev, struct virtio_snd_config, chmaps, &snd->nchmaps);
	if (!snd->nchmaps)
		return 0;

	snd->chmaps = devm_kcalloc(&vdev->dev, snd->nchmaps,
				   sizeof(*snd->chmaps), GFP_KERNEL);
	if (!snd->chmaps)
		return -ENOMEM;

	rc = virtsnd_ctl_query_info(snd, VIRTIO_SND_R_CHMAP_INFO, 0,
				    snd->nchmaps, sizeof(*snd->chmaps),
				    snd->chmaps);
	if (rc)
		return rc;

	/* Count the number of channel maps per each pcm/stream. */
	for (i = 0; i < snd->nchmaps; ++i) {
		struct virtio_snd_chmap_info *info = &snd->chmaps[i];
		unsigned int nid = le32_to_cpu(info->hdr.hda_fn_nid);

		pcm = virtsnd_pcm_find_or_create(snd, nid);
		if (IS_ERR(pcm))
			return PTR_ERR(pcm);

		switch (info->direction) {
		case VIRTIO_SND_D_OUTPUT: {
			stream = &pcm->streams[SNDRV_PCM_STREAM_PLAYBACK];
			break;
		}
		case VIRTIO_SND_D_INPUT: {
			stream = &pcm->streams[SNDRV_PCM_STREAM_CAPTURE];
			break;
		}
		default: {
			dev_err(&vdev->dev,
				"chmap #%u: unknown direction (%u)", i,
				info->direction);
			return -EINVAL;
		}
		}

		stream->nchmaps++;
	}

	return 0;
}

int virtsnd_chmap_check_cfg(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	int rc;
	struct virtio_snd_chmap_info *info;
	unsigned int i;

	virtio_cread(vdev, struct virtio_snd_config, chmaps, &i);
	if (snd->nchmaps != i) {
		dev_warn(&vdev->dev,
			 "config: number of channel maps has changed (%u->%u)",
			 snd->nchmaps, i);
		return -EINVAL;
	}

	if (!snd->chmaps)
		return 0;

	info = devm_kcalloc(&vdev->dev, snd->nchmaps, sizeof(*info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	rc = virtsnd_ctl_query_info(snd, VIRTIO_SND_R_CHMAP_INFO, 0,
				    snd->nchmaps, sizeof(*info), info);
	if (rc)
		goto on_failure;

	for (i = 0; i < snd->nchmaps; ++i)
		if (memcmp(&snd->chmaps[i], &info[i], sizeof(*info)) != 0) {
			dev_warn(&vdev->dev,
				 "config: channel map #%u has changed", i);
			rc = -EINVAL;
			break;
		}

on_failure:
	devm_kfree(&vdev->dev, info);

	return rc;
}

static int virtsnd_chmap_add_ctls(struct snd_pcm *pcm, int direction,
				  struct virtio_pcm_stream *stream)
{
	unsigned int i;
	int max_channels = 0;

	for (i = 0; i < stream->nchmaps; i++)
		if (max_channels < stream->chmaps[i].channels)
			max_channels = stream->chmaps[i].channels;

	return snd_pcm_add_chmap_ctls(pcm, direction, stream->chmaps,
				      max_channels, 0, NULL);
}

int virtsnd_chmap_build_devs(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_pcm *pcm;
	struct virtio_pcm_stream *stream;
	unsigned int i;
	int rc;

	/* Allocate channel map elements per each pcm/stream. */
	list_for_each_entry(pcm, &snd->pcm_list, list) {
		for (i = 0; i < ARRAY_SIZE(pcm->streams); ++i) {
			stream = &pcm->streams[i];

			if (!stream->nchmaps)
				continue;

			stream->chmaps = devm_kcalloc(&vdev->dev,
						      stream->nchmaps + 1,
						      sizeof(*stream->chmaps),
						      GFP_KERNEL);
			if (!stream->chmaps)
				return -ENOMEM;

			stream->nchmaps = 0;
		}
	}

	/* Initialize channel maps per each pcm/stream. */
	for (i = 0; i < snd->nchmaps; ++i) {
		struct virtio_snd_chmap_info *info = &snd->chmaps[i];
		unsigned int nid = le32_to_cpu(info->hdr.hda_fn_nid);
		unsigned int channels = info->channels;
		unsigned int ch;
		struct snd_pcm_chmap_elem *chmap;

		pcm = virtsnd_pcm_find(snd, nid);
		if (IS_ERR(pcm))
			return PTR_ERR(pcm);

		if (info->direction == VIRTIO_SND_D_OUTPUT)
			stream = &pcm->streams[SNDRV_PCM_STREAM_PLAYBACK];
		else
			stream = &pcm->streams[SNDRV_PCM_STREAM_CAPTURE];

		chmap = &stream->chmaps[stream->nchmaps++];

		if (channels > ARRAY_SIZE(chmap->map))
			channels = ARRAY_SIZE(chmap->map);

		chmap->channels = channels;

		for (ch = 0; ch < channels; ++ch) {
			u8 position = info->positions[ch];

			if (position >= ARRAY_SIZE(g_v2a_position_map))
				return -EINVAL;

			chmap->map[ch] = g_v2a_position_map[position];
		}
	}

	list_for_each_entry(pcm, &snd->pcm_list, list) {
		if (!pcm->pcm)
			continue;

		for (i = 0; i < ARRAY_SIZE(pcm->streams); ++i) {
			stream = &pcm->streams[i];

			if (!stream->nchmaps)
				continue;

			rc = virtsnd_chmap_add_ctls(pcm->pcm, i, stream);
			if (rc)
				return rc;
		}
	}

	return 0;
}
