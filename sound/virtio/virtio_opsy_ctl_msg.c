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

int virtsnd_ctl_query_opsy_extensions(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_msg *msg;
	struct virtio_snd_hdr *hdr;
	struct virtio_snd_opsy_info *info;
	int code;

	msg = virtsnd_ctl_msg_alloc(vdev, sizeof(*hdr), sizeof(*info),
				    GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	virtsnd_ctl_msg_ref(vdev, msg);

	hdr = sg_virt(&msg->sg_request);
	hdr->code = cpu_to_virtio32(vdev, VIRTIO_SND_R_OPSY_INFO);

	code = virtsnd_ctl_msg_send_sync(snd, msg);
	if (code)
		return code;

	info = sg_virt(&msg->sg_response);

	snd->extensions = le32_to_cpu(info->extensions);

	if (VIRTIO_HAS_OPSY_EXTENSION(snd, DEV_EXT_INFO))
		dev_info(&vdev->dev,
			 "OpSy extension: ALSA extended device information\n");
	if (VIRTIO_HAS_OPSY_EXTENSION(snd, DEV_CTLS))
		dev_info(&vdev->dev, "OpSy extension: ALSA device controls\n");

	virtsnd_ctl_msg_unref(vdev, msg);

	return 0;
}

int virtsnd_ctl_alsa_card_info(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_msg *msg;
	struct virtio_snd_hdr *hdr;
	struct virtio_snd_alsa_card_info *info = NULL;
	struct scatterlist sg_response_ext;
	int code;

	msg = virtsnd_ctl_msg_alloc(vdev, sizeof(*hdr), sizeof(*hdr),
				    GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	virtsnd_ctl_msg_ref(vdev, msg);

	info = devm_kzalloc(&vdev->dev, sizeof(*info), GFP_KERNEL);
	if (!info) {
		code = -ENOMEM;
		goto on_failure;
	}

	hdr = sg_virt(&msg->sg_request);
	hdr->code = cpu_to_virtio32(vdev, VIRTIO_SND_R_ALSA_CARD_INFO);

	sg_init_one(&sg_response_ext, info, sizeof(*info));
	msg->sg_response_ext = &sg_response_ext;

	code = virtsnd_ctl_msg_send_sync(snd, msg);
	if (code)
		goto on_failure;

	virtsnd_strlcpy(snd->card->id, info->id, sizeof(snd->card->id));
	virtsnd_strlcpy(snd->card->driver, info->driver,
			sizeof(snd->card->driver));
	virtsnd_strlcpy(snd->card->shortname, info->name,
			sizeof(snd->card->shortname));
	virtsnd_strlcpy(snd->card->longname, info->longname,
			sizeof(snd->card->longname));
	virtsnd_strlcpy(snd->card->mixername, info->mixername,
			sizeof(snd->card->mixername));
	virtsnd_strlcpy(snd->card->components, info->components,
			sizeof(snd->card->components));

on_failure:
	if (info)
		devm_kfree(&vdev->dev, info);

	virtsnd_ctl_msg_unref(vdev, msg);

	return code;
}

int virtsnd_ctl_alsa_pcm_info(struct virtio_snd *snd, struct snd_pcm *pcm)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_msg *msg;
	struct virtio_snd_alsa_query_pcm_info *hdr;
	struct virtio_snd_alsa_pcm_info *info = NULL;
	struct scatterlist sg_response_ext;
	int code;

	msg = virtsnd_ctl_msg_alloc(vdev, sizeof(*hdr),
				    sizeof(struct virtio_snd_hdr), GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	virtsnd_ctl_msg_ref(vdev, msg);

	info = devm_kzalloc(&vdev->dev, sizeof(*info), GFP_KERNEL);
	if (!info) {
		code = -ENOMEM;
		goto on_failure;
	}

	hdr = sg_virt(&msg->sg_request);
	hdr->hdr.code = cpu_to_virtio32(vdev, VIRTIO_SND_R_ALSA_PCM_INFO);
	hdr->hda_fn_nid = cpu_to_virtio32(vdev, pcm->device);

	sg_init_one(&sg_response_ext, info, sizeof(*info));
	msg->sg_response_ext = &sg_response_ext;

	code = virtsnd_ctl_msg_send_sync(snd, msg);
	if (code)
		goto on_failure;

	virtsnd_strlcpy(pcm->id, info->id, sizeof(pcm->id));
	virtsnd_strlcpy(pcm->name, info->name, sizeof(pcm->name));

on_failure:
	if (info)
		devm_kfree(&vdev->dev, info);

	virtsnd_ctl_msg_unref(vdev, msg);

	return 0;
}
