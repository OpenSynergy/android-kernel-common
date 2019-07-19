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
#include <sound/jack.h>
#include <sound/hda_verbs.h>

#include "virtio_card.h"

/**
 * struct virtio_jack - Virtio jack representation.
 * @jack: Kernel jack control.
 * @nid: Functional group node identifier.
 * @features: Jack virtio feature bit map (1 << VIRTIO_SND_JACK_F_XXX).
 * @defconf: Pin default configuration value.
 * @caps: Pin capabilities value.
 * @connected: Current jack connection status.
 * @type: Kernel jack type (SND_JACK_XXX).
 */
struct virtio_jack {
	struct snd_jack *jack;
	unsigned int nid;
	unsigned int features;
	unsigned int defconf;
	unsigned int caps;
	bool connected;
	int type;
};

static const char *virtsnd_jack_get_label(struct virtio_jack *jack)
{
	unsigned int defconf = jack->defconf;
	unsigned int device =
		(defconf & AC_DEFCFG_DEVICE) >> AC_DEFCFG_DEVICE_SHIFT;
	unsigned int location =
		(defconf & AC_DEFCFG_LOCATION) >> AC_DEFCFG_LOCATION_SHIFT;

	switch (device) {
	case AC_JACK_LINE_OUT:
		return "Line Out";
	case AC_JACK_SPEAKER:
		return "Speaker";
	case AC_JACK_HP_OUT:
		return "Headphone";
	case AC_JACK_CD:
		return "CD";
	case AC_JACK_SPDIF_OUT:
	case AC_JACK_DIG_OTHER_OUT:
		if (location == AC_JACK_LOC_HDMI)
			return "HDMI Out";
		else
			return "SPDIF Out";
	case AC_JACK_LINE_IN:
		return "Line";
	case AC_JACK_AUX:
		return "Aux";
	case AC_JACK_MIC_IN:
		return "Mic";
	case AC_JACK_SPDIF_IN:
		return "SPDIF In";
	case AC_JACK_DIG_OTHER_IN:
		return "Digital In";
	default:
		return "Misc";
	}
}

static int virtsnd_jack_get_type(struct virtio_jack *jack)
{
	unsigned int defconf = jack->defconf;
	unsigned int device =
		(defconf & AC_DEFCFG_DEVICE) >> AC_DEFCFG_DEVICE_SHIFT;

	switch (device) {
	case AC_JACK_LINE_OUT:
	case AC_JACK_SPEAKER:
		return SND_JACK_LINEOUT;
	case AC_JACK_HP_OUT:
		return SND_JACK_HEADPHONE;
	case AC_JACK_SPDIF_OUT:
	case AC_JACK_DIG_OTHER_OUT:
		return SND_JACK_AVOUT;
	case AC_JACK_MIC_IN:
		return SND_JACK_MICROPHONE;
	default:
		return SND_JACK_LINEIN;
	}
}

int virtsnd_jack_parse_cfg(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	int code;
	unsigned int i;
	struct virtio_snd_jack_info *info;

	virtio_cread(vdev, struct virtio_snd_config, jacks, &snd->njacks);
	if (!snd->njacks)
		return 0;

	snd->jacks = devm_kcalloc(&vdev->dev, snd->njacks, sizeof(*snd->jacks),
				  GFP_KERNEL);
	if (!snd->jacks)
		return -ENOMEM;

	info = devm_kcalloc(&vdev->dev, snd->njacks, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	code = virtsnd_ctl_query_info(snd, VIRTIO_SND_R_JACK_INFO, 0,
				      snd->njacks, sizeof(*info), info);
	if (code)
		return code;

	for (i = 0; i < snd->njacks; ++i) {
		struct virtio_jack *jack = &snd->jacks[i];
		struct virtio_pcm *pcm;

		jack->nid = le32_to_cpu(info[i].hdr.hda_fn_nid);
		jack->features = le32_to_cpu(info[i].features);
		jack->defconf = le32_to_cpu(info[i].hda_reg_defconf);
		jack->caps = le32_to_cpu(info[i].hda_reg_caps);
		jack->connected = info[i].connected;

		pcm = virtsnd_pcm_find_or_create(snd, jack->nid);
		if (IS_ERR(pcm))
			return PTR_ERR(pcm);
	}

	devm_kfree(&vdev->dev, info);

	return 0;
}

static int virtsnd_jack_check_entity_cfg(struct virtio_jack *jack,
					 struct virtio_snd_jack_info *info)
{
	if (jack->nid != le32_to_cpu(info->hdr.hda_fn_nid))
		return -EINVAL;
	if (jack->defconf != le32_to_cpu(info->hda_reg_defconf))
		return -EINVAL;

	jack->features = le32_to_cpu(info->features);
	jack->caps = le32_to_cpu(info->hda_reg_caps);
	jack->connected = info->connected;

	return 0;
}

int virtsnd_jack_check_cfg(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	int rc;
	unsigned int i;
	struct virtio_snd_jack_info *info;

	virtio_cread(vdev, struct virtio_snd_config, jacks, &i);
	if (snd->njacks != i) {
		dev_warn(&vdev->dev,
			 "config: number of jacks has changed (%u->%u)",
			 snd->njacks, i);
		return -EINVAL;
	}

	if (!snd->njacks)
		return 0;

	info = devm_kcalloc(&vdev->dev, snd->njacks, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	rc = virtsnd_ctl_query_info(snd, VIRTIO_SND_R_JACK_INFO, 0,
				      snd->njacks, sizeof(*info), info);
	if (rc)
		goto on_failure;

	for (i = 0; i < snd->njacks; ++i) {
		struct virtio_jack *jack = &snd->jacks[i];

		rc = virtsnd_jack_check_entity_cfg(jack, &info[i]);
		if (rc) {
			dev_warn(&vdev->dev,
				 "config: jack#%u configuration has changed", i);
			break;
		}

		snd_jack_report(jack->jack, jack->connected ? jack->type : 0);
	}

on_failure:
	devm_kfree(&vdev->dev, info);

	return rc;
}

int virtsnd_jack_build_devs(struct virtio_snd *snd)
{
	unsigned int i;
	int code;

	for (i = 0; i < snd->njacks; ++i) {
		struct virtio_jack *jack = &snd->jacks[i];

		jack->type = virtsnd_jack_get_type(jack);

		code = snd_jack_new(snd->card, virtsnd_jack_get_label(jack),
				    jack->type, &jack->jack, true, true);
		if (code)
			return code;

		if (!jack->jack)
			continue;

		jack->jack->private_data = jack;

		snd_jack_report(jack->jack,
				jack->connected ? jack->type : 0);
	}

	return 0;
}

void virtsnd_jack_event(struct virtio_snd *snd, struct virtio_snd_event *event)
{
	unsigned int jack_id = le32_to_cpu(event->data);
	struct virtio_jack *jack;

	if (jack_id >= snd->njacks)
		return;

	jack = &snd->jacks[jack_id];

	switch (le32_to_cpu(event->hdr.code)) {
	case VIRTIO_SND_EVT_JACK_CONNECTED: {
		jack->connected = true;
		break;
	}
	case VIRTIO_SND_EVT_JACK_DISCONNECTED: {
		jack->connected = false;
		break;
	}
	default: {
		return;
	}
	}

	snd_jack_report(jack->jack, jack->connected ? jack->type : 0);
}
