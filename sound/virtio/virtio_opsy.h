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
#ifndef VIRTIO_SND_OPSY_H
#define VIRTIO_SND_OPSY_H

#define VIRTIO_HAS_OPSY_EXTENSION(_snd_, _extension_) \
	((_snd_)->extensions & (1U << (VIRTIO_SND_OPSY_F_ ## _extension_)))

int virtsnd_ctl_query_opsy_extensions(struct virtio_snd *snd);

int virtsnd_ctl_alsa_card_info(struct virtio_snd *snd);

int virtsnd_ctl_alsa_pcm_info(struct virtio_snd *snd, struct snd_pcm *pcm);

#endif /* VIRTIO_SND_OPSY_H */
