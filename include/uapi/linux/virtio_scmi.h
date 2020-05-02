/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2020  OpenSynergy GmbH
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef VIRTIO_SCMI_IF_H
#define VIRTIO_SCMI_IF_H

#include <linux/virtio_types.h>

#define VQ_TX 0
#define VQ_RX 1
#define VQ_MAX_CNT 2

/*
 * For virtio scmi transport message size is not limited by mailbox shmem size,
 * and can be bigger than still hardcoded in mainline value of 128, so this
 * value can be changed.
 */
#define VIRTIO_SCMI_MAX_MSG_SIZE 128

/*
 * Feature bits.
 *
 * VIRTIO_SCMI_F_P2A_CHANNELS - Device implements some SCMI, notifications,
 *                              or delayed responses.
 */
#define VIRTIO_SCMI_F_P2A_CHANNELS 0

struct virtio_scmi_response {
	__virtio32 hdr;
	__virtio32 status;
	u8 data[];
};

struct virtio_scmi_request {
	__virtio32 hdr;
	u8 data[];
};

struct virtio_scmi_notification {
	__virtio32 hdr;
	u8 data[];
};
#endif /* VIRTIO_SCMI_IF_H */
