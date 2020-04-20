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

struct virtio_scmi_response {
	__virtio32 len;
	__virtio32 hdr;
	__virtio32 status;
	u8 data[];
};

struct virtio_scmi_request {
	__virtio32 len;
	__virtio32 hdr;
	u8 data[];
};

#endif /* VIRTIO_SCMI_IF_H */
