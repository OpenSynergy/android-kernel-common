/* SPDX-License-Identifier: GPL-2.0 */
/*
 * System Control and Management Interface (SCMI) Message Protocol
 * notification header file containing some definitions, structures
 * and function prototypes related to SCMI Notification handling.
 *
 * Copyright (C) 2020 ARM Ltd.
 */
#ifndef _SCMI_NOTIFY_H
#define _SCMI_NOTIFY_H

#include <linux/bug.h>
#include <linux/device.h>
#include <linux/types.h>

#define MAP_EVT_TO_ENABLE_CMD(id, map)			\
({							\
	int ret = -1;					\
							\
	if (likely((id) < ARRAY_SIZE((map))))		\
		ret = (map)[(id)];			\
	else						\
		WARN(1, "UN-KNOWN evt_id:%d\n", (id));	\
	ret;						\
})

/**
 * struct scmi_event  - Describes an event to be supported
 * @id: Event ID
 * @max_payld_sz: Max possible size for the payload of a notif msg of this kind
 * @max_report_sz: Max possible size for the report of a notif msg of this kind
 *
 * Each SCMI protocol, during its initialization phase, can describe the events
 * it wishes to support in a few struct scmi_event and pass them to the core
 * using scmi_register_protocol_events().
 */
struct scmi_event {
	u8	id;
	size_t	max_payld_sz;
	size_t	max_report_sz;
};

/**
 * struct scmi_protocol_event_ops  - Protocol helpers called by the notification
 *				     core.
 * @set_notify_enabled: Enable/disable the required evt_id/src_id notifications
 *			using the proper custom protocol commands.
 *			Return true if at least one the required src_id
 *			has been successfully enabled/disabled
 *
 * Context: Helpers described in &struct scmi_protocol_event_ops are called
 *	    only in process context.
 */
struct scmi_protocol_event_ops {
	bool (*set_notify_enabled)(const struct scmi_handle *handle,
				   u8 evt_id, u32 src_id, bool enabled);
};

int scmi_notification_init(struct scmi_handle *handle);
void scmi_notification_exit(struct scmi_handle *handle);

int scmi_register_protocol_events(const struct scmi_handle *handle,
				  u8 proto_id, size_t queue_sz,
				  const struct scmi_protocol_event_ops *ops,
				  const struct scmi_event *evt, int num_events,
				  int num_sources);

#endif /* _SCMI_NOTIFY_H */
