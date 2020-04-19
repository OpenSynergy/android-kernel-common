// SPDX-License-Identifier: GPL-2.0
/*
 * SCMI Sensor Example driver.
 *
 * Copyright (C) 2020 ARM Ltd.
 */

#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>

enum {
	SENSOR_TRIP_POINT_EVENT = 0x0,
	SENSOR_UPDATE = 0x1,
};

static int sensor_trip_cb(struct notifier_block *nb,
			  unsigned long event, void *data)
{
	struct scmi_sensor_trip_point_report *er = data;

	pr_info("%s()::%d - EVENT:[%ld] - TS:%lld  SID:%d  AID:%d  TRIP:%d\n",
		__func__, __LINE__, event, er->timestamp, er->sensor_id,
		er->agent_id, er->trip_point_desc);

	return NOTIFY_OK;
}

static struct notifier_block sensor_trip_nb = {
	.notifier_call = sensor_trip_cb,
};

static int sensor_update_cb(struct notifier_block *nb,
			    unsigned long event, void *data)
{
	int i;
	struct scmi_sensor_update_report *er = data;

	for (i = 0; i < er->readings_count; i++) {
		pr_info("%s() - EVT[%ld] TS:%lld ID:%d VAL_H:%d VAL_L:%d STS:%lld\n",
			__func__, event, er->timestamp, er->sensor_id,
			er->readings[i].sensor_value_high,
			er->readings[i].sensor_value_low,
			(u64)er->readings[i].timestamp_high << 32 |
			er->readings[i].sensor_value_low);
	}

	return NOTIFY_OK;
}

static struct notifier_block sensor_update_nb = {
	.notifier_call = sensor_update_cb,
};

static int scmi_iiodev_probe(struct scmi_device *sdev)
{
	int num_sensors, ret;
	struct device *dev = &sdev->dev;
	const struct scmi_handle *handle = sdev->handle;
	const struct scmi_sensor_info *s;
	struct scmi_sensor_reading *readings;
	u32 sensor_id, conf;

	if (!handle || !handle->sensor_ops)
		return -ENODEV;

	num_sensors = handle->sensor_ops->count_get(handle);
	if (num_sensors < 0) {
		dev_err(dev, "number of sensors not found\n");
		return num_sensors;
	}

	/*
	 * Picking one sensor_id descriptor
	 *
	 * scmi_sensor_info will contain all the needed
	 * sensor descriptions.
	 *
	 * Assuming in the following that sensor_id is capable
	 * of generating both SENSOR notifications:
	 *
	 * - SENSOR_TRIP_POINT_EVENT
	 * - SENSOR_UPDATE
	 */
	sensor_id = 0;
	s = handle->sensor_ops->info_get(handle, sensor_id);
	if (!s)
		return -ENOMEM;

	/*
	 * Configure and enable the sensor using one of the
	 * existent intervals listed in sensor_info.
	 *
	 * (retrieved at init by SCMI sensors protocol implementation)
	 *
	 *  conf = s->intervals.desc[1] << 11 | 2 << 9 | 1 << 1 | 1 << 0;
	 *
	 *  Still not supported...so use fixed vals
	 */
	conf =  3 << 16 | 1 << 11 | 2 << 9 | 1 << 1 | 1 << 0;
	ret = handle->sensor_ops->config_set(handle, sensor_id, conf);
	if (ret)
		pr_err("%s():%d UNSUPPORTED STILL...\n",
		       __func__, __LINE__);
		//return -EINVAL;

	/*
	 * We can read some multi-axis timestamped values...
	 * ...assuming are supported
	 */
	readings = devm_kcalloc(handle->dev, s->num_axis,
				sizeof(*readings), GFP_KERNEL);
	if (!readings)
		return -ENOMEM;

	ret = handle->sensor_ops->reading_get_timestamped(handle,
							  sensor_id,
							  s->num_axis,
							  readings);
	if (ret)
		pr_err("%s():%d UNSUPPORTED STILL...\n",
		       __func__, __LINE__);
		//return -EINVAL;

	/*
	 * We can register a notifer for SENSOR_UPDATE (we could have it also
	 * before even when the sensor was still not enabled or configured: in
	 * such case the callback would have been put in place and the event
	 * enabled BUT no event is effectively emitted until the sensor is
	 * proeprly configured/enabled or a trip point set depending on the
	 * specific event...this is not generally true for all events: some
	 * other events juts need a proper callback in place in order for
	 * notifications to be emitted).
	 *
	 * NOTE that you MUST NOT explicitly enable the specific notification
	 * with .continuos_update_notifiy() method....it will be taken care
	 * by the SCMI notification core,
	 * This also means that if platform does NOT support the specific
	 * event/sensor_id pair and returns an error on the core inner
	 * notification enable request, register_event_notifier() will fail
	 * and return error too.
	 */
	ret = handle->notify_ops->register_event_notifier(handle,
							  SCMI_PROTOCOL_SENSOR,
							  SENSOR_UPDATE,
							  &sensor_id,
							  &sensor_update_nb);
	if (ret)
		pr_err("Error registering notifier for evt:%d", 0x1);

	/*
	 * As an additional remark about registering notifiers note that
	 * you can also register you notifier for a specific event BUT
	 * at the same time not specifying a specific sensor (leaving above
	 * sensor_id == NULL) you'll end-up receiving all the notifications
	 * for that event BUT coming from all existent sensors on the system.
	 */

	/* PLUS ALL YOUR IIO SPECIFIC INIT AND REGISTRATIONS DOWN HERE ... */

	return 0;
}

static void scmi_iiodev_remove(struct scmi_device *sdev)
{
	u32 sensor_id = 0;
	const struct scmi_handle *handle = sdev->handle;

	/*
	 * You want to unregister your notifiers here
	 *
	 * like:
	 *
	 * handle->notify_ops->unregister_event_notifier(handle,
	 *						 SCMI_PROTOCOL_SENSOR,
	 *						 evt_id,
	 *						 &sensor_id,
	 *						 &sensor_trip_nb);
	 */

	handle->notify_ops->unregister_event_notifier(handle,
						SCMI_PROTOCOL_SENSOR,
						SENSOR_TRIP_POINT_EVENT,
						&sensor_id,
						&sensor_trip_nb);

	 handle->notify_ops->unregister_event_notifier(handle,
						  SCMI_PROTOCOL_SENSOR,
						  SENSOR_UPDATE,
						  &sensor_id,
						  &sensor_update_nb);
	return;
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_SENSOR, "iiodev" },
	{ },
};
MODULE_DEVICE_TABLE(scmi, scmi_id_table);

static struct scmi_driver scmi_iiodev_driver = {
	.name = "scmi-sensor-iiodev",
	.probe = scmi_iiodev_probe,
	.remove = scmi_iiodev_remove,
	.id_table = scmi_id_table,
};
module_scmi_driver(scmi_iiodev_driver);

MODULE_LICENSE("GPL v2");
