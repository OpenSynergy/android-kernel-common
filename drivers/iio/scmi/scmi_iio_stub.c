//SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface(SCMI) sensor protocol stub device
 *
 * Copyright (C) 2020 Google LLC
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>

#define NUM_OF_SENSORS 2
#define ACCEL_SENSOR_ID 0
#define GYRO_SENSOR_ID 1

//Initial stub sensor value for Accelerometer
static u64 accelval = 20;
//Initial stub sensor value for Gyroscope
static u64 gyroval = 300;

enum { SENSOR_TRIP_POINT_EVENT = 0x0,
       SENSOR_UPDATE = 0x1,
};

static int scmi_sensor_count_get(const struct scmi_handle *handle)
{
	return NUM_OF_SENSORS;
}

//Stub Sampling frequency available for the sensors
static u32 sampling_freq_avail[] = { 0x641C, 0x301C, 0x181C, 0xC1C, 0x61C,
				     0x31C,  0x19C,  0xDC,   0x7C,  0x12BA };

#define NUM_OF_SAMP_FREQ                                                       \
	sizeof(sampling_freq_avail) / sizeof(sampling_freq_avail[0])

//Stub Values for Accel Axis
static struct scmi_sensor_axis_info accel_axis_info[] = {
	{
		.id = 0,
		.type = METERS_SEC_SQUARED,
		.name = "X",
		.scale = -4,
		.extended_attrs = false,
	},
	{
		.id = 1,
		.type = METERS_SEC_SQUARED,
		.name = "Y",
		.scale = -4,
		.extended_attrs = false,
	},
	{
		.id = 2,
		.type = METERS_SEC_SQUARED,
		.name = "Z",
		.scale = -4,
		.extended_attrs = false,
	}

};

//Stub values for Gyro axis
static struct scmi_sensor_axis_info gyro_axis_info[] = {
	{
		.id = 0,
		.type = RADIANS_SEC,
		.name = "X",
		.scale = -5,
		.extended_attrs = false,
	},
	{
		.id = 1,
		.type = RADIANS_SEC,
		.name = "Y",
		.scale = -5,
		.extended_attrs = false,
	},
	{
		.id = 2,
		.type = RADIANS_SEC,
		.name = "Z",
		.scale = -5,
		.extended_attrs = false,
	}

};

static struct scmi_sensor_info accel_info = {
	.id = ACCEL_SENSOR_ID,
	.type = METERS_SEC_SQUARED,
	.scale = 5,
	.async = true,
	.name = "scmi.iio.accel", 
	.num_trip_points = 0,
	.update = true,
	.timestamped = true,
	.tstamp_scale = -9,
	.num_axis = 3,
	.axis = accel_axis_info,
	.sensor_config = 0,
	.intervals.count = NUM_OF_SAMP_FREQ,
	.intervals.segmented = false,
	.intervals.desc = sampling_freq_avail,
	.extended_scalar_attrs = true,
	.sensor_power = 200

};
static struct scmi_sensor_info gyro_info = {
	.id = GYRO_SENSOR_ID,
	.type = RADIANS_SEC,
	.scale = 2,
	.async = true,
	.name = "scmi.iio.gyro",
	.num_trip_points = 0,
	.update = true,
	.timestamped = true,
	.tstamp_scale = -9,
	.num_axis = 3,
	.axis = gyro_axis_info,
	.sensor_config = 0,
	.intervals.count = NUM_OF_SAMP_FREQ,
	.intervals.segmented = false,
	.intervals.desc = sampling_freq_avail,
	.extended_scalar_attrs = true,
	.sensor_power = 300

};

struct blocking_notifier_head accel_chain;
struct blocking_notifier_head gyro_chain;
static struct hrtimer accel_timer;
static struct hrtimer gyro_timer;

static const struct scmi_sensor_info *
scmi_sensor_info_get(const struct scmi_handle *handle, u32 sensor_id)
{
	switch (sensor_id) {
	case ACCEL_SENSOR_ID:
		return &accel_info;
	case GYRO_SENSOR_ID:
		return &gyro_info;
	}
	return NULL;
}

struct scmi_sensor_update_report *accel_sensor_report;
struct scmi_sensor_update_report *gyro_sensor_report;

enum hrtimer_restart accel_timer_callback(struct hrtimer *timer_for_restart)
{
	ktime_t currtime = ktime_get();
	ktime_t interval = ktime_set(0, NSEC_PER_SEC);
	u64 currtime_ns = ktime_get_ns();
	int i;

	printk(KERN_INFO "\n scmi_sensor_reading_get accel  %lld\n", accelval);
	accelval++;
	accel_sensor_report->timestamp = 0;
	accel_sensor_report->agent_id = 1;
	accel_sensor_report->sensor_id = ACCEL_SENSOR_ID;
	accel_sensor_report->readings_count = accel_info.num_axis;
	for (i = 0; i < accel_sensor_report->readings_count; i++) {
		accel_sensor_report->readings[i].sensor_value_low =
			(accelval & 0xFFFFFFFF);
		accel_sensor_report->readings[i].sensor_value_high =
			(accelval & 0xFFFFFFFF00000000) >> 32;
		accel_sensor_report->readings[i].timestamp_low =
			currtime_ns & 0xFFFFFFFF;
		accel_sensor_report->readings[i].timestamp_high =
			(currtime_ns & 0xFFFFFFFF00000000) >> 32;
	}
	blocking_notifier_call_chain(&accel_chain, SENSOR_UPDATE,
				     (void *)(accel_sensor_report));
	hrtimer_forward(timer_for_restart, currtime, interval);
	return HRTIMER_RESTART;
}

enum hrtimer_restart gyro_timer_callback(struct hrtimer *timer_for_restart)
{
	ktime_t currtime = ktime_get();
	ktime_t interval = ktime_set(0, NSEC_PER_SEC);
	u64 currtime_ns = ktime_get_ns();
	int i;

	printk(KERN_INFO "\n scmi_sensor_reading_get gyro  %lld\n", gyroval);

	gyroval++;
	gyro_sensor_report->timestamp = 0;
	gyro_sensor_report->agent_id = 1;
	gyro_sensor_report->sensor_id = GYRO_SENSOR_ID;
	gyro_sensor_report->readings_count = gyro_info.num_axis;

	for (i = 0; i < gyro_sensor_report->readings_count; i++) {
		gyro_sensor_report->readings[i].sensor_value_low =
			(gyroval & 0xFFFFFFFF);
		gyro_sensor_report->readings[i].sensor_value_high =
			(gyroval & 0xFFFFFFFF00000000) >> 32;
		gyro_sensor_report->readings[i].timestamp_low =
			currtime_ns & 0xFFFFFFFF;
		gyro_sensor_report->readings[i].timestamp_high =
			(currtime_ns & 0xFFFFFFFF00000000) >> 32;
	}

	blocking_notifier_call_chain(&gyro_chain, SENSOR_UPDATE,
				     (void *)(gyro_sensor_report));
	hrtimer_forward(timer_for_restart, currtime, interval);
	return HRTIMER_RESTART;
}

static int scmi_register_notifier(const struct scmi_handle *handle, u8 proto_id,
				  u8 evt_id, u32 *src_id,
				  struct notifier_block *nb)
{
	switch (*src_id) {
	case ACCEL_SENSOR_ID:
		BLOCKING_INIT_NOTIFIER_HEAD(&accel_chain);
		blocking_notifier_chain_register(&accel_chain, nb);
		hrtimer_init(&accel_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		accel_timer.function = &accel_timer_callback;
		break;

	case GYRO_SENSOR_ID:
		BLOCKING_INIT_NOTIFIER_HEAD(&gyro_chain);
		blocking_notifier_chain_register(&gyro_chain, nb);
		hrtimer_init(&gyro_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		gyro_timer.function = &gyro_timer_callback;
		break;
	}
	return 0;
}
static int scmi_unregister_notifier(const struct scmi_handle *handle,
				    u8 proto_id, u8 evt_id, u32 *src_id,
				    struct notifier_block *nb)
{
	switch (*src_id) {
	case ACCEL_SENSOR_ID:
		blocking_notifier_chain_unregister(&accel_chain, nb);
		break;
	case GYRO_SENSOR_ID:
		blocking_notifier_chain_unregister(&gyro_chain, nb);
		break;
	}
	return 0;
}

static int scmi_sensor_config_get(const struct scmi_handle *handle,
				  u32 sensor_id, u32 *sensor_config)
{
	switch (sensor_id) {
	case ACCEL_SENSOR_ID:
		*sensor_config = accel_info.sensor_config;
		break;
	case GYRO_SENSOR_ID:
		*sensor_config = gyro_info.sensor_config;
		break;
	}
	return 0;
}

static int scmi_sensor_config_set(const struct scmi_handle *handle,
				  u32 sensor_id, u32 sensor_config)
{
	switch (sensor_id) {
	case ACCEL_SENSOR_ID:
		accel_info.sensor_config = sensor_config;
		if (SCMI_SENSOR_CFG_IS_ENABLED(sensor_config)) {
			ktime_t ktime = ktime_set(0, NSEC_PER_SEC);
			hrtimer_start(&accel_timer, ktime, HRTIMER_MODE_REL);
		} else {
			hrtimer_cancel(&accel_timer);
		}
		break;

	case GYRO_SENSOR_ID:
		gyro_info.sensor_config = sensor_config;
		if (SCMI_SENSOR_CFG_IS_ENABLED(sensor_config)) {
			ktime_t ktime = ktime_set(0, NSEC_PER_SEC);
			hrtimer_start(&gyro_timer, ktime, HRTIMER_MODE_REL);
		} else {
			hrtimer_cancel(&gyro_timer);
		}
		break;
	}

	return 0;
}

static struct scmi_sensor_ops sensor_ops = {
	.count_get = scmi_sensor_count_get,
	.info_get = scmi_sensor_info_get,
	.reading_get = NULL,
	.config_get = scmi_sensor_config_get,
	.config_set = scmi_sensor_config_set,

};
static struct scmi_notify_ops notify_ops = {
	.register_event_notifier = scmi_register_notifier,
	.unregister_event_notifier = scmi_unregister_notifier,
};

struct scmi_device *scmi_dev;

int scmi_stub_init(void)
{
	printk(KERN_INFO "scmi stub init.... \n");
	scmi_dev =
		scmi_device_create(NULL, NULL, SCMI_PROTOCOL_SENSOR, "iiodev");
	if (!scmi_dev) {
		printk(KERN_INFO "could not alloc memory for scmi device ..\n");
		return -ENOMEM;
	}
	scmi_dev->handle = kzalloc(sizeof(struct scmi_handle), GFP_KERNEL);
	if (!scmi_dev->handle) {
		printk(KERN_INFO "could not alloc memory for scmi handle ..\n");
		return -ENOMEM;
	}
	scmi_dev->handle->sensor_ops = &sensor_ops;
	scmi_dev->handle->notify_ops = &notify_ops;
	scmi_dev->handle->dev = &scmi_dev->dev;
	accel_sensor_report =
		devm_kzalloc(scmi_dev->handle->dev,
			     sizeof(struct scmi_sensor_update_report) +
				     accel_info.num_axis *
					     sizeof(struct scmi_sensor_reading),
			     GFP_KERNEL);
	gyro_sensor_report = devm_kzalloc(
		scmi_dev->handle->dev,
		sizeof(struct scmi_sensor_update_report) +
			gyro_info.num_axis * sizeof(struct scmi_sensor_reading),
		GFP_KERNEL);
	printk(KERN_INFO "Platform SCMI device registered.... \n");
	return 0;
}

void scmi_stub_exit(void)
{
	printk(KERN_INFO "scmi_stub_exit \n");
	if (scmi_dev)
		kfree(scmi_dev->handle);
}

module_init(scmi_stub_init);
module_exit(scmi_stub_exit);

MODULE_AUTHOR("Jyoti Bhayana <jbhayana@google.com>");
MODULE_DESCRIPTION("SCMI Sensor Stub Device");
MODULE_LICENSE("GPL v2");
