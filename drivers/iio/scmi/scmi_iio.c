// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface(SCMI) based IIO sensor driver
 *
 * Copyright (C) 2020 Google LLC
 */

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/iio/buffer.h>
#include <linux/iio/iio.h>
#include <linux/iio/kfifo_buf.h>
#include <linux/iio/sysfs.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/scmi_protocol.h>
#include <linux/time.h>
#include <linux/types.h>

#define SCMI_SENSOR_GET_UPDATE_INTERVAL_SEC(x) (((x) >> 5) & 0xFFFF)
#define SCMI_SENSOR_GET_UPDATE_INTERVAL_MULT(x) ((x)&0x1F)
#define SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_MASK BIT(4)
#define SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_EXTEND_MASK GENMASK(7, 5)
#define SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_EXTEND(x)                        \
	(((x)&SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_MASK) ?                    \
		 ((x) | SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_EXTEND_MASK) :   \
		 (x))

#define USEC_MULT_POW_10 (const_ilog2(USEC_PER_SEC) / const_ilog2(10))
#define NSEC_MULT_POW_10 (const_ilog2(NSEC_PER_SEC) / const_ilog2(10))
#define COMBINE_32_TO_64(x, y) (((x) << 32) | (y))

//one additional channel for timestamp
#define SCMI_IIO_EXTRA_CHANNELS 1

//TODO : (egranata,jbhayana) : Try to remove this global variable and move it to IIO private data
static struct iio_dev **iio_dev_arr;

struct scmi_iio_priv {
	struct scmi_handle *handle;
	const struct scmi_sensor_info *sensor_info;
	u8 *iio_buf;
};

static int scmi_iio_check_valid_sensor(struct scmi_iio_priv *sensor)
{
	if (!sensor || !sensor->handle || !sensor->sensor_info)
		return -EINVAL;
	else
		return 0;
}
static int sensor_update_cb(struct notifier_block *nb, unsigned long event,
			    void *data)
{
	struct scmi_sensor_update_report *sensor_update = data;
	u64 time, time_ns;
	s64 sensor_value;
	struct scmi_iio_priv *sensor;
	struct iio_dev *scmi_iio_dev = iio_dev_arr[sensor_update->sensor_id];
	s8 tstamp_scale_ns;
	int i, err;
	sensor = iio_priv(scmi_iio_dev);
	err = scmi_iio_check_valid_sensor(sensor);

	if (err)
		return err;

	for (i = 0; i < sensor_update->readings_count; i++) {
		sensor_value = COMBINE_32_TO_64(
			(s64)sensor_update->readings[i].sensor_value_high,
			sensor_update->readings[i].sensor_value_low);
		time = COMBINE_32_TO_64(
			(u64)sensor_update->readings[i].timestamp_high,
			sensor_update->readings[i].timestamp_low);
		memcpy(&sensor->iio_buf[i * sizeof(s64)], &sensor_value,
		       sizeof(s64));
	}

	if (!sensor->sensor_info->timestamped) {
		time_ns = iio_get_time_ns(scmi_iio_dev);
	} else {
		tstamp_scale_ns =
			sensor->sensor_info->tstamp_scale + NSEC_MULT_POW_10;
		if (tstamp_scale_ns < 0) {
			tstamp_scale_ns = -1 * tstamp_scale_ns;
			time_ns = div64_u64(time, int_pow(10, tstamp_scale_ns));
		} else {
			time_ns = time * int_pow(10, tstamp_scale_ns);
		}
	}

	iio_push_to_buffers_with_timestamp(scmi_iio_dev, sensor->iio_buf,
					   time_ns);

	return NOTIFY_OK;
}

static struct notifier_block sensor_update_nb = {
	.notifier_call = sensor_update_cb,
};
static int scmi_iio_is_scalar_sensor(const struct scmi_sensor_info *sensor_info,
				     bool *scalar)
{
	if (!sensor_info || !scalar)
		return -EINVAL;

	if (sensor_info->num_axis > 0)
		*scalar = false;
	else
		*scalar = true;

	return 0;
}

static int scmi_iio_buffer_preenable(struct iio_dev *dev)
{
	struct scmi_iio_priv *sensor = iio_priv(dev);
	u32 sensor_config = 0;
	int err = scmi_iio_check_valid_sensor(sensor);
	u32 sensor_id = sensor->sensor_info->id;

	if (err)
		return err;

	if (sensor->sensor_info->timestamped)
		sensor_config =
			SCMI_SENSOR_CFG_SET_TSTAMP_ENABLED(sensor_config);

	sensor_config = SCMI_SENSOR_CFG_SET_ENABLE(sensor_config);

	//TODO : (jbhayana) : Moved the register event notifier here instead of scmi_iio_dev_probe because of http://b/156036964
	// Check if this can be moved back to scmi_iio_dev_probe later
	err = sensor->handle->notify_ops->register_event_notifier(
		sensor->handle, SCMI_PROTOCOL_SENSOR, SCMI_EVENT_SENSOR_UPDATE, &sensor_id,
		&sensor_update_nb);

	if (err) {
		printk(KERN_ERR
		       "Error in registering sensor update notifier for sensor %s err %d",
		       sensor->sensor_info->name, err);
		return err;
	}
	err = sensor->handle->sensor_ops->config_set(
		sensor->handle, sensor->sensor_info->id, sensor_config);
	if (err)
		printk(KERN_ERR "Error in enabling sensor %s err %d",
		       sensor->sensor_info->name, err);

	return err;
}

static int scmi_iio_buffer_postdisable(struct iio_dev *iio_dev)
{
	struct scmi_iio_priv *sensor = iio_priv(iio_dev);
	u32 sensor_config = 0;
	int err = scmi_iio_check_valid_sensor(sensor);
	u32 sensor_id = sensor_id = sensor->sensor_info->id;

	if (err)
		return err;

	sensor_config = SCMI_SENSOR_CFG_SET_DISABLE(sensor_config);

	//TODO : (jbhayana) : Moved the unregister event notifier here instead of scmi_iio_dev_remove because of http://b/156036964
	// Check if this can be moved back to scmi_iio_dev_remove later

	err = sensor->handle->notify_ops->unregister_event_notifier(
		sensor->handle, SCMI_PROTOCOL_SENSOR, SCMI_EVENT_SENSOR_UPDATE, &sensor_id,
		&sensor_update_nb);
	if (err) {
		printk(KERN_ERR
		       "Error in unregistering sensor update notifier for sensor %s err %d",
		       sensor->sensor_info->name, err);
		return err;
	}

	err = sensor->handle->sensor_ops->config_set(
		sensor->handle, sensor->sensor_info->id, sensor_config);

	if (err)
		printk(KERN_ERR "Error in disabling sensor %s with err %d",
		       sensor->sensor_info->name, err);

	return err;
}

static ssize_t scmi_iio_sysfs_sampling_freq_avail(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	struct scmi_iio_priv *sensor = iio_priv(dev_get_drvdata(dev));
	int err = scmi_iio_check_valid_sensor(sensor);
	u64 sensor_update_interval, sensor_interval_mult, freq_hz, freq_uhz;
	int i, len = 0;
	s8 mult;

	if (err)
		return err;

	// TODO(jbhayana) : Add support for segmented intervals (b/155122344)
	if (!sensor->sensor_info->intervals.segmented) {
		for (i = 0; i < sensor->sensor_info->intervals.count; i++) {
			mult = SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_EXTEND(
				SCMI_SENSOR_GET_UPDATE_INTERVAL_MULT(
					sensor->sensor_info->intervals.desc[i]));
			mult = mult < 0 ? -mult : mult;
			sensor_interval_mult = int_pow(10, mult);
			sensor_update_interval =
				SCMI_SENSOR_GET_UPDATE_INTERVAL_SEC(
					sensor->sensor_info->intervals.desc[i]) *
				USEC_PER_SEC;
			if (sensor->sensor_info->intervals.desc[i] &
			    SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_MASK)
				sensor_update_interval =
					sensor_update_interval /
					sensor_interval_mult;
			else
				sensor_update_interval =
					sensor_update_interval *
					sensor_interval_mult;
			freq_hz = div64_u64_rem(USEC_PER_SEC,
						sensor_update_interval,
						&freq_uhz);
			len += scnprintf(buf + len, PAGE_SIZE - len,
					 "%llu.%llu ", freq_hz, freq_uhz);
		}
		buf[len - 1] = '\n';
	}

	return len;
}

static int scmi_iio_set_odr_val(struct iio_dev *iio_dev, int val, int val2)
{
	struct scmi_iio_priv *sensor = iio_priv(iio_dev);
	int err = scmi_iio_check_valid_sensor(sensor);
	u32 sensor_config = 0;
	u64 sec;

	if (err)
		return err;

	sec = div_u64(USEC_PER_SEC, val);

	if (sec == 0) {
		printk(KERN_ERR
		       "Trying to set invalid sensor update value for sensor %s",
		       sensor->sensor_info->name);
		return -EINVAL;
	}

	sensor_config = SCMI_SENSOR_CFG_SET_UPDATE_SECS(sensor_config, sec);
	sensor_config = SCMI_SENSOR_CFG_SET_UPDATE_MULTI(sensor_config,
							 -USEC_MULT_POW_10);
	sensor_config = SCMI_SENSOR_CFG_SET_AUTO_ROUND_UP(sensor_config);
	if (sensor->sensor_info->timestamped)
		sensor_config =
			SCMI_SENSOR_CFG_SET_TSTAMP_ENABLED(sensor_config);

	err = sensor->handle->sensor_ops->config_set(
		sensor->handle, sensor->sensor_info->id, sensor_config);

	if (err)
		printk(KERN_ERR
		       "Error in setting sensor update interval for sensor %s value %u err %d",
		       sensor->sensor_info->name, sensor_config, err);

	return err;
}

static int scmi_iio_write_raw(struct iio_dev *iio_dev,
			      struct iio_chan_spec const *chan, int val,
			      int val2, long mask)
{
	int err;

	mutex_lock(&iio_dev->mlock);
	switch (mask) {
	case IIO_CHAN_INFO_SAMP_FREQ:
		err = scmi_iio_set_odr_val(iio_dev, val, val2);
		break;
	default:
		err = -EINVAL;
		break;
	}
	mutex_unlock(&iio_dev->mlock);

	return err;
}

static int scmi_iio_read_raw(struct iio_dev *iio_dev,
			     struct iio_chan_spec const *ch, int *val,
			     int *val2, long mask)
{
	struct scmi_iio_priv *sensor = iio_priv(iio_dev);
	int ret = scmi_iio_check_valid_sensor(sensor);
	bool scalar_sensor;
	s8 scale;

	if (ret)
		return ret;

	switch (mask) {
	case IIO_CHAN_INFO_SCALE:
		ret = scmi_iio_is_scalar_sensor(sensor->sensor_info,
						&scalar_sensor);
		if (ret)
			return ret;
		if (!scalar_sensor) {
			if (ch == NULL)
				return -EINVAL;
			scale = sensor->sensor_info->axis[ch->scan_index].scale;
			if (scale < 0) {
				scale = -scale;
				*val = 1;
				*val2 = int_pow(10, scale);
				ret = IIO_VAL_FRACTIONAL;
			} else {
				*val = int_pow(10, scale);
				ret = IIO_VAL_INT;
			}
		} else {
			ret = -EINVAL;
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static ssize_t scmi_iio_get_sensor_power(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct scmi_iio_priv *sensor = iio_priv(dev_get_drvdata(dev));
	int err = scmi_iio_check_valid_sensor(sensor);
	int len = 0;

	if (err)
		return err;

	if (sensor->sensor_info->extended_scalar_attrs)
		len = scnprintf(buf, PAGE_SIZE, "%u\n",
				sensor->sensor_info->sensor_power);

	return len;
}

static IIO_DEV_ATTR_SAMP_FREQ_AVAIL(scmi_iio_sysfs_sampling_freq_avail);
static IIO_DEVICE_ATTR(sensor_power, 0440, scmi_iio_get_sensor_power, NULL, 0);

// TODO(jbhayana) : Add support for sensor_max_range attribute (b/155129166)
static struct attribute *scmi_iio_attributes[] = {
	&iio_dev_attr_sampling_frequency_available.dev_attr.attr,
	&iio_dev_attr_sensor_power.dev_attr.attr,
	NULL,
};
static const struct attribute_group scmi_iio_attribute_group = {
	.attrs = scmi_iio_attributes,
};

static const struct iio_info scmi_iio_info = {
	.read_raw = scmi_iio_read_raw,
	.write_raw = scmi_iio_write_raw,
	.attrs = &scmi_iio_attribute_group,
};

static const struct iio_buffer_setup_ops scmi_iio_buffer_ops = {
	.preenable = scmi_iio_buffer_preenable,
	.postdisable = scmi_iio_buffer_postdisable,
};

static int scmi_iio_get_chan_type(u8 scmi_type, enum iio_chan_type *iio_type)
{
	int ret = 0;

	if (iio_type == NULL)
		return -EINVAL;

	switch (scmi_type) {
	case METERS_SEC_SQUARED:
		*iio_type = IIO_ACCEL;
		break;
	case RADIANS_SEC:
		*iio_type = IIO_ANGL_VEL;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int scmi_iio_get_chan_modifier(const char *name,
				      enum iio_modifier *modifier)
{
	int ret = 0;

	if ((name == NULL) || (modifier == NULL))
		return -EINVAL;

	if (strcasecmp(name, "X") == 0)
		*modifier = IIO_MOD_X;
	else if (strcasecmp(name, "Y") == 0)
		*modifier = IIO_MOD_Y;
	else if (strcasecmp(name, "Z") == 0)
		*modifier = IIO_MOD_Z;
	else
		ret = -EINVAL;

	return ret;
}
static void scmi_iio_set_data_channel(struct iio_chan_spec *iio_chan,
				      enum iio_chan_type type,
				      enum iio_modifier mod, int scan_index)
{
	if (iio_chan == NULL)
		return;

	iio_chan->type = type;
	iio_chan->modified = 1;
	iio_chan->channel2 = mod;
	iio_chan->info_mask_separate =
		BIT(IIO_CHAN_INFO_RAW) | BIT(IIO_CHAN_INFO_SCALE);
	iio_chan->info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SAMP_FREQ);
	iio_chan->scan_index = scan_index;
	iio_chan->scan_type.sign = 's';
	iio_chan->scan_type.realbits = 64;
	iio_chan->scan_type.storagebits = 64;
	iio_chan->scan_type.endianness = IIO_LE;
}

static void scmi_iio_set_timestamp_channel(struct iio_chan_spec *iio_chan,
					   int scan_index)
{
	if (iio_chan == NULL)
		return;

	iio_chan->type = IIO_TIMESTAMP;
	iio_chan->channel = -1;
	iio_chan->scan_index = scan_index;
	iio_chan->scan_type.sign = 'u';
	iio_chan->scan_type.realbits = 64;
	iio_chan->scan_type.storagebits = 64;
}

static int
scmi_iio_alloc_nonscalar_sensor(struct device *dev, struct scmi_handle *handle,
				const struct scmi_sensor_info *sensor_info,
				struct iio_dev **scmi_iio_dev)
{
	struct scmi_iio_priv *sensor;
	struct iio_chan_spec *iio_channels;
	enum iio_chan_type type;
	enum iio_modifier modifier;
	struct iio_dev *iio_dev_temp;
	int i, ret = 0;

	if (!scmi_iio_dev)
		return -EINVAL;

	iio_dev_temp = devm_iio_device_alloc(dev, sizeof(struct scmi_iio_priv));
	if (!iio_dev_temp)
		return -ENOMEM;
	iio_dev_temp->modes = INDIO_DIRECT_MODE;
	iio_dev_temp->dev.parent = dev;
	sensor = iio_priv(iio_dev_temp);
	sensor->handle = handle;
	sensor->sensor_info = sensor_info;
	iio_dev_temp->num_channels =
		sensor_info->num_axis + SCMI_IIO_EXTRA_CHANNELS;
	iio_dev_temp->name = sensor_info->name;
	iio_dev_temp->info = &scmi_iio_info;
	iio_channels = devm_kzalloc(dev,
				    sizeof(struct iio_chan_spec) *
					    (iio_dev_temp->num_channels),
				    GFP_KERNEL);
	if (!iio_channels)
		return -ENOMEM;
	for (i = 0; i < sensor_info->num_axis; i++) {
		ret = scmi_iio_get_chan_type(sensor_info->axis[i].type, &type);
		if (ret < 0)
			return ret;
		ret = scmi_iio_get_chan_modifier(sensor_info->axis[i].name,
						 &modifier);
		if (ret < 0)
			return ret;
		scmi_iio_set_data_channel(&iio_channels[i], type, modifier,
					  sensor_info->axis[i].id);
	}
	scmi_iio_set_timestamp_channel(&iio_channels[i], i);
	iio_dev_temp->channels = iio_channels;
	iio_dev_arr[sensor_info->id] = iio_dev_temp;
	*scmi_iio_dev = iio_dev_temp;
	return ret;
}

static int scmi_alloc_iiodev(struct device *dev, struct scmi_handle *handle,
			     const struct scmi_sensor_info *sensor_info,
			     struct iio_dev **scmi_iio_dev)
{
	int ret = 0;
	bool scalar_sensor;

	ret = scmi_iio_is_scalar_sensor(sensor_info, &scalar_sensor);

	if (ret)
		return ret;

	if (!scalar_sensor)
		ret = scmi_iio_alloc_nonscalar_sensor(dev, handle, sensor_info,
						      scmi_iio_dev);
	else
		ret = -EINVAL;

	return ret;
}

static int scmi_iio_buffers_setup(struct iio_dev *scmi_iiodev)
{
	struct iio_buffer *buffer = devm_iio_kfifo_allocate(&scmi_iiodev->dev);
	struct scmi_iio_priv *sensor = iio_priv(scmi_iiodev);
	int err = scmi_iio_check_valid_sensor(sensor);

	if (!buffer)
		return -ENOMEM;

	if (err)
		return err;

	iio_device_attach_buffer(scmi_iiodev, buffer);
	scmi_iiodev->modes |= INDIO_BUFFER_SOFTWARE;
	scmi_iiodev->setup_ops = &scmi_iio_buffer_ops;
	sensor->iio_buf =
		devm_kzalloc(&scmi_iiodev->dev,
			     sizeof(s64) * (scmi_iiodev->num_channels),
			     GFP_KERNEL);
	if (!sensor->iio_buf)
		return -ENOMEM;
	return 0;
}

static int scmi_iio_dev_probe(struct scmi_device *sdev)
{
	struct scmi_handle *handle;
	u16 nr_sensors;
	struct iio_dev *scmi_iio_dev;
	const struct scmi_sensor_info *sensor_info;
	int err = 0, i;
	struct device *dev;

	printk(KERN_DEBUG "scmi_iio_drv_probe enter\n");

	if (sdev == NULL)
		return -ENODEV;

	handle = sdev->handle;
	if (!handle || !handle->sensor_ops)
		return -EINVAL;

	nr_sensors = handle->sensor_ops->count_get(handle);
	if (!nr_sensors) {
		printk(KERN_ERR "No sensors found via SCMI bus");
		return -EINVAL;
	}

	printk(KERN_INFO "%d sensors found via SCMI bus", nr_sensors);

	iio_dev_arr = devm_kzalloc(
		handle->dev, sizeof(struct iiodev *) * nr_sensors, GFP_KERNEL);
	if (!iio_dev_arr)
		return -ENOMEM;
	dev = &sdev->dev;
	for (i = 0; i < nr_sensors; i++) {
		sensor_info = handle->sensor_ops->info_get(handle, i);
		if (!sensor_info)
			return -EINVAL;
		err = scmi_alloc_iiodev(dev, handle, sensor_info,
					&scmi_iio_dev);
		if (err < 0)
			return err;
		if (!scmi_iio_dev)
			return -ENOMEM;
		err = scmi_iio_buffers_setup(scmi_iio_dev);
		if (err < 0)
			return err;
		err = devm_iio_device_register(dev, scmi_iio_dev);
		if (err)
			return err;
	}

	printk(KERN_DEBUG "scmi_iio_dev_probe successful\n");

	return err;
}

static void scmi_iio_dev_remove(struct scmi_device *sdev)
{
	printk(KERN_DEBUG "scmi_iio_drv_remove\n");
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_SENSOR, "iiodev" },
	{},
};

MODULE_DEVICE_TABLE(scmi, scmi_id_table);

static struct scmi_driver scmi_iiodev_driver = {
	.name = "scmi-sensor-iiodev",
	.probe = scmi_iio_dev_probe,
	.remove = scmi_iio_dev_remove,
	.id_table = scmi_id_table,
};

module_scmi_driver(scmi_iiodev_driver);

MODULE_AUTHOR("Jyoti Bhayana <jbhayana@google.com>");
MODULE_DESCRIPTION("SCMI IIO Driver");
MODULE_LICENSE("GPL v2");
