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

#define NSEC_MULT_POW_10 (const_ilog2(NSEC_PER_SEC) / const_ilog2(10))
#define COMBINE_32_TO_64(x, y) (((x) << 32) | (y))
#define UHZ_PER_HZ 1000000UL
#define ODR_EXPAND(odr, uodr) (((odr)*1000000ULL) + (uodr))

//one additional channel for timestamp
#define SCMI_IIO_EXTRA_CHANNELS 1

struct scmi_iio_priv {
	struct scmi_handle *handle;
	const struct scmi_sensor_info *sensor_info;
	u8 *iio_buf;
	struct notifier_block sensor_update_nb;
};

struct sensor_freq {
	u64 hz;
	u64 uhz;
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
	struct scmi_iio_priv *sensor =
		container_of(nb, struct scmi_iio_priv, sensor_update_nb);
	struct iio_dev *scmi_iio_dev;
	s8 tstamp_scale_ns;
	int i, err;

	err = scmi_iio_check_valid_sensor(sensor);

	if (err)
		return err;

	scmi_iio_dev = iio_priv_to_dev(sensor);

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

	err = sensor->handle->notify_ops->register_event_notifier(
		sensor->handle, SCMI_PROTOCOL_SENSOR, SCMI_EVENT_SENSOR_UPDATE,
		&sensor_id, &sensor->sensor_update_nb);

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

	err = sensor->handle->notify_ops->unregister_event_notifier(
		sensor->handle, SCMI_PROTOCOL_SENSOR, SCMI_EVENT_SENSOR_UPDATE,
		&sensor_id, &sensor->sensor_update_nb);
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

static u64 convert_interval_to_ns(u32 interval)
{
	u64 sensor_update_interval, sensor_interval_mult;
	s8 mult;

	mult = SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_EXTEND(
		SCMI_SENSOR_GET_UPDATE_INTERVAL_MULT(interval));
	mult = abs(mult);
	sensor_interval_mult = int_pow(10, mult);
	sensor_update_interval =
		SCMI_SENSOR_GET_UPDATE_INTERVAL_SEC(interval) * NSEC_PER_SEC;
	if (interval & SCMI_SENSOR_UPDATE_INTERVAL_MULT_SIGN_MASK)
		sensor_update_interval =
			sensor_update_interval / sensor_interval_mult;
	else
		sensor_update_interval =
			sensor_update_interval * sensor_interval_mult;

	return sensor_update_interval;
}

static int convert_ns_to_freq(u64 interval_ns, struct sensor_freq *freq)
{
	u64 rem;

	if (!freq)
		return -EINVAL;

	freq->hz = div64_u64_rem(NSEC_PER_SEC, interval_ns, &rem);
	freq->uhz = (rem * 1000000UL) / interval_ns;

	return 0;
}

static ssize_t scmi_iio_sysfs_sampling_freq_avail(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	struct scmi_iio_priv *sensor = iio_priv(dev_get_drvdata(dev));
	int err = scmi_iio_check_valid_sensor(sensor);
	struct sensor_freq freq;
	u64 lowest_interval_ns, highest_interval_ns, cur_interval_ns,
		step_size_ns;
	int i, len = 0;

	if (err)
		return err;

	if (!sensor->sensor_info->intervals.segmented) {
		for (i = 0; i < sensor->sensor_info->intervals.count; i++) {
			cur_interval_ns = convert_interval_to_ns(
				sensor->sensor_info->intervals.desc[i]);
			err = convert_ns_to_freq(cur_interval_ns, &freq);
			if (err)
				return 0;
			len += scnprintf(buf + len, PAGE_SIZE - len,
					 "%llu.%06llu ", freq.hz, freq.uhz);
		}
	} else {
		// If the intervals are segmented, the intervals array is a triplet
		// which constitues a segment in the form of
		// [lowest_interval,highest_interval,step_size]
		if (sensor->sensor_info->intervals.count != 3) {
			printk(KERN_ERR
			       "SCMI sensor %s has segmented update intervals count %d which is not a triplet",
			       sensor->sensor_info->name,
			       sensor->sensor_info->intervals.count);
			return len;
		} else {
			lowest_interval_ns = convert_interval_to_ns(
				sensor->sensor_info->intervals.desc[0]);
			highest_interval_ns = convert_interval_to_ns(
				sensor->sensor_info->intervals.desc[1]);
			step_size_ns = convert_interval_to_ns(
				sensor->sensor_info->intervals.desc[2]);
			cur_interval_ns = lowest_interval_ns;
			while (cur_interval_ns <= highest_interval_ns) {
				err = convert_ns_to_freq(cur_interval_ns,
							 &freq);
				if (err)
					return 0;
				len += scnprintf(buf + len, PAGE_SIZE - len,
						 "%llu.%06llu ", freq.hz,
						 freq.uhz);
				cur_interval_ns += step_size_ns;
			}
		}
	}

	if (len > 0)
		buf[len - 1] = '\n';
	return len;
}

static int scmi_iio_set_odr_val(struct iio_dev *iio_dev, int val, int val2)
{
	struct scmi_iio_priv *sensor = iio_priv(iio_dev);
	int err = scmi_iio_check_valid_sensor(sensor);
	u32 sensor_config = 0, cur_sensor_config;
	u64 sec, mult, uHz;
	char buf[32];

	if (err)
		return err;

	err = sensor->handle->sensor_ops->config_get(
		sensor->handle, sensor->sensor_info->id, &cur_sensor_config);

	if (err) {
		printk(KERN_ERR
		       "scmi_iio_set_odr_val: Error in getting sensor config for sensor %s err %d",
		       sensor->sensor_info->name, err);
		return err;
	}

	uHz = ODR_EXPAND(val, val2);

	// The seconds field in the sensor interval in SCMI is 16 bits long
	// Therefore seconds  = 1/Hz <= 0xFFFF. As floating point calculations are
	// discouraged in the kernel driver code, to calculate the scale factor (sf)
	// (1* 1000000 * sf)/uHz <= 0xFFFF. Therefore, sf <= (uHz * 0xFFFF)/1000000
	//  To calculate the multiplier,we convert the sf into char string  and
	//  count the number of characters

	mult = scnprintf(buf, 32, "%llu", ((u64)uHz * 0xFFFF) / UHZ_PER_HZ) - 1;

	sec = div64_u64(int_pow(10, mult) * UHZ_PER_HZ, uHz);
	if (sec == 0) {
		printk(KERN_ERR
		       "Trying to set invalid sensor update value for sensor %s",
		       sensor->sensor_info->name);
		return -EINVAL;
	}

	// Not able to use cur_sensor_config to build/modify the sensor config with
	// new configuration as the SCMI macros below doesn't clear the old values
	// and executes bitwise operations over them. Therefore, building new sensor config
	// from scratch.
	sensor_config = SCMI_SENSOR_CFG_SET_UPDATE_SECS(sensor_config, sec);
	sensor_config = SCMI_SENSOR_CFG_SET_UPDATE_MULTI(sensor_config, -mult);
	sensor_config = SCMI_SENSOR_CFG_SET_AUTO_ROUND_UP(sensor_config);
	if (sensor->sensor_info->timestamped)
		sensor_config =
			SCMI_SENSOR_CFG_SET_TSTAMP_ENABLED(sensor_config);
	if (SCMI_SENSOR_CFG_IS_ENABLED(cur_sensor_config))
		sensor_config = SCMI_SENSOR_CFG_SET_ENABLE(sensor_config);
	else
		sensor_config = SCMI_SENSOR_CFG_SET_DISABLE(sensor_config);

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

static ssize_t scmi_iio_get_sensor_max_range(struct device *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	struct scmi_iio_priv *sensor = iio_priv(dev_get_drvdata(dev));
	int err = scmi_iio_check_valid_sensor(sensor);
	int i;
	s64 max_range = S64_MIN, max_range_axis;

	if (err)
		return err;

	for (i = 0; i < sensor->sensor_info->num_axis; i++) {
		if (sensor->sensor_info->axis[i].extended_attrs) {
			max_range_axis = COMBINE_32_TO_64(
				(s64)sensor->sensor_info->axis[i]
					.attrs.max_range_high,
				sensor->sensor_info->axis[i]
					.attrs.max_range_low);
			max_range = max(max_range, max_range_axis);
		}
	}

	return scnprintf(buf, PAGE_SIZE, "%lld\n", max_range);
}

static ssize_t scmi_iio_get_sensor_resolution(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
{
	struct scmi_iio_priv *sensor = iio_priv(dev_get_drvdata(dev));
	bool scalar_sensor;
	int len = 0;
	int err = scmi_iio_check_valid_sensor(sensor);

	if (err)
		return err;

	err = scmi_iio_is_scalar_sensor(sensor->sensor_info, &scalar_sensor);
	if (err)
		return err;

	if (!scalar_sensor) {
		// All the axes are supposed to have the same value for resolution
		// and exponent. We are just using the values from the Axis 0 here.
		if (sensor->sensor_info->axis[0].extended_attrs) {
			u32 resolution =
				sensor->sensor_info->axis[0].resolution;
			s8 exponent = sensor->sensor_info->axis[0].exponent;
			u32 multiplier = int_pow(10, abs(exponent));
			if (exponent < 0) {
				int vals[] = { resolution, multiplier };
				len = iio_format_value(
					buf, IIO_VAL_FRACTIONAL,
					sizeof(vals) / sizeof(vals[0]), vals);
			} else {
				int vals[] = { resolution * multiplier };
				len = iio_format_value(
					buf, IIO_VAL_INT,
					sizeof(vals) / sizeof(vals[0]), vals);
			}
		}
	}

	return len;
}

static IIO_DEV_ATTR_SAMP_FREQ_AVAIL(scmi_iio_sysfs_sampling_freq_avail);
static IIO_DEVICE_ATTR(sensor_power, S_IRUGO, scmi_iio_get_sensor_power, NULL,
		       0);
static IIO_DEVICE_ATTR(sensor_max_range, S_IRUGO, scmi_iio_get_sensor_max_range,
		       NULL, 0);
static IIO_DEVICE_ATTR(sensor_resolution, S_IRUGO,
		       scmi_iio_get_sensor_resolution, NULL, 0);

static struct attribute *scmi_iio_attributes[] = {
	&iio_dev_attr_sampling_frequency_available.dev_attr.attr,
	&iio_dev_attr_sensor_power.dev_attr.attr,
	&iio_dev_attr_sensor_max_range.dev_attr.attr,
	&iio_dev_attr_sensor_resolution.dev_attr.attr,
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
	sensor->sensor_update_nb.notifier_call = sensor_update_cb;
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

	if (sdev == NULL) {
		printk(KERN_ERR "scmi_iio_dev: missing SCMI device\n");
		return -ENODEV;
	}

	dev = &sdev->dev;

	handle = sdev->handle;
	if (!handle || !handle->sensor_ops) {
		dev_err(dev, "SCMI device has no sensor interface\n");
		return -EINVAL;
	}

	nr_sensors = handle->sensor_ops->count_get(handle);
	if (!nr_sensors) {
		dev_warn(dev, "0 sensors found via SCMI bus\n");
		return -EINVAL;
	} else {
		dev_info(dev, "%d sensors found via SCMI bus\n", nr_sensors);
	}

	for (i = 0; i < nr_sensors; i++) {
		sensor_info = handle->sensor_ops->info_get(handle, i);
		if (!sensor_info) {
			dev_err(dev, "SCMI sensor %d has missing info\n", i);
			return -EINVAL;
		}
		err = scmi_alloc_iiodev(dev, handle, sensor_info,
					&scmi_iio_dev);
		if (err < 0) {
			dev_err(dev,
				"memory allocation error at sensor %s: %d\n",
				sensor_info->name, err);
			return err;
		}
		if (!scmi_iio_dev) {
			dev_err(dev, "memory allocation failed at sensor %s\n",
				sensor_info->name);
			return -ENOMEM;
		}
		err = scmi_iio_buffers_setup(scmi_iio_dev);
		if (err < 0) {
			dev_err(dev,
				"IIO buffer setup error at sensor %s: %d\n",
				sensor_info->name, err);
			return err;
		}
		err = devm_iio_device_register(dev, scmi_iio_dev);
		if (err) {
			dev_err(dev,
				"IIO device registration failed at sensor %s: %d\n",
				sensor_info->name, err);
			return err;
		}
	}

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
