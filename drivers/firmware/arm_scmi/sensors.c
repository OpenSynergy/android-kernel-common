// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Sensor Protocol
 *
 * Copyright (C) 2018-2020 ARM Ltd.
 */

#include "common.h"
#include "notify.h"

#define SCMI_MAX_NUM_SENSOR_AXIS	64

enum scmi_sensor_protocol_cmd {
	SENSOR_DESCRIPTION_GET = 0x3,
	SENSOR_TRIP_POINT_NOTIFY = 0x4,
	SENSOR_TRIP_POINT_CONFIG = 0x5,
	SENSOR_READING_GET = 0x6,
	SENSOR_AXIS_DESCRIPTION_GET = 0x7,
	SENSOR_LIST_UPDATE_INTERVALS = 0x8,
	SENSOR_CONFIG_GET = 0x9,
	SENSOR_CONFIG_SET = 0xA,
	SENSOR_CONTINUOUS_UPDATE_NOTIFY = 0xB,
};

enum scmi_sensor_protocol_notify {
	SENSOR_TRIP_POINT_EVENT = 0x0,
	SENSOR_UPDATE = 0x1,
};

struct scmi_msg_resp_sensor_attributes {
	__le16 num_sensors;
	u8 max_requests;
	u8 reserved;
	__le32 reg_addr_low;
	__le32 reg_addr_high;
	__le32 reg_size;
};

/* v21 attributes_low macros */
#define SUPPORTS_UPDATE_NOTIFY(x)	((x) & BIT(30))
#define SENSOR_MULTI(x)			(((x) >> 10) & 0x1f)
#define SUPPORTS_TIMESTAMP(x)		((x) & BIT(9))
#define SUPPORTS_EXTEND_ATTRS(x)	((x) & BIT(8))

/* v2 attributes_high macros */
#define SENSOR_UPDATE_BASE(x)		(((x) >> 27) & 0x1f)
#define SENSOR_UPDATE_SCALE(x)		(((x) >> 22) & 0x1f)

/* v21 attributes_high macros */
#define SENSOR_AXIS_NUMBER(x)		(((x) >> 16) & 0x3f)
#define SUPPORTS_AXIS(x)		((x) & BIT(8))

struct scmi_extended_attrs_le {
	__le32 min_range_low;
	__le32 min_range_high;
	__le32 max_range_low;
	__le32 max_range_high;
};

/* Whole struct is naturally packed */
struct scmi_msg_resp_sensor_description {
	__le16 num_returned;
	__le16 num_remaining;
	struct scmi_sensor_descriptor {
		__le32 id;
		__le32 attributes_low;
/* Common attributes_low macros */
#define SUPPORTS_ASYNC_READ(x)		((x) & BIT(31))
#define NUM_TRIP_POINTS(x)		((x) & 0xff)
		__le32 attributes_high;
/* Common attributes_high macros */
#define SENSOR_SCALE(x)			(((x) >> 11) & 0x1f)
#define SENSOR_SCALE_SIGN		BIT(4)
#define SENSOR_SCALE_EXTEND		GENMASK(7, 5)
#define SENSOR_TYPE(x)			((x) & 0xff)
		u8 name[SCMI_MAX_STR_SIZE];
		/* only for version > 2.0 */
		__le32 power;
		struct scmi_extended_attrs_le scalar_attrs;
	} desc[0];
};

/* Sign extend to a full s8 */
#define	S8_EXT(v)							\
	(((v) & SENSOR_SCALE_SIGN) ? ((v) | SENSOR_SCALE_EXTEND) : (v))

#define SCMI_MSG_RESP_SENS_DESCR_MAX_SZ					\
	(sizeof(struct scmi_sensor_descriptor) -			\
	  sizeof(__le32) - sizeof(struct scmi_extended_attrs_le))

struct scmi_msg_sensor_axis_description_get {
	__le32 id;
	__le32 axis_desc_index;
};

struct scmi_msg_resp_sensor_axis_description {
	__le32 num_axis_flags;
#define NUM_AXIS_RETURNED(x)		((x) & 0x3f)
#define NUM_AXIS_REMAINING(x)		(((x) >> 26) & 0x3f)
	struct scmi_axis_descriptor {
		__le32 id;
		__le32 attributes_low;
		__le32 attributes_high;
		u8 name[SCMI_MAX_STR_SIZE];
		struct scmi_extended_attrs_le attrs;
	} desc[0];
};

#define SCMI_MSG_RESP_AXIS_DESCR_MAX_SZ					\
		(sizeof(struct scmi_axis_descriptor) -			\
		 sizeof(struct scmi_extended_attrs_le))

struct scmi_msg_sensor_list_update_intervals {
	__le32 id;
	__le32 index;
};

struct scmi_msg_resp_sensor_list_update_intervals {
	__le32 num_intervals_flags;
#define NUM_INTERVALS_RETURNED(x)	((x) & 0xfff)
#define SEGMENTED_INTVL_FORMAT(x)	((x) & BIT(12))
#define NUM_INTERVALS_REMAINING(x)	(((x) >> 16) & 0xffff)
	__le32 intervals[0];
};

struct scmi_msg_sensor_request_notify {
	__le32 id;
	__le32 event_control;
#define SENSOR_NOTIFY_ALL	BIT(0)
};

struct scmi_msg_set_sensor_trip_point {
	__le32 id;
	__le32 event_control;
#define SENSOR_TP_EVENT_MASK	(0x3)
#define SENSOR_TP_DISABLED	0x0
#define SENSOR_TP_POSITIVE	0x1
#define SENSOR_TP_NEGATIVE	0x2
#define SENSOR_TP_BOTH		0x3
#define SENSOR_TP_ID(x)		(((x) & 0xff) << 4)
	__le32 value_low;
	__le32 value_high;
};

struct scmi_msg_sensor_config_get {
	__le32 id;
};

struct scmi_resp_sensor_config_get {
	__le32 sensor_config;
};

struct scmi_msg_sensor_config_set {
	__le32 id;
	__le32 sensor_config;
};

struct scmi_msg_sensor_reading_get {
	__le32 id;
	__le32 flags;
#define SENSOR_READ_ASYNC	BIT(0)
};

struct scmi_resp_sensor_reading_get {
	__le64 readings;
};

struct scmi_resp_sensor_reading_complete {
	__le32 id;
	__le64 readings;
};

struct scmi_sensor_reading_le {
	__le32 sensor_value_low;
	__le32 sensor_value_high;
	__le32 timestamp_low;
	__le32 timestamp_high;
};

struct scmi_resp_sensor_reading_get_v21{
	struct scmi_sensor_reading_le readings[0];
};

struct scmi_resp_sensor_reading_complete_v21{
	__le32 id;
	struct scmi_sensor_reading_le readings[0];
};

struct scmi_sensor_trip_notify_payld {
	__le32 agent_id;
	__le32 sensor_id;
	__le32 trip_point_desc;
};

struct scmi_msg_sensor_continuous_update_notify {
	__le32 id;
	__le32 event_control;
};

struct scmi_sensor_update_notify_payld {
	__le32 agent_id;
	__le32 sensor_id;
	struct scmi_sensor_reading_le readings[0];
};

struct sensors_info {
	u32 version;
	int num_sensors;
	int max_requests;
	u64 reg_addr;
	u32 reg_size;
	struct scmi_sensor_info *sensors;
};

static u32 single_interval_info;

static int scmi_sensor_attributes_get(const struct scmi_handle *handle,
				      struct sensors_info *si)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_resp_sensor_attributes *attr;

	ret = scmi_xfer_get_init(handle, PROTOCOL_ATTRIBUTES,
				 SCMI_PROTOCOL_SENSOR, 0, sizeof(*attr), &t);
	if (ret)
		return ret;

	attr = t->rx.buf;

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		si->num_sensors = le16_to_cpu(attr->num_sensors);
		si->max_requests = attr->max_requests;
		si->reg_addr = le32_to_cpu(attr->reg_addr_low) |
				(u64)le32_to_cpu(attr->reg_addr_high) << 32;
		si->reg_size = le32_to_cpu(attr->reg_size);
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static void inline scmi_parse_ext_attrs(struct scmi_extended_attrs *out,
					struct scmi_extended_attrs_le *in)
{
	out->min_range_low = le32_to_cpu(in->min_range_low);
	out->min_range_high = le32_to_cpu(in->min_range_high);
	out->max_range_low = le32_to_cpu(in->max_range_low);
	out->max_range_high = le32_to_cpu(in->max_range_high);
}

static int scmi_sensor_update_intervals(const struct scmi_handle *handle,
					struct scmi_sensor_info *s)
{
	int ret, cnt;
	u32 desc_index = 0;
	u16 num_returned, num_remaining;
	struct scmi_xfer *ti;
	struct scmi_msg_resp_sensor_list_update_intervals *buf;
	struct scmi_msg_sensor_list_update_intervals *msg;

	ret = scmi_xfer_get_init(handle, SENSOR_LIST_UPDATE_INTERVALS,
				 SCMI_PROTOCOL_SENSOR, sizeof(*msg), 0, &ti);
	if (ret)
		return ret;

	buf = ti->rx.buf;
	do {
		u32 flags;

		msg = ti->tx.buf;
		/* Set the number of sensors to be skipped/already read */
		msg->id = cpu_to_le32(s->id);
		msg->index = cpu_to_le32(desc_index);

		ret = scmi_do_xfer(handle, ti);
		if (ret)
			break;

		flags = le32_to_cpu(buf->num_intervals_flags);
		num_returned = NUM_INTERVALS_RETURNED(flags);
		num_remaining = NUM_INTERVALS_REMAINING(flags);

		/*
		 * Max intervals is not declared previously anywhere so we
		 * assume it's returned+remaining.
		 */
		if (unlikely(!s->intervals.count)) {
			s->intervals.count = num_returned + num_remaining;
			s->intervals.desc = devm_kcalloc(handle->dev,
							 s->intervals.count,
						sizeof(*s->intervals.desc),
								 GFP_KERNEL);
			if (!s->intervals.desc) {
				s->intervals.count = 0;
				ret = -ENOMEM;
				break;
			}
			s->intervals.segmented = SEGMENTED_INTVL_FORMAT(flags);
		} else if (desc_index + num_returned > s->intervals.count) {
			dev_err(handle->dev,
				"No. of update intervals can't exceed %d",
				s->intervals.count);
			ret = -EINVAL;
			break;
		}

		for (cnt = 0; cnt < num_returned; cnt++)
			s->intervals.desc[desc_index + cnt] =
					le32_to_cpu(buf->intervals[cnt]);

		desc_index += num_returned;
		/*
		 * check for both returned and remaining to avoid infinite
		 * loop due to buggy firmware
		 */
	} while (num_returned && num_remaining);

	scmi_xfer_put(handle, ti);
	return ret;
}

static int scmi_sensor_axis_description(const struct scmi_handle *handle,
					struct scmi_sensor_info *s)
{
	int ret, cnt;
	u32 desc_index = 0;
	u16 num_returned, num_remaining;
	struct scmi_xfer *te;
	struct scmi_msg_resp_sensor_axis_description *buf;
	struct scmi_msg_sensor_axis_description_get *msg;

	s->axis = devm_kcalloc(handle->dev, s->num_axis,
			       sizeof(*s->axis), GFP_KERNEL);
	if (!s->axis)
		return -ENOMEM;

	ret = scmi_xfer_get_init(handle, SENSOR_AXIS_DESCRIPTION_GET,
				 SCMI_PROTOCOL_SENSOR, sizeof(*msg), 0, &te);
	if (ret)
		return ret;

	buf = te->rx.buf;
	do {
		u32 flags;
		struct scmi_axis_descriptor *adesc;

		msg = te->tx.buf;
		/* Set the number of sensors to be skipped/already read */
		msg->id = cpu_to_le32(s->id);
		msg->axis_desc_index = cpu_to_le32(desc_index);

		ret = scmi_do_xfer(handle, te);
		if (ret)
			break;

		flags = le32_to_cpu(buf->num_axis_flags);
		num_returned = NUM_AXIS_RETURNED(flags);
		num_remaining = NUM_AXIS_REMAINING(flags);

		if (desc_index + num_returned > s->num_axis) {
			dev_err(handle->dev, "No. of axis can't exceed %d",
				s->num_axis);
			break;
		}

		adesc = &buf->desc[0];
		for (cnt = 0; cnt < num_returned; cnt++) {
			u32 attrh, attrl;
			struct scmi_sensor_axis_info *a;
			size_t dsize = SCMI_MSG_RESP_AXIS_DESCR_MAX_SZ;

			attrl = le32_to_cpu(adesc->attributes_low);

			a = &s->axis[desc_index + cnt];

			a->id = le32_to_cpu(adesc->id);
			a->extended_attrs = SUPPORTS_EXTEND_ATTRS(attrl);

			attrh = le32_to_cpu(adesc->attributes_high);
			a->scale = S8_EXT(SENSOR_SCALE(attrh));
			a->type = SENSOR_TYPE(attrh);
			strlcpy(a->name, adesc->name, SCMI_MAX_STR_SIZE);

			if (a->extended_attrs) {
				scmi_parse_ext_attrs(&a->attrs, &adesc->attrs);
				dsize += sizeof(adesc->attrs);
			}

			adesc = (typeof(adesc))((u8 *)adesc + dsize);
		}

		desc_index += num_returned;
		/*
		 * check for both returned and remaining to avoid infinite
		 * loop due to buggy firmware
		 */
	} while (num_returned && num_remaining);

	scmi_xfer_put(handle, te);
	return ret;
}


static int scmi_sensor_description_get(const struct scmi_handle *handle,
				       struct sensors_info *si)
{
	int ret, cnt;
	u32 desc_index = 0;
	u16 num_returned, num_remaining;
	struct scmi_xfer *t;
	struct scmi_msg_resp_sensor_description *buf;

	ret = scmi_xfer_get_init(handle, SENSOR_DESCRIPTION_GET,
				 SCMI_PROTOCOL_SENSOR, sizeof(__le32), 0, &t);
	if (ret)
		return ret;

	buf = t->rx.buf;

	do {
		struct scmi_sensor_descriptor *sdesc;

		/* Set the number of sensors to be skipped/already read */
		put_unaligned_le32(desc_index, t->tx.buf);
		ret = scmi_do_xfer(handle, t);
		if (ret)
			break;

		num_returned = le16_to_cpu(buf->num_returned);
		num_remaining = le16_to_cpu(buf->num_remaining);

		if (desc_index + num_returned > si->num_sensors) {
			dev_err(handle->dev, "No. of sensors can't exceed %d",
				si->num_sensors);
			break;
		}

		sdesc = &buf->desc[0];
		for (cnt = 0; cnt < num_returned; cnt++) {
			u32 attrh, attrl;
			struct scmi_sensor_info *s;
			size_t dsize = SCMI_MSG_RESP_SENS_DESCR_MAX_SZ;

			s = &si->sensors[desc_index + cnt];
			s->id = le32_to_cpu(sdesc->id);

			attrl = le32_to_cpu(sdesc->attributes_low);
			/* common bitfields parsing */
			s->async = SUPPORTS_ASYNC_READ(attrl);
			s->num_trip_points = NUM_TRIP_POINTS(attrl);
			/**
			 * only v2.1 specific bitfield below.
			 * Such bitfields are assumed to be zeroed on non
			 * relevant fw versions...assuming fw not buggy !
			 */
			s->update = SUPPORTS_UPDATE_NOTIFY(attrl);
			s->timestamped = SUPPORTS_TIMESTAMP(attrl);
			if (s->timestamped)
				s->tstamp_scale = S8_EXT(SENSOR_MULTI(attrl));
			s->extended_scalar_attrs =
				SUPPORTS_EXTEND_ATTRS(attrl);

			attrh = le32_to_cpu(sdesc->attributes_high);
			/* common bitfields parsing */
			s->scale = S8_EXT(SENSOR_SCALE(attrh));
			s->type = SENSOR_TYPE(attrh);
			if (si->version == 0x10000) {
				/* Bitfield 31:22 is only used in v2.0 */
				s->intervals.segmented = false;
				s->intervals.count = 1;
				/* using same u32 desc format as v2.1 */
				single_interval_info =
					(SENSOR_UPDATE_BASE(attrh) << 5) |
					 S8_EXT(SENSOR_UPDATE_SCALE(attrh));
				s->intervals.desc = &single_interval_info;
			} else {
				/*
				 * For version > v2.0 update intervals are
				 * retrieved via a dedicated command.
				 */
				ret = scmi_sensor_update_intervals(handle, s);
				if (ret)
					goto out;
			}
			/**
			 * only v2.1 specific bitfield below.
			 * Such bitfields are assumed to be zeroed on non
			 * relevant fw versions...assuming fw not buggy !
			 */
			s->num_axis = SUPPORTS_AXIS(attrh) ?
					SENSOR_AXIS_NUMBER(attrh) : 1;
			strlcpy(s->name, sdesc->name, SCMI_MAX_STR_SIZE);

			if (s->extended_scalar_attrs) {
				s->sensor_power = le32_to_cpu(sdesc->power);
				dsize += sizeof(sdesc->power);
				if (s->num_axis == 1) {
					scmi_parse_ext_attrs(&s->scalar_attrs,
							&sdesc->scalar_attrs);
					dsize += sizeof(sdesc->scalar_attrs);
				}
			}
			if (s->num_axis > 1) {
				ret = scmi_sensor_axis_description(handle, s);
				if (ret)
					goto out;
			}

			sdesc = (typeof(sdesc))((u8 *)sdesc + dsize);
		}

		desc_index += num_returned;

		scmi_reset_rx_to_maxsz(handle, t);
		/*
		 * check for both returned and remaining to avoid infinite
		 * loop due to buggy firmware
		 */
	} while (num_returned && num_remaining);

out:
	scmi_xfer_put(handle, t);
	return ret;
}

static inline int
scmi_sensor_request_notify(const struct scmi_handle *handle, u32 sensor_id,
			   u8 message_id, bool enable)
{
	int ret;
	u32 evt_cntl = enable ? SENSOR_NOTIFY_ALL : 0;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_request_notify *cfg;

	ret = scmi_xfer_get_init(handle, message_id,
				 SCMI_PROTOCOL_SENSOR, sizeof(*cfg), 0, &t);
	if (ret)
		return ret;

	cfg = t->tx.buf;
	cfg->id = cpu_to_le32(sensor_id);
	cfg->event_control = cpu_to_le32(evt_cntl);

	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_sensor_trip_point_notify(const struct scmi_handle *handle,
					 u32 sensor_id, bool enable)
{
	return scmi_sensor_request_notify(handle, sensor_id,
					  SENSOR_TRIP_POINT_NOTIFY,
					  enable);
}

static int
scmi_sensor_continuous_update_notify(const struct scmi_handle *handle,
				     u32 sensor_id, bool enable)
{
	return scmi_sensor_request_notify(handle, sensor_id,
					  SENSOR_CONTINUOUS_UPDATE_NOTIFY,
					  enable);
}

static int
scmi_sensor_trip_point_config(const struct scmi_handle *handle, u32 sensor_id,
			      u8 trip_id, u64 trip_value)
{
	int ret;
	u32 evt_cntl = SENSOR_TP_BOTH;
	struct scmi_xfer *t;
	struct scmi_msg_set_sensor_trip_point *trip;

	ret = scmi_xfer_get_init(handle, SENSOR_TRIP_POINT_CONFIG,
				 SCMI_PROTOCOL_SENSOR, sizeof(*trip), 0, &t);
	if (ret)
		return ret;

	trip = t->tx.buf;
	trip->id = cpu_to_le32(sensor_id);
	trip->event_control = cpu_to_le32(evt_cntl | SENSOR_TP_ID(trip_id));
	trip->value_low = cpu_to_le32(trip_value & 0xffffffff);
	trip->value_high = cpu_to_le32(trip_value >> 32);

	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_sensor_config_get(const struct scmi_handle *handle,
				  u32 sensor_id, u32 *sensor_config)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_config_get *msg;
	struct scmi_resp_sensor_config_get *resp;

	ret = scmi_xfer_get_init(handle, SENSOR_CONFIG_GET,
				 SCMI_PROTOCOL_SENSOR, sizeof(*msg),
				 sizeof(*resp), &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	msg->id = cpu_to_le32(sensor_id);
	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		struct sensors_info *si = handle->sensor_priv;
		struct scmi_sensor_info *s = si->sensors + sensor_id;

		resp = t->rx.buf;
		*sensor_config = le32_to_cpu(resp->sensor_config);
		s->sensor_config = *sensor_config;
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_sensor_config_set(const struct scmi_handle *handle,
				  u32 sensor_id, u32 sensor_config)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_config_set *msg;

	ret = scmi_xfer_get_init(handle, SENSOR_CONFIG_SET,
				 SCMI_PROTOCOL_SENSOR, sizeof(*msg), 0, &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	msg->id = cpu_to_le32(sensor_id);
	msg->sensor_config = cpu_to_le32(sensor_config);

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		struct sensors_info *si = handle->sensor_priv;
		struct scmi_sensor_info *s = si->sensors + sensor_id;

		s->sensor_config = sensor_config;
	}

	scmi_xfer_put(handle, t);
	return ret;
}

/**
 * scmi_sensor_reading_get  - Read scalar sensor value
 * @handle: Platform handle
 * @sensor_id: Sensor ID
 * @value: The 64bit value sensor reading
 *
 * This function returns a single 64 bit reading value representing the sensor
 * value; if the platform SCMI Protocol implementation and the sensor support
 * multiple axis and timestamped-reads, this just returns the first axis while
 * dropping the timestamp value.
 * Use instead the @scmi_sensor_reading_get_timestamped to retrieve the array of
 * timestamped multi-axis values.
 *
 * Return: 0 on Success
 */
static int scmi_sensor_reading_get(const struct scmi_handle *handle,
				   u32 sensor_id, u64 *value)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_reading_get *sensor;
	struct sensors_info *si = handle->sensor_priv;
	struct scmi_sensor_info *s = si->sensors + sensor_id;

	ret = scmi_xfer_get_init(handle, SENSOR_READING_GET,
				 SCMI_PROTOCOL_SENSOR, sizeof(*sensor),
				 sizeof(u64), &t);
	if (ret)
		return ret;

	sensor = t->tx.buf;
	sensor->id = cpu_to_le32(sensor_id);
	if (s->async) {
		sensor->flags = cpu_to_le32(SENSOR_READ_ASYNC);
		ret = scmi_do_xfer_with_response(handle, t);
		if (!ret) {
			struct scmi_resp_sensor_reading_complete *resp;

			resp = t->rx.buf;
			if (le32_to_cpu(resp->id) == sensor_id)
				*value = le64_to_cpu(resp->readings);
			else
				ret = -EPROTO;
		}
	} else {
		sensor->flags = cpu_to_le32(0);
		ret = scmi_do_xfer(handle, t);
		if (!ret) {
			struct scmi_resp_sensor_reading_get *resp;

			resp = t->rx.buf;
			*value = le64_to_cpu(resp->readings);
		}
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static void inline scmi_parse_sensor_readings(struct scmi_sensor_reading *out,
					const struct scmi_sensor_reading_le *in)
{
	out->sensor_value_low = le32_to_cpu(in->sensor_value_low);
	out->sensor_value_high = le32_to_cpu(in->sensor_value_high);
	out->timestamp_low = le32_to_cpu(in->timestamp_low);
	out->timestamp_high = le32_to_cpu(in->timestamp_high);
}

/**
 * scmi_sensor_reading_get_timestamped  - Read multiple-axis timestamped values
 * @handle: Platform handle
 * @sensor_id: Sensor ID
 * @count: The length of the provided @readings array
 * @readings: An array of elements each representing a timestamped per-axis
 *	      reading of type @struct scmi_sensor_reading.
 *	      Returned readings are ordered as the @axis descriptors array
 *	      included in @struct scmi_sensor_info and the max number of
 *	      returned elements is min(@count, @num_axis); ideally the provided
 *	      array should be of length @count equal to @num_axis.
 *
 * Return: 0 on Success
 */
static int
scmi_sensor_reading_get_timestamped(const struct scmi_handle *handle,
				    u32 sensor_id, u8 count,
				    struct scmi_sensor_reading *readings)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_sensor_reading_get *sensor;
	struct sensors_info *si = handle->sensor_priv;
	struct scmi_sensor_info *s = si->sensors + sensor_id;

	if (!count || !readings || count > s->num_axis)
		return -EINVAL;

	ret = scmi_xfer_get_init(handle, SENSOR_READING_GET,
				 SCMI_PROTOCOL_SENSOR, sizeof(*sensor), 0, &t);
	if (ret)
		return ret;

	sensor = t->tx.buf;
	sensor->id = cpu_to_le32(sensor_id);
	if (s->async) {
		sensor->flags = cpu_to_le32(SENSOR_READ_ASYNC);
		ret = scmi_do_xfer_with_response(handle, t);
		if (!ret) {
			int i;
			struct scmi_resp_sensor_reading_complete_v21 *resp;

			resp = t->rx.buf;
			/* Retrieve only the number of requested axis anyway */
			if (le32_to_cpu(resp->id) == sensor_id)
				for (i = 0; i < count; i++)
					scmi_parse_sensor_readings(&readings[i],
							    &resp->readings[i]);
			else
				ret = -EPROTO;
		}
	} else {
		sensor->flags = cpu_to_le32(0);
		ret = scmi_do_xfer(handle, t);
		if (!ret) {
			int i;
			struct scmi_resp_sensor_reading_get_v21 *resp;

			resp = t->rx.buf;
			for (i = 0; i < count; i++)
				scmi_parse_sensor_readings(&readings[i],
							   &resp->readings[i]);
		}
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static const struct scmi_sensor_info *
scmi_sensor_info_get(const struct scmi_handle *handle, u32 sensor_id)
{
	struct sensors_info *si = handle->sensor_priv;

	return si->sensors + sensor_id;
}

static int scmi_sensor_count_get(const struct scmi_handle *handle)
{
	struct sensors_info *si = handle->sensor_priv;

	return si->num_sensors;
}

static struct scmi_sensor_ops sensor_ops = {
	.count_get = scmi_sensor_count_get,
	.info_get = scmi_sensor_info_get,
	.trip_point_notify = scmi_sensor_trip_point_notify,
	.trip_point_config = scmi_sensor_trip_point_config,
	.reading_get = scmi_sensor_reading_get,
	.reading_get_timestamped = scmi_sensor_reading_get_timestamped,
	.config_get = scmi_sensor_config_get,
	.config_set = scmi_sensor_config_set,
	.continuous_update_notify = scmi_sensor_continuous_update_notify,
};

static bool scmi_sensor_set_notify_enabled(const struct scmi_handle *handle,
					   u8 evt_id, u32 src_id, bool enable)
{
	int ret;

	switch (evt_id) {
	case SENSOR_TRIP_POINT_EVENT:
		ret = scmi_sensor_trip_point_notify(handle, src_id, enable);
		break;
	case SENSOR_UPDATE:
		ret = scmi_sensor_continuous_update_notify(handle, src_id,
							   enable);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		pr_warn("SCMI Notifications - Proto:%X - FAIL_ENABLED - evt[%X] dom[%d] - ret:%d\n",
			SCMI_PROTOCOL_SENSOR, evt_id, src_id, ret);

	return !ret;
}

static void *scmi_sensor_fill_custom_report(const struct scmi_handle *handle,
					    u8 evt_id, u64 timestamp,
					    const void *payld, size_t payld_sz,
					    void *report, u32 *src_id)
{
	void *rep = NULL;

	switch (evt_id) {
	case SENSOR_TRIP_POINT_EVENT:
	{
		const struct scmi_sensor_trip_notify_payld *p = payld;
		struct scmi_sensor_trip_point_report *r = report;

		if (sizeof(*p) != payld_sz)
			break;

		r->timestamp = timestamp;
		r->agent_id = le32_to_cpu(p->agent_id);
		r->sensor_id = le32_to_cpu(p->sensor_id);
		r->trip_point_desc = le32_to_cpu(p->trip_point_desc);
		*src_id = r->sensor_id;
		rep = r;
		break;
	}
	case SENSOR_UPDATE:
	{
		int i;
		struct scmi_sensor_info *s;
		const struct scmi_sensor_update_notify_payld *p = payld;
		struct scmi_sensor_update_report *r = report;
		struct sensors_info *sinfo = handle->sensor_priv;

		/* payld_sz is variable for this event */
		r->sensor_id = le32_to_cpu(p->sensor_id);
		if (r->sensor_id >= sinfo->num_sensors)
			break;
		r->timestamp = timestamp;
		r->agent_id = le32_to_cpu(p->agent_id);
		s = &sinfo->sensors[r->sensor_id];
		/*
		 * The generated report r (@struct scmi_sensor_update_report)
		 * was pre-allocated to contain up to SCMI_MAX_NUM_SENSOR_AXIS
		 * readings: here it is filled with the effective @num_axis
		 * readings defined for this sensor.
		 */
		r->readings_count = s->num_axis;
		for (i = 0; i < r->readings_count; i++)
			scmi_parse_sensor_readings(&r->readings[i],
						   &p->readings[i]);
		*src_id = r->sensor_id;
		rep = r;
		break;
	}
	default:
		break;
	}

	return rep;
}

static const struct scmi_event sensor_events[] = {
	{
		.id = SENSOR_TRIP_POINT_EVENT,
		.max_payld_sz = 12,
		.max_report_sz =
			sizeof(struct scmi_sensor_trip_point_report),
	},
	{
		.id = SENSOR_UPDATE,
		.max_payld_sz =
			sizeof(struct scmi_sensor_update_notify_payld) +
			 SCMI_MAX_NUM_SENSOR_AXIS *
			 sizeof(struct scmi_sensor_reading_le),
		.max_report_sz = sizeof(struct scmi_sensor_update_report) +
				  SCMI_MAX_NUM_SENSOR_AXIS *
				  sizeof(struct scmi_sensor_reading),
	},
};

static const struct scmi_protocol_event_ops sensor_event_ops = {
	.set_notify_enabled = scmi_sensor_set_notify_enabled,
	.fill_custom_report = scmi_sensor_fill_custom_report,
};

static int scmi_sensors_protocol_init(struct scmi_handle *handle)
{
	u32 version;
	int ret;
	struct sensors_info *sinfo;

	scmi_version_get(handle, SCMI_PROTOCOL_SENSOR, &version);

	dev_dbg(handle->dev, "Sensor Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	sinfo = devm_kzalloc(handle->dev, sizeof(*sinfo), GFP_KERNEL);
	if (!sinfo)
		return -ENOMEM;
	sinfo->version = version;

	ret = scmi_sensor_attributes_get(handle, sinfo);
	if (ret)
		return ret;
	sinfo->sensors = devm_kcalloc(handle->dev, sinfo->num_sensors,
				      sizeof(*sinfo->sensors), GFP_KERNEL);
	if (!sinfo->sensors)
		return -ENOMEM;

	ret = scmi_sensor_description_get(handle, sinfo);
	if (ret)
		return ret;

	scmi_register_protocol_events(handle,
				      SCMI_PROTOCOL_SENSOR, PAGE_SIZE,
				      &sensor_event_ops, sensor_events,
				      ARRAY_SIZE(sensor_events),
				      sinfo->num_sensors);

	handle->sensor_priv = sinfo;
	handle->sensor_ops = &sensor_ops;

	return 0;
}

static int __init scmi_sensors_init(void)
{
	return scmi_protocol_register(SCMI_PROTOCOL_SENSOR,
				      &scmi_sensors_protocol_init);
}
subsys_initcall(scmi_sensors_init);
