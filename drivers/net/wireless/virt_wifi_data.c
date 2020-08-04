// SPDX-License-Identifier: GPL-2.0
/* virt_wifi_data.c
 *
 * Load simulation data from the file.
 *
 * Copyright (C) 2019 Google LLC
 *
 * Author: lesl@google.com
 */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "virt_wifi_simulation.h"
#include "virt_wifi_data.h"
#include <linux/device.h>
#include <linux/firmware.h>

mm_segment_t oldfs;

static int total_configured_ap_num;
static int total_configured_scan_result;
static struct access_point *ap_list[MAX_AP_NUM];
static struct scan_config *scan_list[MAX_SCAN_CONFIG];
static char scan_result_switch_factor;

void free_scan_ap_info_list(struct list_head *apInfoList)
{
	struct scan_ap_info  *pos, *next;

	list_for_each_entry_safe(pos, next, apInfoList, list) {
		list_del(&pos->list);
		kfree(pos);
	}
}

/* config_data format:
 * 10;0,-55;1,-55;  // Control Setting;AP_index,Ap_Rssi;AP2_index,AP2_Rssi; ...
 */
static struct scan_config *extract_scan_list_from_file(char *config_data)
{
	unsigned long val;
	int parser_index = 0;
	struct scan_ap_info *ap_info;
	char *token_scan_list, *token_ap;
	struct scan_config *config;
	struct list_head *scan_list;

	config = kzalloc(sizeof(struct scan_config), GFP_KERNEL);
	if (!config)
		goto error;
	scan_list = kzalloc(sizeof(struct list_head),  GFP_KERNEL);
	if (!scan_list)
		goto error;
	INIT_LIST_HEAD(scan_list);

	do {
		token_scan_list = strsep(&config_data, ";");
		if (token_scan_list == NULL)
			break;
		if (parser_index == 0) {
			kstrtoul(token_scan_list, 10, &val);
			config->control_setting = val;
			parser_index++;
			continue;
		} else if (strlen(token_scan_list) <= 1) { // ignore "\n"
			continue;
		}
		parser_index = 0;
		ap_info = kzalloc(sizeof(struct scan_ap_info), GFP_KERNEL);
		if (!ap_info)
			goto error;
		do {
			token_ap = strsep(&token_scan_list, ",");
			if (token_ap != NULL) {
				if (parser_index == 0) {
					kstrtoul(token_ap, 10, &val);
					ap_info->ap_index = val;
				} else {
					kstrtoul(token_ap + 1, 10, &val);
					ap_info->signal = val * (-1);
				}
				parser_index++;
			}
		} while (token_ap != NULL);
		list_add(&ap_info->list, scan_list);
	} while (1);
	config->scanList = scan_list;
	return config;
error:
	if (config) {
		if (scan_list) {
			free_scan_ap_info_list(scan_list);
			kfree(scan_list);
		}
		kfree(config);
	}
	return NULL;
}

static bool read_scan_config(struct device *dev)
{
	bool ret = false;
	const struct firmware *fw_scan_config_entry;
	int max_config_len;
	struct  scan_config *sc = NULL;
	char *token, *buf = NULL, *tmp = NULL;

	if (request_firmware(&fw_scan_config_entry,
			     SCAN_CONTROL_CONFIG_FILE, dev)) {
		pr_err("request_firmware: %s Firmware not available",
		       SCAN_CONTROL_CONFIG_FILE);
		goto error;
	}
	buf = kzalloc(fw_scan_config_entry->size + 1, GFP_KERNEL);
	if (!buf)
		goto error;
	memcpy(buf, fw_scan_config_entry->data, fw_scan_config_entry->size);
	max_config_len = MAX_AP_NUM * MAX_AP_SCAN_CONFIG_LEN;
	tmp = kzalloc(max_config_len + 1, GFP_KERNEL);
	if (!tmp)
		goto error;
	do {
		token = strsep(&buf, "\n");
		if (token == NULL || strlen(token) == 0)
			break;
		memset(tmp, 0, max_config_len + 1);
		if (strlen(token) > max_config_len)
			goto error;
		strncpy(tmp, token, strlen(token));
		if (strlen(tmp) == 1) {
			scan_result_switch_factor = tmp[0];
		} else {
			sc = extract_scan_list_from_file(tmp);
			if (!sc)
				goto error;
			scan_list[total_configured_scan_result] = sc;
			total_configured_scan_result++;
			if (total_configured_scan_result >= MAX_SCAN_CONFIG)
				break;
		}
	} while (1);
	ret = true;
error:
	kfree(buf);
	kfree(tmp);
	if (fw_scan_config_entry)
		release_firmware(fw_scan_config_entry);
	return ret;
}

/* ap_info format:
 * index,bssid,security_type,channel,ssid
 * example:
 * 0,aa:bb:cc:dd:ee:ff,OPEN,5240,Test_SSID_1
 */
static struct access_point *extract_ap_from_file(char *ap_info)
{
	unsigned long val;
	int parser_index = 0;
	char *token;
	struct access_point *ap = kzalloc(sizeof(struct access_point),
					   GFP_KERNEL);

	if (!ap)
		goto error;
	do {
		token = strsep(&ap_info, ",");
		if (token == NULL)
			break;
		switch (parser_index) {
		case 0:
			kstrtoul(token, 10, &val);
			ap->index = val;
			break;
		case 1:
			if (strlen(token) <= sizeof(ap->bssid)) {
				strncpy(ap->bssid, token, strlen(token));
				break;
			}
		case 2:
			if (strlen(token) <= sizeof(ap->security_type)) {
				strncpy(ap->security_type, token,
					strlen(token));
				break;
			}
		case 3:
			kstrtoul(token, 10, &val);
			ap->channel = val;
			break;
		case 4:
			if (strlen(token) < sizeof(ap->ssid)) {
				strncpy(ap->ssid, token, strlen(token));
				break;
			}
		default:
			pr_err("%s - parser error ", __func__);
			kfree(ap);
			ap = NULL;
			break;
		}
		parser_index++;
	} while (ap);
error:
	return ap;
}

static bool read_ap_config(struct device *dev)
{
	bool ret = false;
	/**
	 * ap_config format is
	 * "index, bssid, security_type, channel, ssid"
	 * The buf len should be +2 for index and channel
	 * which type is not string.
	 */
	int buf_len = sizeof(struct access_point) + 2;
	struct access_point *ap;
	const struct firmware *fw_ap_config_entry;
	char *token, *buf = NULL, *tmp = NULL;

	if (request_firmware(&fw_ap_config_entry, AP_LIST_CONFIG_FILE, dev)) {
		pr_err("request_firmware: %s Firmware not available",
			AP_LIST_CONFIG_FILE);
		goto error;
	}
	buf = kzalloc(fw_ap_config_entry->size + 1, GFP_KERNEL);
	if (!buf)
		goto error;
	memcpy(buf, fw_ap_config_entry->data, fw_ap_config_entry->size);
	tmp = kzalloc(buf_len, GFP_KERNEL);
	if (!tmp)
		goto error;
	do {
		token = strsep(&buf, "\n");
		if (token == NULL || strlen(token) == 0)
			break;
		memset(tmp, 0, buf_len);
		strncpy(tmp, token, strlen(token));
		ap = extract_ap_from_file(tmp);
		if (!ap)
			goto error;
		if (total_configured_ap_num != ap->index ||
		   ap->index > MAX_AP_NUM) {
			pr_err("%s - Invalid index found\n", __func__);
			goto error;
		}
		if (ap->index < MAX_AP_NUM) {
			ap_list[ap->index] = ap;
			total_configured_ap_num++;
		}
	} while (1);
	ret = true;
error:
	kfree(buf);
	kfree(tmp);
	if (fw_ap_config_entry)
		release_firmware(fw_ap_config_entry);
	return ret;
}

int load_simulation_data(struct device *dev)
{
	return read_ap_config(dev) && read_scan_config(dev);
}

void data_clean_up(void)
{
	int i;

	for (i = 0; i < total_configured_scan_result; i++) {
		free_scan_ap_info_list(scan_list[i]->scanList);
		kfree(scan_list[i]->scanList); // free list head
		kfree(scan_list[i]);
	}
	memset(ap_list, 0, MAX_AP_NUM * sizeof(struct access_point *));
	memset(scan_list, 0, MAX_SCAN_CONFIG * sizeof(struct scan_config *));
	total_configured_ap_num =  0;
	total_configured_scan_result = 0;
}

struct access_point **get_ap_list(int *list_len_ptr)
{
	*list_len_ptr = total_configured_ap_num;
	return ap_list;
}

struct scan_config **get_scan_config_list(int *list_len_ptr,
					  char *switch_factor_ptr)
{
	*list_len_ptr = total_configured_scan_result;
	*switch_factor_ptr = scan_result_switch_factor;
	return scan_list;
}

