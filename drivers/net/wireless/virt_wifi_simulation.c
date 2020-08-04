// SPDX-License-Identifier: GPL-2.0
/* virt_wifi_simulation.c
 *
 * Regist ops to virt_wifi driver.
 *
 * And decide which simulation data need to simulate.
 *
 * Copyright (C) 2019 Google LLC
 *
 * Author: lesl@google.com
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <net/cfg80211.h>
#include <net/virt_wifi.h>
#include "virt_wifi_simulation.h"
#include "virt_wifi_data.h"

static struct virt_wifi_network_simulation ops = {
	.notify_device_open = notify_device_open,
	.notify_device_stop = notify_device_stop,
	.notify_scan_trigger = notify_scan_trigger,
	.generate_virt_scan_result = generate_virt_scan_result,
};

struct device wlan_simulation_device;

struct information_element {
	u8 tag;
	u8 len;
	u8 *data;
} __packed;

char scan_result_switch_factor;
int total_configured_ap_num;
int total_configured_scan_result;
int current_scan_trigger_count;
u64 current_scan_trigger_time;
u64 wifi_enable_tsf;
int last_scan_config_index;
struct access_point **ap_list;
struct scan_config **scan_list;

static u8 *convert_bssid(char *bssid_str)
{
	char *token, *tmp;
	unsigned long val;
	int parser_index = 0;
	u8 *converted_bssid = kzalloc(ETH_ALEN, GFP_KERNEL);

	if (!converted_bssid)
		return NULL;

	tmp = kstrdup(bssid_str, GFP_KERNEL);
	if (!tmp) {
		kfree(converted_bssid);
		return NULL;
	}

	do {
		token = strsep(&tmp, ":");
		if (token != NULL) {
			kstrtoul(token, 16, &val);
			converted_bssid[parser_index] = val;
			parser_index++;
			if (parser_index == ETH_ALEN)
				break;
		}
	} while (token != NULL);
	return converted_bssid;
}

static u8 *generate_ie(struct access_point *ap, int *ie_len_ptr)
{
	int ssid_len;
	u8 *ie = NULL;
	char rsn_data_aes_psk[20] = {0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
				     0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
				     0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
				     0x0c, 0x00};
	struct information_element *ssid =
		      kzalloc(sizeof(struct information_element), GFP_KERNEL);
	struct information_element *rsn = NULL;

	if (!ssid)
		goto error;
	ssid_len = strlen(ap->ssid);
	ssid->tag = WLAN_EID_SSID;
	ssid->len = ssid_len;

	if (!strcmp(ap->security_type, TYPE_WPA2)) {
		pr_debug("ap : %s is WPA2", ap->ssid);
		rsn = kzalloc(sizeof(struct information_element), GFP_KERNEL);
		if (!rsn)
			goto error;
		rsn->tag = WLAN_EID_RSN;
		rsn->len = 20;
	}
	*ie_len_ptr = ssid->len + 2;
	if (rsn)
		*ie_len_ptr += (rsn->len + 2);

	ie = kzalloc(*ie_len_ptr, GFP_KERNEL);
	if (ie) {
		memcpy(ie, ssid, 2);
		memcpy(ie+2, ap->ssid, ssid_len);
	}
	if (rsn && ie) {
		memcpy(ie + ssid_len + 2, rsn, 2);
		memcpy(ie + ssid_len + 4, rsn_data_aes_psk, rsn->len);
	}
error:
	kfree(rsn);
	kfree(ssid);
	return ie;
}

static int select_scan_config(void)
{
	int index;
	u64 delta_time = div_u64(current_scan_trigger_time - wifi_enable_tsf,
				 1000000000);

	for (index = last_scan_config_index;
	     index < total_configured_scan_result; index++) {
		if (scan_result_switch_factor == 'C' &&
		    (scan_list[index]->control_setting >
		     current_scan_trigger_count)) {
			break;
		}
		if (scan_result_switch_factor == 'T' &&
		    scan_list[index]->control_setting > delta_time) {
			break;
		}
	}
	if (index == total_configured_scan_result)
		index = total_configured_scan_result - 1;
	if (last_scan_config_index != index) {
		last_scan_config_index = index;
		pr_info("%s switch config to %d", __func__, index);
	}
	return index;
}

int get_virt_scan_result(struct wiphy *wiphy)
{
	int ie_len, ret = 0;
	int targer_scan_config = select_scan_config();
	struct list_head *pos;
	struct cfg80211_bss *informed_bss;
	struct ieee80211_channel *channel;
	u8 *bssid, *ie;

	list_for_each(pos, scan_list[targer_scan_config]->scanList) {
		struct scan_ap_info *ap_info =
		    list_entry(pos, struct scan_ap_info, list);
		ie_len = 0;
		if (ap_info->ap_index > total_configured_ap_num) {
			pr_err("The ap_index %d doesn't exist in cf_ap_list",
			       ap_info->ap_index);
			ret = -1;
			break;
		}
		channel =
		    ieee80211_get_channel(wiphy,
					  ap_list[ap_info->ap_index]->channel);
		bssid = convert_bssid(ap_list[ap_info->ap_index]->bssid);
		if (!bssid) {
			ret = -1;
			goto error;
		}
		ie = generate_ie(ap_list[ap_info->ap_index], &ie_len);
		if (!ie) {
			kfree(bssid);
			ret = -1;
			goto error;
		}
		informed_bss = cfg80211_inform_bss(wiphy, channel,
						   CFG80211_BSS_FTYPE_PRESP,
						   bssid,
						   ktime_get_ns(),
						   WLAN_CAPABILITY_ESS, 0,
						   (void *)ie, ie_len,
						   DBM_TO_MBM(ap_info->signal),
						   GFP_KERNEL);
		cfg80211_put_bss(wiphy, informed_bss);
		kfree(ie);
		kfree(bssid);
		ie = NULL;
		bssid = NULL;
	}
error:
	return ret;
}

int do_virt_scan(void)
{
	current_scan_trigger_count++;
	current_scan_trigger_time = ktime_get_ns();
	pr_info("%s enter, count = %d, trigger time is |%lu|",
		__func__, current_scan_trigger_count,
		current_scan_trigger_time);
	return 0;
}

int virt_wifi_simulation_clean_up(void)
{
	pr_info("%s enter", __func__);
	total_configured_ap_num =  0;
	total_configured_scan_result = 0;
	current_scan_trigger_count = 0;
	current_scan_trigger_time = 0;
	wifi_enable_tsf = 0;
	last_scan_config_index = 0;
	data_clean_up();
	return 0;
}

void notify_device_open(struct net_device *dev)
{
	if (!load_simulation_data(&wlan_simulation_device)) {
		virt_wifi_simulation_clean_up();
		return;
	}
	ap_list = get_ap_list(&total_configured_ap_num);
	scan_list = get_scan_config_list(&total_configured_scan_result,
					 &scan_result_switch_factor);
	wifi_enable_tsf = ktime_get_ns();
	pr_info("%s - total ap num=%d and total scan config num = %d,",
		__func__, total_configured_ap_num,
		total_configured_scan_result);
	pr_info(" %s - switch factor = %c and enable time :|%lu|",
		__func__, scan_result_switch_factor, wifi_enable_tsf);
}

void notify_device_stop(struct net_device *dev)
{
	virt_wifi_unregister_network_simulation();
	virt_wifi_simulation_clean_up();
	virt_wifi_register_network_simulation(&ops);
}

void notify_scan_trigger(struct wiphy *wiphy,
			 struct cfg80211_scan_request *request)
{
	do_virt_scan();
}

int generate_virt_scan_result(struct wiphy *wiphy)
{
	if ((total_configured_ap_num && total_configured_scan_result))
		get_virt_scan_result(wiphy);
	return 0;
}

int __init init_virt_data_simulation_module(void)
{
	pr_info("%s - enter", __func__);
	virt_wifi_register_network_simulation(&ops);
	device_register(&wlan_simulation_device);
	return 0;
}

void __exit exit_virt_data_simulation_module(void)
{
	pr_info("%s - enter", __func__);
	device_unregister(&wlan_simulation_device);
	virt_wifi_simulation_clean_up();
	virt_wifi_unregister_network_simulation();
}

module_init(init_virt_data_simulation_module);
module_exit(exit_virt_data_simulation_module);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Les Lee <lesl@google.com>");
MODULE_DESCRIPTION("Module for the wifi virt driver data simulation.");

