// SPDX-License-Identifier: GPL-2.0
/* virt_wifi_simulation.h
 *
 * Register ops to virt_wifi driver.
 *
 * And decide which simulation data need to simulate.
 *
 * Copyright (C) 2019 Google LLC
 *
 * Author: lesl@google.com
 */
#ifndef __VIRT_WIFI_SIMULATION_H
#define __VIRT_WIFI_SIMULATION_H

#include <net/cfg80211.h>

#define BSSID_LEN 17
#define MAX_SSID_LEN 32
#define MAX_SECURITY_TYPE_LEN 4
#define TYPE_WPA2 "WPA2"

struct access_point {
	uint8_t index;
	char bssid[BSSID_LEN + 1];
	char security_type[MAX_SECURITY_TYPE_LEN + 1];
	int32_t channel;
	char ssid[MAX_SSID_LEN + 1];
};

struct scan_ap_info {
	uint8_t ap_index;
	int32_t signal;
	struct list_head list;
};

struct scan_config {
	int32_t control_setting;
	struct list_head *scanList;
};

void notify_device_open(struct net_device *dev);
void notify_device_stop(struct net_device *dev);
void notify_scan_trigger(struct wiphy *wiphy,
			 struct cfg80211_scan_request *req);
int generate_virt_scan_result(struct wiphy *wiphy);

#endif
