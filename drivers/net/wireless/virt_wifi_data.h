// SPDX-License-Identifier: GPL-2.0
/* virt_wifi_data.h
 *
 * Load simulation data from the file.
 *
 * Copyright (C) 2019 Google LLC
 *
 * Author: lesl@google.com
 */
#ifndef __VIRT_WIFI_DATA_H
#define __VIRT_WIFI_DATA_H

#include <linux/firmware.h>

#define MAX_AP_NUM 100
#define MAX_SCAN_CONFIG 100
#define AP_LIST_CONFIG_FILE "cf_ap_list"
#define SCAN_CONTROL_CONFIG_FILE "cf_scan_control_list"

// Each scan config format is index(max len=2), rssi(max len=4);
#define MAX_AP_SCAN_CONFIG_LEN 8
// The value of max control setting is 99999
#define MAX_CONTROL_SETTING_LEN 5

int load_simulation_data(struct device *dev);
struct access_point **get_ap_list(int *len);
struct scan_config **get_scan_config_list(int *leni, char *switch_factor);
void data_clean_up(void);

#endif
