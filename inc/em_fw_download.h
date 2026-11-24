/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EM_FW_DOWNLOAD_H
#define EM_FW_DOWNLOAD_H

#include <cstddef>
#include <cstdint>
#include "em_base.h"

class dm_easy_mesh_t;
class em_cmd_t;
class em_mgr_t;

/*
 * Controller driven extender firmware download.
 *
 * The five proprietary messages are carried in a Vendor Specific CMDU (0x0004)
 * holding a single Vendor Specific TLV (0x0B):
 *
 *   TLV value = OUI[3] | message type[1] | service/notification type[2] | fields
 *
 * All integers are in network byte order, strings are UINT16 length prefixed
 * UTF-8 without NUL termination.
 */
#define EM_FW_DL_SERVICE_TYPE           0x0001
#define EM_FW_DL_NOTIF_TYPE             0x0001

/* Vendor TLV OUI; defaults to the OUI used by the other vendor specific messages */
#define EM_FW_DL_OUI                    comcast_vendor_oui

#define EM_FW_DL_SVC_RSP_FIXED_LEN      6   /* type + svc + protocols + version len */
#define EM_FW_DL_PATH_REQ_FIXED_LEN     21
#define EM_FW_DL_PATH_RSP_LEN           6
#define EM_FW_DL_NOTIF_LEN              22

typedef enum {
    em_fw_dl_msg_service_req = 0x01,
    em_fw_dl_msg_service_rsp = 0x02,
    em_fw_dl_msg_l3_path_req = 0x03,
    em_fw_dl_msg_l3_path_rsp = 0x04,
    em_fw_dl_msg_service_notif = 0x05,
} em_fw_dl_msg_type_t;

#define EM_FW_DL_PROTO_HTTP_BIT         0x01
#define EM_FW_DL_PROTO_HTTPS_BIT        0x02

typedef enum {
    em_fw_dl_path_status_accepted = 0x00,
    em_fw_dl_path_status_rejected = 0x01,
    em_fw_dl_path_status_not_supported = 0x02,
} em_fw_dl_path_status_t;

typedef enum {
    em_fw_dl_op_success = 0x00,
    em_fw_dl_op_in_progress = 0x01,
    em_fw_dl_op_retrying = 0x02,
    em_fw_dl_op_cancelled = 0x03,
    em_fw_dl_op_failed = 0x04,
} em_fw_dl_op_status_t;

typedef enum {
    em_fw_dl_event_connection_started = 0x01,
    em_fw_dl_event_connection_success = 0x02,
    em_fw_dl_event_connection_failed = 0x03,
    em_fw_dl_event_download_started = 0x10,
    em_fw_dl_event_download_in_progress = 0x11,
    em_fw_dl_event_download_completed = 0x12,
    em_fw_dl_event_download_failed = 0x13,
    em_fw_dl_event_download_retrying = 0x14,
    em_fw_dl_event_download_cancelled = 0x15,
    em_fw_dl_event_validation_started = 0x20,
    em_fw_dl_event_validation_success = 0x21,
    em_fw_dl_event_validation_failed = 0x22,
    em_fw_dl_event_flashing_started = 0x30,
    em_fw_dl_event_flashing_in_progress = 0x31,
    em_fw_dl_event_flashing_completed = 0x32,
    em_fw_dl_event_flashing_failed = 0x33,
    em_fw_dl_event_reboot_initiated = 0x40,
    em_fw_dl_event_device_rebooted = 0x41,
    em_fw_dl_event_post_reboot_verification_failed = 0x42,
    em_fw_dl_event_upgrade_completed = 0x50,
    em_fw_dl_event_upgrade_failed = 0x51,
    em_fw_dl_event_rollback_completed = 0x52,
    em_fw_dl_event_activation_pending = 0x60,
    em_fw_dl_event_activation_started = 0x61,
    em_fw_dl_event_activation_cancelled = 0x62,
    em_fw_dl_event_activation_failed = 0x63,
} em_fw_dl_event_t;

typedef struct {
    uint8_t     supported_protocols;
    char        current_version[EM_FW_VERSION_MAX_LEN];
} em_fw_dl_svc_rsp_t;

typedef struct {
    uint8_t     status;
    uint16_t    error_code;
} em_fw_dl_path_rsp_t;

typedef struct {
    uint8_t     event;
    uint8_t     op_status;
    uint64_t    total_bytes;
    uint64_t    bytes_downloaded;
    uint8_t     percentage;
} em_fw_dl_notif_t;

/* Per extender state tracked by the controller, backing the FirmwareImage data model */
typedef struct {
    mac_address_t   al_mac;
    bool            in_use;
    bool            active;                 /* an upgrade is being tracked */
    char            name[EM_FW_NAME_MAX_LEN];
    char            version[EM_FW_VERSION_MAX_LEN];         /* target version */
    char            current_version[EM_FW_VERSION_MAX_LEN]; /* running version reported by the agent */
    uint8_t         supported_protocols;
    uint8_t         last_event;
    uint8_t         last_op_status;
    uint16_t        path_error_code;
    uint64_t        total_bytes;
    uint64_t        bytes_downloaded;
    uint8_t         percentage;
} em_fw_dl_status_t;

class em_fw_download_t {
public:
    virtual dm_easy_mesh_t  *get_data_model() = 0;
    virtual em_state_t       get_state() = 0;
    virtual void             set_state(em_state_t state) = 0;
    virtual int              send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual em_mgr_t        *get_mgr() = 0;
    virtual em_cmd_t        *get_current_cmd() = 0;
    virtual em_service_type_t get_service_type() = 0;

    /**!
     * @brief Serializes a Service Request for the firmware download service.
     *
     * @param[out] out Buffer receiving the payload (after the OUI).
     * @param[in] out_len Size of out.
     *
     * @returns Encoded length, 0 when out is too small.
     */
    static size_t encode_service_req(uint8_t *out, size_t out_len);

    /**!
     * @brief Serializes a Layer#3 Path Request from validated command parameters.
     *
     * @returns Encoded length, 0 when out is too small or a field is out of range.
     */
    static size_t encode_l3_path_req(const em_cmd_fw_download_params_t *params, uint8_t *out, size_t out_len);

    /**!
     * @brief Parses a Service Response payload (after the OUI). Strict length checking.
     *
     * @returns true when well formed.
     */
    static bool decode_service_rsp(const uint8_t *in, size_t in_len, em_fw_dl_svc_rsp_t *rsp);

    /**!
     * @brief Parses a Layer#3 Path Response payload (after the OUI).
     *
     * @returns true when well formed.
     */
    static bool decode_l3_path_rsp(const uint8_t *in, size_t in_len, em_fw_dl_path_rsp_t *rsp);

    /**!
     * @brief Parses a Service Notification payload (after the OUI).
     *
     * @returns true when well formed.
     */
    static bool decode_service_notif(const uint8_t *in, size_t in_len, em_fw_dl_notif_t *notif);

    /**!
     * @brief Returns the checksum length for a checksum algorithm, 0 if unknown.
     */
    static size_t checksum_len(uint8_t alg);

    /**!
     * @brief Locates a firmware download payload in a received CMDU.
     *
     * @param[in] buff Raw frame including the raw header.
     * @param[in] len Frame length.
     * @param[out] payload Points at the message type octet.
     * @param[out] payload_len Length of the payload following the OUI.
     *
     * @returns true when the frame holds a vendor TLV with the firmware download OUI and a known message type.
     */
    static bool find_payload(unsigned char *buff, unsigned int len, const uint8_t **payload, size_t *payload_len);

    /* Controller side senders, driven by process_ctrl_state() */
    int send_service_req_msg();
    int send_l3_path_req_msg();

    /* Controller side receivers */
    int handle_service_rsp(const uint8_t *payload, size_t len, const unsigned char *src);
    int handle_l3_path_rsp(const uint8_t *payload, size_t len, const unsigned char *src);
    int handle_service_notif(const uint8_t *payload, size_t len, const unsigned char *src);

    /**!
     * @brief Processes a vendor specific CMDU; ignores frames that are not firmware download messages.
     *
     * @returns true when the frame was a firmware download message and was consumed.
     */
    bool process_msg(unsigned char *buff, unsigned int len);

    void process_ctrl_state();

    em_fw_download_t() = default;
    virtual ~em_fw_download_t() = default;

private:
    int send_vendor_cmdu(const uint8_t *payload, size_t payload_len);
};

#endif // EM_FW_DOWNLOAD_H
