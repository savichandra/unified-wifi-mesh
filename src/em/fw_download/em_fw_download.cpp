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

#include <string.h>
#include <arpa/inet.h>
#include "em_fw_download.h"
#include "em_mgr.h"
#include "em_cmd.h"
#include "dm_easy_mesh.h"

namespace {

void put_u8(uint8_t *&p, uint8_t v) { *p++ = v; }

void put_u16(uint8_t *&p, uint16_t v)
{
    *p++ = static_cast<uint8_t>(v >> 8);
    *p++ = static_cast<uint8_t>(v);
}

void put_u64(uint8_t *&p, uint64_t v)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        *p++ = static_cast<uint8_t>(v >> shift);
    }
}

void put_str(uint8_t *&p, const char *s, size_t n)
{
    put_u16(p, static_cast<uint16_t>(n));
    memcpy(p, s, n);
    p += n;
}

/* Bounds checked reader; any over-read latches ok to false */
struct reader_t {
    const uint8_t *p;
    size_t left;
    bool ok;

    reader_t(const uint8_t *buf, size_t len) : p(buf), left(len), ok(true) {}

    uint8_t u8()
    {
        if (left < 1) { ok = false; return 0; }
        left--;
        return *p++;
    }

    uint16_t u16()
    {
        if (left < 2) { ok = false; return 0; }
        uint16_t v = static_cast<uint16_t>((p[0] << 8) | p[1]);
        p += 2; left -= 2;
        return v;
    }

    uint64_t u64()
    {
        if (left < 8) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) { v = (v << 8) | p[i]; }
        p += 8; left -= 8;
        return v;
    }

    /* Copies a length prefixed string into dst (NUL terminated); fails if it does not fit */
    void str(char *dst, size_t dst_len)
    {
        size_t n = u16();
        if (!ok || left < n || n >= dst_len) { ok = false; return; }
        memcpy(dst, p, n);
        dst[n] = '\0';
        p += n; left -= n;
    }
};

} // namespace

size_t em_fw_download_t::checksum_len(uint8_t alg)
{
    switch (alg) {
        case em_fw_dl_checksum_sha256: return 32;
        case em_fw_dl_checksum_sha384: return 48;
        case em_fw_dl_checksum_sha512: return 64;
        default: return 0;
    }
}

size_t em_fw_download_t::encode_service_req(uint8_t *out, size_t out_len)
{
    uint8_t *p = out;

    if (out == NULL || out_len < 3) {
        return 0;
    }
    put_u8(p, em_fw_dl_msg_service_req);
    put_u16(p, EM_FW_DL_SERVICE_TYPE);

    return static_cast<size_t>(p - out);
}

size_t em_fw_download_t::encode_l3_path_req(const em_cmd_fw_download_params_t *prm, uint8_t *out, size_t out_len)
{
    uint8_t *p = out;
    size_t url_len, name_len, ver_len, sum_len;

    if (prm == NULL || out == NULL) {
        return 0;
    }
    if (prm->protocol != em_fw_dl_protocol_http && prm->protocol != em_fw_dl_protocol_https) {
        return 0;
    }
    url_len = strnlen(prm->url, sizeof(prm->url));
    name_len = strnlen(prm->name, sizeof(prm->name));
    ver_len = strnlen(prm->version, sizeof(prm->version));
    sum_len = checksum_len(prm->checksum_alg);
    if (url_len == 0 || url_len >= sizeof(prm->url) || name_len >= sizeof(prm->name) ||
        ver_len >= sizeof(prm->version) || sum_len == 0) {
        return 0;
    }
    if (out_len < (EM_FW_DL_PATH_REQ_FIXED_LEN + url_len + name_len + ver_len + sum_len)) {
        return 0;
    }

    put_u8(p, em_fw_dl_msg_l3_path_req);
    put_u16(p, EM_FW_DL_SERVICE_TYPE);
    put_u8(p, prm->protocol);
    put_str(p, prm->url, url_len);
    put_u64(p, prm->image_size);
    put_str(p, prm->name, name_len);
    put_str(p, prm->version, ver_len);
    put_u8(p, prm->checksum_alg);
    memcpy(p, prm->checksum, sum_len);
    p += sum_len;
    put_u8(p, prm->max_retry);
    put_u8(p, prm->activate_immediately ? 1 : 0);

    return static_cast<size_t>(p - out);
}

bool em_fw_download_t::decode_service_rsp(const uint8_t *in, size_t in_len, em_fw_dl_svc_rsp_t *rsp)
{
    reader_t r(in, in_len);

    if (in == NULL || rsp == NULL) {
        return false;
    }
    memset(rsp, 0, sizeof(*rsp));
    if (r.u8() != em_fw_dl_msg_service_rsp || r.u16() != EM_FW_DL_SERVICE_TYPE) {
        return false;
    }
    rsp->supported_protocols = r.u8();
    r.str(rsp->current_version, sizeof(rsp->current_version));

    return r.ok && r.left == 0;
}

bool em_fw_download_t::decode_l3_path_rsp(const uint8_t *in, size_t in_len, em_fw_dl_path_rsp_t *rsp)
{
    reader_t r(in, in_len);

    if (in == NULL || rsp == NULL || in_len != EM_FW_DL_PATH_RSP_LEN) {
        return false;
    }
    memset(rsp, 0, sizeof(*rsp));
    if (r.u8() != em_fw_dl_msg_l3_path_rsp || r.u16() != EM_FW_DL_SERVICE_TYPE) {
        return false;
    }
    rsp->status = r.u8();
    rsp->error_code = r.u16();

    return r.ok && rsp->status <= em_fw_dl_path_status_not_supported;
}

bool em_fw_download_t::decode_service_notif(const uint8_t *in, size_t in_len, em_fw_dl_notif_t *notif)
{
    reader_t r(in, in_len);

    if (in == NULL || notif == NULL || in_len != EM_FW_DL_NOTIF_LEN) {
        return false;
    }
    memset(notif, 0, sizeof(*notif));
    if (r.u8() != em_fw_dl_msg_service_notif || r.u16() != EM_FW_DL_NOTIF_TYPE) {
        return false;
    }
    notif->event = r.u8();
    notif->op_status = r.u8();
    notif->total_bytes = r.u64();
    notif->bytes_downloaded = r.u64();
    notif->percentage = r.u8();

    return r.ok && notif->op_status <= em_fw_dl_op_failed && notif->percentage <= 100;
}

bool em_fw_download_t::find_payload(unsigned char *buff, unsigned int len, const uint8_t **payload, size_t *payload_len)
{
    const size_t hdr_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    em_cmdu_t *cmdu;
    size_t off = hdr_len;

    if (buff == NULL || len < hdr_len) {
        return false;
    }
    cmdu = reinterpret_cast<em_cmdu_t *>(buff + sizeof(em_raw_hdr_t));
    if (ntohs(cmdu->type) != em_msg_type_topo_vendor) {
        return false;
    }

    while ((off + sizeof(em_tlv_t)) <= len) {
        em_tlv_t *tlv = reinterpret_cast<em_tlv_t *>(buff + off);
        size_t tlv_len = ntohs(tlv->len);

        if (tlv->type == em_tlv_type_eom) {
            break;
        }
        if ((off + sizeof(em_tlv_t) + tlv_len) > len) {
            return false;
        }
        if ((tlv->type == em_tlv_type_vendor_specific) && (tlv_len > (EM_VENDOR_OUI_SIZE + 1)) &&
            (memcmp(tlv->value, EM_FW_DL_OUI, EM_VENDOR_OUI_SIZE) == 0)) {
            uint8_t type = tlv->value[EM_VENDOR_OUI_SIZE];

            if (type < em_fw_dl_msg_service_req || type > em_fw_dl_msg_service_notif) {
                return false;
            }
            *payload = tlv->value + EM_VENDOR_OUI_SIZE;
            *payload_len = tlv_len - EM_VENDOR_OUI_SIZE;
            return true;
        }
        off += sizeof(em_tlv_t) + tlv_len;
    }

    return false;
}

int em_fw_download_t::send_vendor_cmdu(const uint8_t *payload, size_t payload_len)
{
    unsigned char buff[MAX_EM_BUFF_SZ] = {0};
    unsigned char *tmp = buff;
    size_t len = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    size_t tlv_len = EM_VENDOR_OUI_SIZE + payload_len;

    if ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) + 2 * sizeof(em_tlv_t) + tlv_len) > sizeof(buff)) {
        em_printfout("Firmware download message too large");
        return -1;
    }

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t); len += sizeof(mac_address_t);
    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t); len += sizeof(mac_address_t);
    memcpy(tmp, &type, sizeof(type));
    tmp += sizeof(type); len += sizeof(type);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(cmdu, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(em_msg_type_topo_vendor);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t); len += sizeof(em_cmdu_t);

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_vendor_specific;
    tlv->len = htons(static_cast<unsigned short>(tlv_len));
    memcpy(tlv->value, EM_FW_DL_OUI, EM_VENDOR_OUI_SIZE);
    memcpy(tlv->value + EM_VENDOR_OUI_SIZE, payload, payload_len);
    tmp += sizeof(em_tlv_t) + tlv_len; len += sizeof(em_tlv_t) + tlv_len;

    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;
    len += sizeof(em_tlv_t);

    return send_frame(buff, static_cast<unsigned int>(len));
}

int em_fw_download_t::send_service_req_msg()
{
    em_cmd_t *cmd = get_current_cmd();
    uint8_t payload[8];
    size_t n;

    if (cmd == NULL) {
        return -1;
    }
    get_mgr()->fw_download_begin(&cmd->m_param.u.fw_download_params);

    n = encode_service_req(payload, sizeof(payload));
    if (n == 0 || send_vendor_cmdu(payload, n) < 0) {
        em_printfout("Service Request send failed");
        set_state(em_state_ctrl_fw_download_done);
        return -1;
    }
    em_printfout("Firmware download Service Request sent");
    set_state(em_state_ctrl_fw_svc_rsp_pending);

    return 0;
}

int em_fw_download_t::send_l3_path_req_msg()
{
    em_cmd_t *cmd = get_current_cmd();
    uint8_t payload[MAX_EM_BUFF_SZ];
    size_t n;

    if (cmd == NULL) {
        return -1;
    }
    n = encode_l3_path_req(&cmd->m_param.u.fw_download_params, payload, sizeof(payload));
    if (n == 0 || send_vendor_cmdu(payload, n) < 0) {
        em_printfout("Layer#3 Path Request send failed");
        set_state(em_state_ctrl_fw_download_done);
        return -1;
    }
    em_printfout("Layer#3 Path Request sent");
    set_state(em_state_ctrl_fw_l3_path_rsp_pending);

    return 0;
}

int em_fw_download_t::handle_service_rsp(const uint8_t *payload, size_t len, const unsigned char *src)
{
    em_cmd_t *cmd = get_current_cmd();
    em_fw_dl_svc_rsp_t rsp;
    em_fw_dl_path_rsp_t unsupported;
    uint8_t needed;

    if (get_state() != em_state_ctrl_fw_svc_rsp_pending || cmd == NULL) {
        em_printfout("Unexpected Service Response in state %d", get_state());
        return -1;
    }
    if (!decode_service_rsp(payload, len, &rsp)) {
        em_printfout("Malformed Service Response");
        return -1;
    }

    get_mgr()->fw_download_service_rsp(src, &rsp);

    needed = (cmd->m_param.u.fw_download_params.protocol == em_fw_dl_protocol_https) ?
        EM_FW_DL_PROTO_HTTPS_BIT : EM_FW_DL_PROTO_HTTP_BIT;
    if ((rsp.supported_protocols & needed) == 0) {
        em_printfout("Agent does not support requested protocol (supported=0x%02x)", rsp.supported_protocols);
        unsupported.status = em_fw_dl_path_status_not_supported;
        unsupported.error_code = 0x0002;
        get_mgr()->fw_download_path_rsp(src, &unsupported);
        set_state(em_state_ctrl_fw_download_done);
        return 0;
    }
    set_state(em_state_ctrl_fw_l3_path_req_pending);

    return 0;
}

int em_fw_download_t::handle_l3_path_rsp(const uint8_t *payload, size_t len, const unsigned char *src)
{
    em_fw_dl_path_rsp_t rsp;

    if (get_state() != em_state_ctrl_fw_l3_path_rsp_pending) {
        em_printfout("Unexpected Layer#3 Path Response in state %d", get_state());
        return -1;
    }
    if (!decode_l3_path_rsp(payload, len, &rsp)) {
        em_printfout("Malformed Layer#3 Path Response");
        return -1;
    }
    em_printfout("Layer#3 Path Response status=%u error=0x%04x", rsp.status, rsp.error_code);

    get_mgr()->fw_download_path_rsp(src, &rsp);
    set_state(em_state_ctrl_fw_download_done);

    return 0;
}

int em_fw_download_t::handle_service_notif(const uint8_t *payload, size_t len, const unsigned char *src)
{
    em_fw_dl_notif_t notif;

    if (!decode_service_notif(payload, len, &notif)) {
        em_printfout("Malformed Service Notification");
        return -1;
    }
    em_printfout("Firmware notification event=0x%02x op=%u %llu/%llu bytes (%u%%)", notif.event, notif.op_status,
        static_cast<unsigned long long>(notif.bytes_downloaded), static_cast<unsigned long long>(notif.total_bytes),
        notif.percentage);

    get_mgr()->fw_download_notif(src, &notif);

    return 0;
}

bool em_fw_download_t::process_msg(unsigned char *buff, unsigned int len)
{
    const uint8_t *payload;
    size_t payload_len;
    em_raw_hdr_t *hdr;

    if (get_service_type() != em_service_type_ctrl || !find_payload(buff, len, &payload, &payload_len)) {
        return false;
    }
    hdr = reinterpret_cast<em_raw_hdr_t *>(buff);

    switch (payload[0]) {
        case em_fw_dl_msg_service_rsp:
            handle_service_rsp(payload, payload_len, hdr->src);
            break;
        case em_fw_dl_msg_l3_path_rsp:
            handle_l3_path_rsp(payload, payload_len, hdr->src);
            break;
        case em_fw_dl_msg_service_notif:
            handle_service_notif(payload, payload_len, hdr->src);
            break;
        default:
            em_printfout("Ignoring firmware download message type 0x%02x on controller", payload[0]);
            break;
    }

    return true;
}

void em_fw_download_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_fw_svc_req_pending:
            send_service_req_msg();
            break;

        case em_state_ctrl_fw_l3_path_req_pending:
            send_l3_path_req_msg();
            break;

        default:
            break;
    }
}
