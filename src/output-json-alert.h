/* Copyright (C) 2013-2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Logs alerts in JSON format.
 *
 */

#ifndef __OUTPUT_JSON_ALERT_H__
#define __OUTPUT_JSON_ALERT_H__

typedef struct AlertJsonOutputCtx_ {
    LogFileCtx* file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
    int replace_body_enabled;
    const char* replace_body;
    const ConfNode* content_type;
} AlertJsonOutputCtx;

void JsonAlertLogRegister(void);
void AlertJsonHeader(void *ctx, const Packet *p, const PacketAlert *pa, JsonBuilder *js,
        uint16_t flags, JsonAddrInfo *addr, char *xff_buffer);
void EveAddVerdict(JsonBuilder *jb, const Packet *p);

#endif /* __OUTPUT_JSON_ALERT_H__ */

