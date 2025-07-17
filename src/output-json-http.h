/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 */

#ifndef __OUTPUT_JSON_HTTP_H__
#define __OUTPUT_JSON_HTTP_H__
#include "output-json-alert.h"

#define URI_NOT_SEEN           "/libhtp::request_uri_not_seen"
#define HTTP_PROTO_PREFIX      "HTTP"
#define HTTP_URI_PREFIX1       "/"
#define HTTP_URI_PREFIX2       "http"
#define UA_ENVOY_HC            "Envoy/HC"  // 健康检查包
#define UA_NUCLEI              "nuclei"    // 漏洞扫描
#define HTTP_PROTO_1_0         "HTTP/1.0" 

#define SR_CMP_MIN(a, b)       ((a) < (b) ? (a) : (b))
#define BSTR_NCMP_C(a, b)      strncmp((const char *)bstr_ptr(a), b, SR_CMP_MIN(bstr_len(a), sizeof(b) - 1))

void JsonHttpLogRegister(void);

bool EveHttpAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js);
void EveHttpLogJSONBodyPrintable(JsonBuilder *js, Flow *f, uint64_t tx_id, const AlertJsonOutputCtx* json_output_ctx);
void EveHttpLogJSONBodyBase64(JsonBuilder *js, Flow *f, uint64_t tx_id);

#endif /* __OUTPUT_JSON_HTTP_H__ */

