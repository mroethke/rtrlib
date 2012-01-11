/*
 * This file is part of RTRlib.
 *
 * RTRlib is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * RTRlib is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RTRlib; see the file COPYING.LESSER.
 *
 * written by Fabian Holler, in cooperation with:
 * INET group, Hamburg University of Applied Sciences,
 * CST group, Freie Universitaet Berlin
 * Website: http://rpki.realmv6.org/
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "rtrlib/transport/transport.h"
#include "rtrlib/rtr/packets.h"
#include "rtrlib/lib/utils.h"
#include "rtrlib/lib/log.h"

typedef enum pdu_error_type{
    CORRUPT_DATA = 0,
    INTERNAL_ERROR = 1,
    NO_DATA_AVAIL = 2,
    INVALID_REQUEST = 3,
    UNSUPPORTED_PROTOCOL_VER = 4,
    UNSUPPORTED_PDU_TYPE = 5,
    WITHDRAWAL_OF_UNKNOWN_RECORD = 6,
    DUPLICATE_ANNOUNCEMENT = 7
} pdu_error_type;

typedef enum pdu_type{
    SERIAL_NOTIFY = 0,
    SERIAL_QUERY = 1,
    RESET_QUERY = 2,
    CACHE_RESPONSE = 3,
    IPV4_PREFIX = 4,
    IPV6_PREFIX = 6,
    EOD = 7,
    CACHE_RESET = 8,
    ERROR = 10
} pdu_type;

typedef struct pdu_header{
    uint8_t ver;
    uint8_t type;
    uint16_t reserved;
    uint32_t len;
} pdu_header;

typedef struct pdu_serial_notify{
    uint8_t ver;
    uint8_t type;
    uint16_t nonce;
    uint32_t len;
    uint32_t sn;
} pdu_serial_notify;

typedef struct pdu_serial_query{
    uint8_t ver;
    uint8_t type;
    uint16_t nonce;
    uint32_t len;
    uint32_t sn;
} pdu_serial_query;

typedef pdu_serial_query pdu_eod;

typedef struct pdu_ipv4{
    uint8_t ver;
    uint8_t type;
    uint16_t reserved;
    uint32_t len;
    uint8_t flags;
    uint8_t prefix_len;
    uint8_t max_prefix_len;
    uint8_t zero;
    uint32_t prefix;
    uint32_t asn;
} pdu_ipv4;

typedef struct pdu_ipv6{
    uint8_t ver;
    uint8_t type;
    uint16_t reserved;
    uint32_t len;
    uint8_t flags;
    uint8_t prefix_len;
    uint8_t max_prefix_len;
    uint8_t zero;
    uint32_t prefix[4];
    uint32_t asn;
} pdu_ipv6;

typedef struct pdu_error{
    uint8_t ver;
    uint8_t type;
    uint16_t error_code;
    uint32_t len;
    uint32_t len_enc_pdu;
    uint8_t rest[];
} pdu_error;

/*
   0          8          16         24        31
   .-------------------------------------------.
   | Protocol |   PDU    |                     |
   | Version  |   Type   |    reserved = zero  |
   |    0     |    2     |                     |
   +-------------------------------------------+
   |                                           |
   |                 Length=8                  |
   |                                           |
   `-------------------------------------------'
 */
static const pdu_header pdu_reset_query =
{
    0, //sollte RTR_PROTOCOL_VERSION sein, aber gcc mag dat net:(
    2,
    0,
    8
};


static int rtr_receive_pdu(rtr_socket* rtr_socket, void* pdu, const size_t pdu_len, const time_t timeout);
static int rtr_send_error_pdu(const rtr_socket* rtr_socket, const void* erroneous_pdu, const uint32_t pdu_len, const pdu_error_type error, const char* text, const uint32_t text_len);
static void rtr_pdu_header_to_host_byte_order(void* pdu);
static void rtr_pdu_footer_to_host_byte_order(void* pdu);
static pdu_type rtr_get_pdu_type(const void* pdu);
static int rtr_handle_error_pdu(rtr_socket* rtr_socket, const void* buf);
static int rtr_send_pdu(const rtr_socket* rtr_socket, const void* pdu, const unsigned len);
static int rtr_update_pfx_table(rtr_socket* rtr_socket, const void* pdu);
static int rtr_set_last_update(rtr_socket* rtr_socket);


void rtr_change_socket_state(rtr_socket* rtr_socket, const rtr_socket_state new_state){
    if(rtr_socket->state == new_state)
        return;

    //RTR_SHUTDOWN state is final, rtr_socket will be shutdowned can't be switched to any other state
    if(rtr_socket->state == RTR_SHUTDOWN)
        return;

    rtr_socket->state = new_state;
    if(rtr_socket->connection_state_fp != NULL)
        rtr_socket->connection_state_fp(rtr_socket, new_state, rtr_socket->connection_state_fp_param);
}

void rtr_pdu_header_to_host_byte_order(void* pdu){
    pdu_header* header = pdu;
    uint16_t reserved_tmp =  ntohs(header->reserved);
    header->reserved = reserved_tmp;

    uint32_t len_tmp = ntohl(header->len);
    header->len = len_tmp;
}

inline pdu_type rtr_get_pdu_type(const void* pdu){
    return *((char*) pdu + 1);
}


void rtr_pdu_footer_to_host_byte_order(void* pdu){
    const pdu_type type = rtr_get_pdu_type(pdu);

    uint32_t int32_tmp;
    uint32_t addr6[4];

    switch(type){
        case SERIAL_NOTIFY:
            //same as EOD
        case EOD:
            int32_tmp = ntohl(((pdu_serial_notify*) pdu)->sn);
            ((pdu_serial_notify*) pdu)->sn = int32_tmp;
            break;
        case IPV4_PREFIX:
            int32_tmp = ntohl(((pdu_ipv4*) pdu)->prefix);
            ((pdu_ipv4*) pdu)->prefix = int32_tmp;

            int32_tmp = ntohl(((pdu_ipv4*) pdu)->asn);
            ((pdu_ipv4*) pdu)->asn = int32_tmp;
            break;
        case IPV6_PREFIX:
            ipv6_addr_to_host_byte_order(((pdu_ipv6*) pdu)->prefix, addr6);
            memcpy(((pdu_ipv6*) pdu)->prefix, addr6, sizeof(addr6));

            int32_tmp = ntohl(((pdu_ipv6*) pdu)->asn);
            ((pdu_ipv6*) pdu)->asn = int32_tmp;
            break;
        case ERROR:
            int32_tmp = ntohl(((pdu_error*) pdu)->len_enc_pdu);
            ((pdu_error*) pdu)->len_enc_pdu = int32_tmp;
            break;
        default:
            break;
    }
}

void rtr_pdu_to_network_byte_order(void* pdu){
    pdu_header* header = pdu;

    uint16_t int16_tmp =  htons(header->reserved);
    header->reserved = int16_tmp;

    uint32_t int32_tmp = htonl(header->len);
    header->len = int32_tmp;

    const pdu_type type = rtr_get_pdu_type(pdu);
    switch(type){
        case SERIAL_QUERY:
            int32_tmp = htonl(((pdu_serial_query*) pdu)->sn);
            ((pdu_serial_query*) pdu)->sn = int32_tmp;
            break;
        case ERROR:
            int32_tmp = htonl(((pdu_error*) pdu)->len_enc_pdu);
            ((pdu_error*) pdu)->len_enc_pdu = int32_tmp;
            break;
        default:
            break;
    }
}

/*
 * if RTR_ERROR was returned a error pdu was sent, and the socket state changed
 * @param pdu_len must >= RTR_MAX_PDU_LEN Bytes 
 * @return RTR_SUCCESS
 * @return RTR_ERROR, error pdu was sent and socket_state changed
 * @return TR_WOULDBLOCK
 */
int rtr_receive_pdu(rtr_socket* rtr_socket, void* pdu, const size_t pdu_len, const time_t timeout){
    //error values:
    // 0 = no_err
    // 1 = internal error
    // 2 = unknown pdu type
    // 4 = pdu to big
    // 8 = corrupt data
    // 16 = unknown pdu version
    int error = RTR_SUCCESS;

    assert(pdu_len >= RTR_MAX_PDU_LEN);
    //receive packet header
    if(rtr_socket->state == RTR_SHUTDOWN)
        return RTR_ERROR;
    error = tr_recv_all(rtr_socket->tr_socket, pdu, sizeof(pdu_header), timeout);
    if(error < 0)
        goto error;
    else
        error = 0;

    //header in hostbyte order, retain original received pdu, in case we need to detach it to an error pdu
    pdu_header header;
    memcpy(&header, pdu, sizeof(pdu_header));
    rtr_pdu_header_to_host_byte_order(&header);

    if(header.ver != RTR_PROTOCOL_VERSION){
        error = 16;
        goto error;
    }
    if(header.type > 10){
        error = 2;
        goto error;
    }

    //if header->len is < packet_header = corrupt data received
    if(header.len < sizeof(pdu_header)){
        error = 8;
        goto error;
    }
    else if(header.len > RTR_MAX_PDU_LEN){ //PDU too big, > than MAX_PDU_LEN Bytes
        error = 4;
        goto error;
    }

    //receive packet payload
    const unsigned int remaining_len = header.len - sizeof(pdu_header);
    if(remaining_len > 0){
        if(rtr_socket->state == RTR_SHUTDOWN)
            return RTR_ERROR;
        error = tr_recv_all(rtr_socket->tr_socket, (((char*) pdu) + sizeof(pdu_header)), remaining_len, RTR_RECV_TIMEOUT);
        if(error < 0)
            goto error;
        else
            error = 0;
    }
    memcpy(pdu, &header, sizeof(pdu_header)); //copy header in host_byte_order to pdu
    rtr_pdu_footer_to_host_byte_order(pdu);

    return RTR_SUCCESS;

error:
    //send error msg to server, including unmodified pdu header(pdu variable instead header)
    if(error == -1){
        rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
        return RTR_ERROR;
    }
    else if(error == TR_WOULDBLOCK){
        RTR_DBG1("receive timeout expired");
        return TR_WOULDBLOCK;
    }
    else if(error == TR_INTR){
        RTR_DBG1("receive call interrupted");
        return TR_INTR;
    }
    else if(error == 8){
        RTR_DBG1("corrupt PDU received");
        const char* txt = "corrupt data received, length value in PDU is too small";
        rtr_send_error_pdu(rtr_socket, pdu, sizeof(pdu_header), CORRUPT_DATA, txt, sizeof(txt));
    }
    else if(error == 4){
        RTR_DBG1("PDU too big");
        char txt[42];
        snprintf(txt, sizeof(txt),"PDU too big, max. PDU size is: %u bytes", RTR_MAX_PDU_LEN);
        RTR_DBG("%s", txt);
        rtr_send_error_pdu(rtr_socket, pdu, sizeof(pdu_header), CORRUPT_DATA, txt, sizeof(txt));
    }
    else if(error == 2){
            RTR_DBG1("Unsupported PDU type received");
            rtr_send_error_pdu(rtr_socket, pdu, header.len, UNSUPPORTED_PDU_TYPE, NULL, 0);
    }
    else if(error == 16){
            RTR_DBG1("PDU with unsupported Protocol version received");
            rtr_send_error_pdu(rtr_socket, pdu, header.len, UNSUPPORTED_PROTOCOL_VER, NULL, 0);
    }

    rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
    return RTR_ERROR;
}

int rtr_set_last_update(rtr_socket* rtr_socket){
    if(rtr_get_monotonic_time(&(rtr_socket->last_update)) == -1){
        RTR_DBG1("get_monotonic_time(..) failed ");
        rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
        return RTR_ERROR;
    }
    return RTR_SUCCESS;
}

int rtr_sync(rtr_socket* rtr_socket){
    char pdu[RTR_MAX_PDU_LEN];

    int rtval = rtr_receive_pdu(rtr_socket, pdu, RTR_MAX_PDU_LEN, RTR_RECV_TIMEOUT);
    if(rtval == TR_WOULDBLOCK){
        rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
        return RTR_ERROR;
    }
    else if(rtval < 0)
        return RTR_ERROR;
    pdu_type type = rtr_get_pdu_type(pdu);

    //ignore serial_notify PDUs, we already sent a serial_query, must be old messages
    while(type == SERIAL_NOTIFY){
        RTR_DBG1("Ignoring Serial Notify");
        rtval = rtr_receive_pdu(rtr_socket, pdu, RTR_MAX_PDU_LEN, RTR_RECV_TIMEOUT);
        if(rtval == TR_WOULDBLOCK){
            rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
            return RTR_ERROR;
        }
        else if(rtval < 0)
            return RTR_ERROR;
        type = rtr_get_pdu_type(pdu);
    }

    if(type == ERROR){
        rtr_handle_error_pdu(rtr_socket, pdu);
        return RTR_ERROR;
    }
    else if(type == CACHE_RESET){
        RTR_DBG1("Cache Reset PDU received");
        rtr_change_socket_state(rtr_socket, RTR_ERROR_NO_INCR_UPDATE_AVAIL);
        return RTR_ERROR;
    }

    if(type == CACHE_RESPONSE){
        RTR_DBG1("Cache Response PDU received");
        pdu_header* cr_pdu = (pdu_header*) pdu;
        //set connection nonce
        if(rtr_socket->request_nonce){
            if(rtr_socket->last_update != 0){
                //if this isnt the first sync, but we already received records, delete old records in the pfx_table
                pfx_table_src_remove(rtr_socket->pfx_table, (uintptr_t) rtr_socket);
                rtr_socket->last_update = 0;
            }
            rtr_socket->nonce = cr_pdu->reserved;
        }
        else{
            if(rtr_socket->nonce != cr_pdu->reserved){
                const char* txt = "Wrong NONCE in Cache Response PDU"; //TODO: Append rtr_socket->nonce to string
                rtr_send_error_pdu(rtr_socket, NULL, 0, CORRUPT_DATA, txt, sizeof(txt));
                rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
                return RTR_ERROR;
            }
        }
    }

    unsigned int received_prefixes = 0; //only for debug builds
    //receive IPV4/IPV6 PDUs till EOD
    do {
        rtval = rtr_receive_pdu(rtr_socket, pdu, RTR_MAX_PDU_LEN, RTR_RECV_TIMEOUT);
        if(rtval == TR_WOULDBLOCK){
            rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
            return RTR_ERROR;
        }
        else if(rtval < 0)
            return RTR_ERROR;
        type = rtr_get_pdu_type(pdu);
        if(type == IPV4_PREFIX || type == IPV6_PREFIX){
            received_prefixes++;
            if(rtr_update_pfx_table(rtr_socket, pdu) == RTR_ERROR)
                return RTR_ERROR;
        }
        else if(type == EOD){
            pdu_eod* eod_pdu = (pdu_eod*) pdu;

            if(eod_pdu->nonce != rtr_socket->nonce){
                char txt[67];
                snprintf(txt, sizeof(txt),"Expected Nonce: %u, received Nonce. %u in EOD PDU", rtr_socket->nonce, eod_pdu->nonce);
                rtr_send_error_pdu(rtr_socket, pdu, RTR_MAX_PDU_LEN, CORRUPT_DATA, txt, strlen(txt) + 1);
                rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
                return RTR_ERROR;
            }
            rtr_socket->serial_number = eod_pdu->sn;
        }
        else if(type == ERROR){
            rtr_handle_error_pdu(rtr_socket, pdu);
            return RTR_ERROR;
        }
        else if(type == SERIAL_NOTIFY){
            RTR_DBG1("Ignoring Serial Notify");
        }
        else{
            RTR_DBG("Received unexpected PDU (Type: %u)", ((pdu_header*) pdu)->type);
            const char* txt = "unexpected PDU received during data sync";
            rtr_send_error_pdu(rtr_socket, pdu, sizeof(pdu_header), CORRUPT_DATA, txt, sizeof(txt));
            return RTR_ERROR;
        }
    } while(type != EOD);
    rtr_socket->request_nonce = false;
    if (rtr_set_last_update(rtr_socket) == RTR_ERROR)
        return RTR_ERROR;
    RTR_DBG("Sync successfull, received %u Prefixes, Nonce: %u, SN: %u", received_prefixes, rtr_socket->nonce, rtr_socket->serial_number);
    return RTR_SUCCESS;
}

int rtr_update_pfx_table(rtr_socket* rtr_socket, const void* pdu){
    const pdu_type type = rtr_get_pdu_type(pdu);
    assert(type == IPV4_PREFIX || type == IPV6_PREFIX);

    pfx_record pfxr;
    size_t pdu_size = 0;

    if(type ==  IPV4_PREFIX){
        pdu_size = sizeof(pdu_ipv4);
        const pdu_ipv4* ipv4 = pdu;
        pfxr.prefix.u.addr4.addr = ipv4->prefix;
        pfxr.asn = ipv4->asn;
        pfxr.prefix.ver = IPV4;
        pfxr.min_len = ipv4->prefix_len;
        pfxr.max_len = ipv4->max_prefix_len;
        pfxr.socket_id = (uintptr_t) rtr_socket;
    }
    else if(type == IPV6_PREFIX){
        pdu_size = sizeof(pdu_ipv6);
        const pdu_ipv6* ipv6 = pdu;
        pfxr.asn = ipv6->asn;
        pfxr.prefix.ver = IPV6;
        memcpy(pfxr.prefix.u.addr6.addr, ipv6->prefix, sizeof(pfxr.prefix.u.addr6.addr));
        pfxr.min_len = ipv6->prefix_len;
        pfxr.max_len = ipv6->max_prefix_len;
        pfxr.socket_id = (uintptr_t) rtr_socket;
    }

    int rtval;
    if(((pdu_ipv4*) pdu)->flags == 1)
        rtval = pfx_table_add(rtr_socket->pfx_table, &pfxr);
    else if(((pdu_ipv4*) pdu)->flags == 0)
        rtval = pfx_table_remove(rtr_socket->pfx_table, &pfxr);
    else{
        const char* txt = "Prefix PDU with invalid flags value received";
        RTR_DBG("%s", txt);
        rtr_send_error_pdu(rtr_socket, pdu, pdu_size, CORRUPT_DATA, txt, sizeof(txt));
        return RTR_ERROR;
    }

    if(rtval == PFX_DUPLICATE_RECORD){
        char ip[INET6_ADDRSTRLEN];
        ip_addr_to_str(&(pfxr.prefix), ip, INET6_ADDRSTRLEN);
        RTR_DBG("Duplicate Announcement for record: %s/%u-%u, ASN: %u, received", ip, pfxr.min_len, pfxr.max_len, pfxr.asn);
        rtr_send_error_pdu(rtr_socket, pdu, pdu_size, DUPLICATE_ANNOUNCEMENT , NULL, 0);
        rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
        return RTR_ERROR;
    }
    else if(rtval == PFX_RECORD_NOT_FOUND){
        RTR_DBG1("Withdrawal of unknown record");
        rtr_send_error_pdu(rtr_socket, pdu, pdu_size, WITHDRAWAL_OF_UNKNOWN_RECORD, NULL, 0);
        rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
        return RTR_ERROR;
    }
    else if(rtval == PFX_ERROR){
        const char* txt = "Error during PFX add or remove operation";
        RTR_DBG("%s", txt);
        rtr_send_error_pdu(rtr_socket, pdu, pdu_size, INTERNAL_ERROR, txt, sizeof(txt));
        rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
        return RTR_ERROR;
    }

    return RTR_SUCCESS;
}

int rtr_wait_for_sync(rtr_socket* rtr_socket){
    char pdu[RTR_MAX_PDU_LEN]; 

    time_t cur_time;
    rtr_get_monotonic_time(&cur_time);
    time_t wait = (rtr_socket->last_update + rtr_socket->polling_period) - cur_time;
    if(wait < 0)
        wait = 0;

    RTR_DBG("waiting %jd sec. till next sync", (intmax_t) wait);
    const int rtval = rtr_receive_pdu(rtr_socket, pdu, sizeof(pdu), wait);
    if(rtval >= 0){
        pdu_type type = rtr_get_pdu_type(pdu);
        if(type == SERIAL_NOTIFY){
            RTR_DBG1("Serial Notify received");
                return RTR_SUCCESS;
        }
    }
    else if(rtval == TR_WOULDBLOCK){
        RTR_DBG1("Polling period expired");
        return RTR_SUCCESS;
    }
    return RTR_ERROR;
}

int rtr_send_error_pdu(const rtr_socket* rtr_socket, const void* erroneous_pdu, const uint32_t pdu_len, const pdu_error_type error, const char* text, const uint32_t text_len){
    //dont send errors for erroneous error PDUs
    if(pdu_len >= 2){
        if(rtr_get_pdu_type(erroneous_pdu) == ERROR )
            return RTR_SUCCESS;
    }

    unsigned int msg_size = 16 + pdu_len + text_len;
    char msg[msg_size];
    bzero(msg, sizeof(msg));
    pdu_header* header = (pdu_header*) msg;
    header->ver = RTR_PROTOCOL_VERSION;
    header->type = 10;
    header->reserved = error;
    header->len = msg_size;

    memcpy(msg+8, &pdu_len, sizeof(pdu_len));
    if(pdu_len > 0)
        memcpy(msg + 12, erroneous_pdu, pdu_len);
    *(msg + 12 + pdu_len) = htonl(text_len);
    if(text_len > 0)
        memcpy(msg+16+pdu_len, text, text_len);

    return rtr_send_pdu(rtr_socket, msg, msg_size);
}

int rtr_send_pdu(const rtr_socket* rtr_socket, const void* pdu, const unsigned len){
    char pdu_converted[len];
    memcpy(pdu_converted, pdu, len);
    rtr_pdu_to_network_byte_order(pdu_converted);
    if(rtr_socket->state == RTR_SHUTDOWN)
        return RTR_ERROR;
    const int rtval = tr_send_all(rtr_socket->tr_socket, pdu_converted, len, RTR_SEND_TIMEOUT);

    if(rtval > 0)
        return RTR_SUCCESS;
    if(rtval == TR_WOULDBLOCK){
        RTR_DBG1("send would block");
        return RTR_ERROR;
    }

    RTR_DBG1("Error sending PDU");
    return RTR_ERROR;
}

int rtr_handle_error_pdu(rtr_socket* rtr_socket, const void* buf){
    RTR_DBG1("Error PDU received");  //TODO: append server ip & port
    const pdu_error* pdu = buf;

    switch(pdu->error_code){
        case CORRUPT_DATA:
            RTR_DBG1("Corrupt data received");
            rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
            break;
        case INTERNAL_ERROR:
            RTR_DBG1("Internal error on server-side");
            rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
            break;
        case NO_DATA_AVAIL:
            RTR_DBG1("No data available");
            rtr_change_socket_state(rtr_socket, RTR_ERROR_NO_DATA_AVAIL);
            break;
        case INVALID_REQUEST:
            RTR_DBG1("Invalid request from client");
            rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
            break;
        case UNSUPPORTED_PROTOCOL_VER:
            RTR_DBG1("Client uses unsupported protocol version");
            rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
            break;
        case UNSUPPORTED_PDU_TYPE:
            RTR_DBG1("Client set unsupported PDU type");
            rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
            break;
        default:
            RTR_DBG("error unknown, server sent unsupported error code %u", pdu->error_code);
            rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
            break;
    }

    const uint32_t len_err_txt = ntohl(*((uint32_t*) ((pdu->rest) + pdu->len_enc_pdu)));
    if(len_err_txt > 0){
        if((sizeof(pdu->ver) + sizeof(pdu->type) + sizeof(pdu->error_code) + sizeof(pdu->len) + sizeof(pdu->len_enc_pdu) + pdu->len_enc_pdu + 4 + len_err_txt) != pdu->len)
            RTR_DBG1("error: Length of error text contains an incorrect value");
        else{
            //assure that the error text contains an terminating \0 char
            char txt[len_err_txt + 1];
            char* pdu_txt = (char*) pdu->rest + pdu->len_enc_pdu + 4;
            snprintf(txt, len_err_txt + 1, "%s", pdu_txt);
            RTR_DBG("Error PDU included the following error msg: \'%s\'", txt);
        }
    }

    return RTR_SUCCESS;
}

int rtr_send_serial_query(rtr_socket* rtr_socket){
    pdu_serial_query pdu;
    pdu.ver = RTR_PROTOCOL_VERSION;
    pdu.type = SERIAL_QUERY;
    pdu.nonce = rtr_socket->nonce;
    pdu.len = sizeof(pdu);
    pdu.sn = rtr_socket->serial_number;

    RTR_DBG("sending serial query, SN: %u", rtr_socket->serial_number);
    if(rtr_send_pdu(rtr_socket, &pdu, sizeof(pdu)) != RTR_SUCCESS){
        rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
        return RTR_ERROR;
    }
    return RTR_SUCCESS;
}

int rtr_send_reset_query(rtr_socket* rtr_socket){
    if(rtr_send_pdu(rtr_socket, &pdu_reset_query, sizeof(pdu_reset_query)) != RTR_SUCCESS){
        rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
        return RTR_ERROR;
    }
    return RTR_SUCCESS;
}
