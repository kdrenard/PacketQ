/*
 * Copyright (c) 2017-2021, OARC, Inc.
 * Copyright (c) 2011-2017, IIS - The Internet Foundation in Sweden
 * All rights reserved.
 *
 * This file is part of PacketQ.
 *
 * PacketQ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PacketQ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PacketQ.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __packetq_packet_handler_h
#define __packetq_packet_handler_h

#include <assert.h>
#include <cctype>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "sql.h"
#include "tcp.h"

#define IPPROTO_ICMP 1

namespace packetq {

class Table;
class Row;

inline int get_int_h(unsigned char* data)
{
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

inline int get_short_h(unsigned char* data)
{
    return data[0] | (data[1] << 8);
}

inline int get_int(unsigned char* data)
{
    return data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
}

inline int get_short(unsigned char* data)
{
    return data[1] | (data[0] << 8);
}

RefCountString* v4_addr2str(in6addr_t& addr);
RefCountString* v6_addr2str(in6addr_t& addr);

class Payload {
public:
    char m_p[0x10000];
    int  m_size;
    Payload()
    {
        m_size = sizeof(m_p);
    }
    inline char* alloc(int size)
    {
        if (size > m_size)
            return 0;
        return m_p;
    }
};

class NetMasks {
public:
    NetMasks () {
        set_netmask (24, 48);
    };

    void set_netmask (char *arg) {
	char *cp1, *cp2, *end;
	int v4_bits, v6_bits;

	if (arg == NULL) return;
	cp1 = arg;
        cp2 = strchr (arg, ':');
	if (cp2 != NULL)
            *cp2++ = (char)0;
        v4_bits = strtol (cp1, &end, 10);
	if (cp1 == end)
            v4_bits = 24;
	if (cp2 != NULL) {
            v6_bits = strtol (cp2, &end, 10);
            if (cp2 == end) v6_bits = 48;
	} else {
            v6_bits = 48;
	}
	set_netmask (v4_bits, v6_bits);
	return;
    }
    void set_netmask (int v4_mask_size, int v6_mask_size) {
	if (v4_mask_size > 32)
            v4_mask_size = 32;
	else if (v4_mask_size < 0)
            v4_mask_size = 0;
        v4_subnet_mask.__in6_u.__u6_addr32[3] = (int32_t) 0x80000000 >> (v4_mask_size - 1);

	if (v6_mask_size > 128)
            v6_mask_size = 128;
	else if (v6_mask_size < 0)
            v6_mask_size = 0;
        for (int i = 0; i < 4; i++) {
            if (v6_mask_size >= 32)
                v6_subnet_mask.__in6_u.__u6_addr32[3-i] = 0xffffffff;
            else
                v6_subnet_mask.__in6_u.__u6_addr32[3-i] = (int32_t)0x80000000 >> (v6_mask_size - 1);
            v6_mask_size -= 32;
            if (v6_mask_size <= 0) break;
        }
        return;
    }
    in6addr_t v4_subnet_mask;
    in6addr_t v6_subnet_mask;
};

class IP_header {
public:
    IP_header()
        : s(0)
        , us(0)
        , ethertype(0)
        , src_port(0)
        , dst_port(0)
        , proto(0)
        , ip_ttl(0)
        , ip_version(0)
        , id(0)
        , length(0)
        , fragments(0)
        , ident(0)
        , offset(0)
    {
        memset(&src_ip, 0, sizeof(src_ip));
        memset(&dst_ip, 0, sizeof(dst_ip));
        memset(&src_subnet, 0, sizeof(src_subnet));
        memset(&dst_subnet, 0, sizeof(dst_subnet));
    }

    void           reset();
    int            decode(unsigned char* data, int ether_type, int id);
    unsigned int   s;
    unsigned int   us;
    unsigned short ethertype;
    in6addr_t      src_ip;
    in6addr_t      dst_ip;
    in6addr_t      src_subnet;
    in6addr_t      dst_subnet;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short proto;
    unsigned short ip_ttl;
    unsigned short ip_version;
    unsigned int   id;
    unsigned int   length;
    unsigned int   fragments;
    unsigned int   ident;
    unsigned int   offset;
};

class Packet_handler;

class IP_header_to_table {
public:
    enum {
        COLUMN_ID,
        COLUMN_S,
        COLUMN_US,
        COLUMN_ETHER_TYPE,
        COLUMN_PROTOCOL,
        COLUMN_IP_TTL,
        COLUMN_IP_VERSION,
        COLUMN_SRC_PORT,
        COLUMN_DST_PORT,
        COLUMN_SRC_ADDR,
        COLUMN_DST_ADDR,
        COLUMN_SRC_SUBNET,
        COLUMN_DST_SUBNET,
        COLUMN_FRAGMENTS
    };

    void add_packet_columns(Packet_handler& packet_handler);
    void on_table_created(Table* table, const std::vector<int>& columns);
    void assign(Row* row, IP_header* head, const std::vector<int>& columns);

private:
    Int_accessor  acc_id;
    Int_accessor  acc_s;
    Int_accessor  acc_us;
    Int_accessor  acc_ether_type;
    Int_accessor  acc_protocol;
    Int_accessor  acc_ip_ttl;
    Int_accessor  acc_ip_version;
    Int_accessor  acc_src_port;
    Int_accessor  acc_dst_port;
    Int_accessor  acc_fragments;
    Text_accessor acc_src_addr;
    Text_accessor acc_dst_addr;
    Text_accessor acc_src_subnet;
    Text_accessor acc_dst_subnet;
};

class Packet {
public:
    enum ParseResult {
        ERROR,
        OK,
        NOT_SAMPLED
    };

    Packet(unsigned char* data, int len, int s, int us, int id, int link_layer_type)
    {
        m_s               = s;
        m_us              = us;
        m_data            = data;
        m_len             = len;
        m_id              = id;
        m_link_layer_type = link_layer_type;
    }

    ParseResult parse(Packet_handler* handler, const std::vector<int>& columns, Row& destination_row, bool sample);
    bool        parse_ethernet();
    bool        parse_ip(unsigned char* data, int len, int ether_type);
    bool        parse_transport(unsigned char* data, int len);

    IP_header      m_ip_header;
    unsigned char* m_data;
    int            m_len;
    int            m_s;
    int            m_us;
    int            m_id;
    int            m_link_layer_type;
};

struct Packet_column {
    const char*   name;
    const char*   description;
    int           id;
    Coltype::Type type;
};

class Packet_handler {
public:
    Packet_handler()
        : table_name(0)
    {
    }
    virtual ~Packet_handler()
    {
    }

    Table* create_table(const std::vector<int>& columns);

    // for actual packet handlers to fill in
    virtual void                on_table_created(Table* table, const std::vector<int>& columns)                           = 0;
    virtual Packet::ParseResult parse(Packet& packet, const std::vector<int>& columns, Row& destination_row, bool sample) = 0;

    const char*                table_name;
    std::vector<Packet_column> packet_columns;

    void add_packet_column(const char* name, const char* description, Coltype::Type type, int id);
};

void            init_packet_handlers(bool escape_dnsnames);
void            destroy_packet_handlers();
Packet_handler* get_packet_handler(std::string table_name);

} // namespace packetq

#endif // __packetq_packet_handler_h
