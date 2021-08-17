/* SharkDB backend Wireshark engine.
 * Copyright (C) 2021  Jack Bernard
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "proto_info.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <kj/std/iostream.h>

#include <iostream>

#include "sharkdb_proto_info.capnp.h"

namespace sharkdb {

template <typename F>
void foreach_heur_cb(void* data, void* user_data) {
    auto callback = *reinterpret_cast<F*>(user_data);
    callback(reinterpret_cast<heur_dtbl_entry_t*>(data));
}

template <typename F>
void foreach_heur(protocol_t* proto, F&& callback) {
    proto_heuristic_dissector_foreach(proto, &foreach_heur_cb<F>, &callback);
}

static void visit_protocol_field(header_field_info* field, Field::TypeInfo::Protocol::Builder out) {
    auto name = out.initProtoName();
    if (field->strings != nullptr) {
        name.setSome(
            proto_get_protocol_short_name(reinterpret_cast<const protocol_t*>(field->strings)));
    }
}

static void visit_boolean_field(header_field_info* field, Field::TypeInfo::Boolean::Builder out) {
    auto strings = out.initStrings();
    if (field->strings != nullptr && (field->display & BASE_CUSTOM) == 0) {
        auto some = strings.initSome();
        auto tfs = reinterpret_cast<const true_false_string*>(field->strings);
        some.setTrue(tfs->true_string);
        some.setFalse(tfs->false_string);
    }
}

static void visit_int_field(header_field_info* field,
                            Field::TypeInfo::Int::Builder out,
                            IntType type) {
    out.setType(type);
    auto strings = out.initStrings();
    if (field->strings != nullptr && (field->display & BASE_CUSTOM) == 0) {
        if ((field->display & BASE_UNIT_STRING) != 0) {
            auto ustr = reinterpret_cast<const unit_name_string*>(field->strings);
            auto unit = strings.initSomeUnit();
            unit.setSingular(ustr->singular);
            auto plural = unit.initPlural();
            if (ustr->plural != nullptr) { plural.setSome(ustr->plural); }
        } else if ((field->display & BASE_RANGE_STRING) != 0) {
            auto rstr = reinterpret_cast<const range_string*>(field->strings);
            std::size_t rstr_count = 0;
            while (rstr[rstr_count].strptr != nullptr) { rstr_count++; }
            auto rstr_out = strings.initSomeRange(rstr_count);
            for (std::size_t i = 0; i < rstr_count; ++i) {
                rstr_out[i].setMin(rstr[i].value_min);
                rstr_out[i].setMax(rstr[i].value_max);
                rstr_out[i].setString(rstr[i].strptr);
            }
        } else if ((field->display & BASE_VAL64_STRING) != 0) {
            const val64_string* vstr;
            if ((field->display & BASE_EXT_STRING) != 0) {
                vstr = reinterpret_cast<const val64_string_ext*>(field->strings)->_vs_p;
            } else {
                vstr = reinterpret_cast<const val64_string*>(field->strings);
            }
            std::size_t vstr_count = 0;
            while (vstr[vstr_count].strptr != nullptr) { vstr_count++; }
            auto vstr_out = strings.initSome64(vstr_count);
            for (std::size_t i = 0; i < vstr_count; ++i) {
                vstr_out[i].setValue(vstr[i].value);
                vstr_out[i].setString(vstr[i].strptr);
            }
        } else {
            const value_string* vstr;
            if ((field->display & BASE_EXT_STRING) != 0) {
                vstr = reinterpret_cast<const value_string_ext*>(field->strings)->_vs_p;
            } else {
                vstr = reinterpret_cast<const value_string*>(field->strings);
            }
            std::size_t vstr_count = 0;
            while (vstr[vstr_count].strptr != nullptr) { vstr_count++; }
            auto vstr_out = strings.initSome32(vstr_count);
            for (std::size_t i = 0; i < vstr_count; ++i) {
                vstr_out[i].setValue(vstr[i].value);
                vstr_out[i].setString(vstr[i].strptr);
            }
        }
    }

    switch (field->display & 0xFF) {
    case BASE_DEC:
        out.setDisplay(IntDisplay::DEC);
        break;
    case BASE_HEX:
        out.setDisplay(IntDisplay::HEX);
        break;
    case BASE_OCT:
        out.setDisplay(IntDisplay::OCT);
        break;
    case BASE_DEC_HEX:
        out.setDisplay(IntDisplay::DEC_HEX);
        break;
    case BASE_HEX_DEC:
        out.setDisplay(IntDisplay::HEX_DEC);
        break;
    case BASE_CUSTOM:
        out.setDisplay(IntDisplay::CUSTOM);
        break;
    case BASE_PT_UDP:
        out.setDisplay(IntDisplay::UDP_PORT);
        break;
    case BASE_PT_TCP:
        out.setDisplay(IntDisplay::TCP_PORT);
        break;
    case BASE_PT_DCCP:
        out.setDisplay(IntDisplay::DCCP_PORT);
        break;
    case BASE_PT_SCTP:
        out.setDisplay(IntDisplay::SCTP_PORT);
        break;
    case BASE_OUI:
        out.setDisplay(IntDisplay::OUI);
        break;
    default:
        out.setDisplay(IntDisplay::NONE);
        break;
    }
}

static void visit_float_field(header_field_info* field,
                              Field::TypeInfo::Float::Builder out,
                              FloatType type) {
    out.setType(type);
    auto strings = out.initStrings();
    if (field->strings != nullptr && (field->display & BASE_UNIT_STRING) != 0 &&
        (field->display & BASE_CUSTOM) == 0) {
        auto ustr = reinterpret_cast<const unit_name_string*>(field->strings);
        auto unit = strings.initSome();
        unit.setSingular(ustr->singular);
        auto plural = unit.initPlural();
        if (ustr->plural != nullptr) { plural.setSome(ustr->plural); }
    }
}

static void visit_string_field(header_field_info* field,
                               Field::TypeInfo::String::Builder out,
                               StringType type) {
    out.setType(type);
    if ((field->display & 0xFF) == STR_UNICODE) {
        out.setDisplay(StringDisplay::UNICODE);
    } else {
        out.setDisplay(StringDisplay::ASCII);
    }
}

static void visit_bytes_field(header_field_info* field,
                              Field::TypeInfo::Bytes::Builder out,
                              bool is_uint) {
    out.setIsUint(is_uint);
    switch (field->display & 0xFF) {
    case SEP_DOT:
        out.setSeparator(BytesSeparator::DOT);
        break;
    case SEP_DASH:
        out.setSeparator(BytesSeparator::DASH);
        break;
    case SEP_COLON:
        out.setSeparator(BytesSeparator::COLON);
        break;
    case SEP_SPACE:
        out.setSeparator(BytesSeparator::SPACE);
        break;
    default:
        out.setSeparator(BytesSeparator::NONE);
        break;
    }
}

static void visit_time_field([[maybe_unused]] header_field_info* field,
                             Field::TypeInfo::Time::Builder out,
                             bool is_rel) {
    out.setIsRelative(is_rel);
}

static void visit_ipv4_field(header_field_info* field, Field::TypeInfo::Ipv4::Builder out) {
    if ((field->display & 0xFF) == BASE_NETMASK) {
        out.setDisplay(Ipv4Display::NETMASK);
    } else {
        out.setDisplay(Ipv4Display::ADDRESS);
    }
}

static void visit_proto(int id, protocol_t* proto, Proto::Builder out) {
    if (proto == nullptr) { return; }

    out.setShortName(proto_get_protocol_short_name(proto));
    out.setLongName(proto_get_protocol_long_name(proto));
    out.setFilterName(proto_get_protocol_filter_name(id));
    out.setEnabled(proto_is_protocol_enabled_by_default(proto) != 0);
    out.setCanDisable(proto_can_toggle_protocol(id) != 0);
    out.setIsPino(proto_is_pino(proto) != 0);

    std::size_t heur_count = 0;
    foreach_heur(proto, [&heur_count](auto heur) { ++heur_count; });
    auto heurs_out = out.initHeuristicDissectors(heur_count);
    std::size_t idx = 0;
    foreach_heur(proto, [&heurs_out, &idx](auto heur) {
        if (heur == nullptr) { return; }

        auto heur_out = heurs_out[idx];
        heur_out.setListName(heur->list_name);
        heur_out.setDisplayName(heur->display_name);
        heur_out.setShortName(heur->display_name);
        heur_out.setEnabled(heur->enabled != 0);

        ++idx;
    });

    std::size_t field_count = 0;
    void* cookie = nullptr;
    auto field = proto_get_first_protocol_field(id, &cookie);
    while (field != nullptr) {
        ++field_count;
        field = proto_get_next_protocol_field(id, &cookie);
    }
    auto fields_out = out.initFields(field_count);
    cookie = nullptr;
    field = proto_get_first_protocol_field(id, &cookie);
    idx = 0;
    while (field != nullptr) {
        auto field_out = fields_out[idx];

        field_out.setName(field->name);
        field_out.setAbbrev(field->abbrev);
        auto desc = field_out.initDescription();
        if (field->blurb != nullptr) { desc.setSome(field->blurb); }
        field_out.setBitmask(field->bitmask);

        auto type = field_out.initTypeInfo();
        switch (field->type) {
        case FT_PROTOCOL:
            visit_protocol_field(field, type.initProtocol());
            break;
        case FT_BOOLEAN:
            visit_boolean_field(field, type.initBoolean());
            break;
        case FT_CHAR:
            visit_int_field(field, type.initInt(), IntType::CHAR);
            break;
        case FT_UINT8:
            visit_int_field(field, type.initInt(), IntType::UINT8);
            break;
        case FT_UINT16:
            visit_int_field(field, type.initInt(), IntType::UINT16);
            break;
        case FT_UINT24:
            visit_int_field(field, type.initInt(), IntType::UINT24);
            break;
        case FT_UINT32:
            visit_int_field(field, type.initInt(), IntType::UINT32);
            break;
        case FT_UINT40:
            visit_int_field(field, type.initInt(), IntType::UINT40);
            break;
        case FT_UINT48:
            visit_int_field(field, type.initInt(), IntType::UINT48);
            break;
        case FT_UINT56:
            visit_int_field(field, type.initInt(), IntType::UINT56);
            break;
        case FT_UINT64:
            visit_int_field(field, type.initInt(), IntType::INT64);
            break;
        case FT_INT8:
            visit_int_field(field, type.initInt(), IntType::INT8);
            break;
        case FT_INT16:
            visit_int_field(field, type.initInt(), IntType::INT16);
            break;
        case FT_INT24:
            visit_int_field(field, type.initInt(), IntType::INT24);
            break;
        case FT_INT32:
            visit_int_field(field, type.initInt(), IntType::INT32);
            break;
        case FT_INT40:
            visit_int_field(field, type.initInt(), IntType::INT40);
            break;
        case FT_INT48:
            visit_int_field(field, type.initInt(), IntType::INT48);
            break;
        case FT_INT56:
            visit_int_field(field, type.initInt(), IntType::INT56);
            break;
        case FT_INT64:
            visit_int_field(field, type.initInt(), IntType::INT64);
            break;
        case FT_IEEE_11073_SFLOAT:
            visit_float_field(field, type.initFloat(), FloatType::IEEE11073_SFLOAT);
            break;
        case FT_IEEE_11073_FLOAT:
            visit_float_field(field, type.initFloat(), FloatType::IEEE11073_FLOAT);
            break;
        case FT_FLOAT:
            visit_float_field(field, type.initFloat(), FloatType::FLOAT);
            break;
        case FT_DOUBLE:
            visit_float_field(field, type.initFloat(), FloatType::DOUBLE);
            break;
        case FT_ABSOLUTE_TIME:
            visit_time_field(field, type.initTime(), false);
            break;
        case FT_RELATIVE_TIME:
            visit_time_field(field, type.initTime(), true);
            break;
        case FT_STRING:
            visit_string_field(field, type.initString(), StringType::STRING);
            break;
        case FT_STRINGZ:
            visit_string_field(field, type.initString(), StringType::STRINGZ);
            break;
        case FT_UINT_STRING:
            visit_string_field(field, type.initString(), StringType::UINT_STRING);
            break;
        case FT_STRINGZPAD:
            visit_string_field(field, type.initString(), StringType::STRINGZ_PAD);
            break;
        case FT_STRINGZTRUNC:
            visit_string_field(field, type.initString(), StringType::STRINGZ_TRUNC);
            break;
        case FT_BYTES:
            visit_bytes_field(field, type.initBytes(), false);
            break;
        case FT_UINT_BYTES:
            visit_bytes_field(field, type.initBytes(), true);
            break;
        case FT_IPv4:
            visit_ipv4_field(field, type.initIpv4());
            break;
        case FT_IPv6:
            type.setIpv6();
            break;
        case FT_ETHER:
            type.setEther();
            break;
        case FT_IPXNET:
            type.setIpxnet();
            break;
        case FT_FRAMENUM:
            type.setFramenum();
            break;
        case FT_GUID:
            type.setGuid();
            break;
        case FT_OID:
            type.setOid();
            break;
        case FT_EUI64:
            type.setEui64();
            break;
        case FT_AX25:
            type.setAx25();
            break;
        case FT_VINES:
            type.setVines();
            break;
        case FT_REL_OID:
            type.setRelOid();
            break;
        case FT_SYSTEM_ID:
            type.setSystemId();
            break;
        case FT_FCWWN:
            type.setFcwwn();
            break;
        default:
            type.setNone();
            break;
        }

        field = proto_get_next_protocol_field(id, &cookie);
        ++idx;
    }
}

int proto_info() {
    kj::std::StdOutputStream out_stream{ std::cout };
    void* cookie = nullptr;
    auto id = proto_get_first_protocol(&cookie);
    protocol_t* proto = nullptr;
    while ((proto = find_protocol_by_id(id)) != nullptr) {
        capnp::MallocMessageBuilder message;
        auto msg = message.initRoot<Proto>();
        visit_proto(id, proto, msg);
        capnp::writeMessage(out_stream, message);
        id = proto_get_next_protocol(&cookie);
    }
    return 0;
}

} // namespace sharkdb
