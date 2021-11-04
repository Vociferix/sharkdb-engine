#include "decode_as_info.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <epan/decode_as.h>
#include <epan/packet.h>
#include <kj/std/iostream.h>

#include <iomanip>
#include <iostream>

#include "decode_as_info.capnp.h"

namespace sharkdb {

template <typename F>
void foreach_decode_as_option_impl([[maybe_unused]] const gchar* table_name,
                                   const gchar* proto_name,
                                   gpointer value,
                                   gpointer user_data) {
    auto handle = reinterpret_cast<dissector_handle_t>(value);
    (*reinterpret_cast<F*>(user_data))(proto_name, handle);
}

template <typename F>
void foreach_decode_as_option(decode_as_t* entry, F&& callback) {
    entry->populate_list(entry->table_name, &foreach_decode_as_option_impl<F>, &callback);
}

UIntDisplay param_to_display(int param) {
    switch (param) {
    case BASE_DEC:
        return UIntDisplay::DEC;
    case BASE_HEX:
        return UIntDisplay::HEX;
    case BASE_DEC_HEX:
        return UIntDisplay::DEC_HEX;
    case BASE_HEX_DEC:
        return UIntDisplay::HEX_DEC;
    default:
        return UIntDisplay::NONE;
    }
}

int decode_as_info() {
    kj::std::StdOutputStream out_stream{ std::cout };
    auto list = decode_as_list;
    while (list != nullptr) {
        capnp::MallocMessageBuilder message;
        auto msg = message.initRoot<DecodeAs>();

        auto info = reinterpret_cast<decode_as_t*>(list->data);
        msg.setProto(info->name);
        msg.setTable(info->table_name);
        msg.setTitle(get_dissector_table_ui_name(info->table_name));
        auto type = get_dissector_table_selector_type(info->table_name);
        auto param = get_dissector_table_param(info->table_name);
        auto selector = msg.initSelector();
        switch (type) {
        case FT_UINT8: {
            auto uint = selector.initUint();
            uint.setType(UIntType::UINT8);
            uint.setDisplay(param_to_display(param));
        } break;
        case FT_UINT16: {
            auto uint = selector.initUint();
            uint.setType(UIntType::UINT16);
            uint.setDisplay(param_to_display(param));
        } break;
        case FT_UINT24: {
            auto uint = selector.initUint();
            uint.setType(UIntType::UINT24);
            uint.setDisplay(param_to_display(param));
        } break;
        case FT_UINT32: {
            auto uint = selector.initUint();
            uint.setType(UIntType::UINT32);
            uint.setDisplay(param_to_display(param));
        } break;
        case FT_STRING: {
            auto str = selector.initString();
            str.setType(StringType::STRING);
            str.setCaseSensitive(param != 0);
        } break;
        case FT_STRINGZ: {
            auto str = selector.initString();
            str.setType(StringType::STRINGZ);
            str.setCaseSensitive(param != 0);
        } break;
        case FT_STRINGZPAD: {
            auto str = selector.initString();
            str.setType(StringType::STRINGZPAD);
            str.setCaseSensitive(param != 0);
        } break;
        case FT_STRINGZTRUNC: {
            auto str = selector.initString();
            str.setType(StringType::STRINGZTRUNC);
            str.setCaseSensitive(param != 0);
        } break;
        case FT_GUID:
            selector.setGuid();
            break;
        case FT_NONE:
        default:
            break;
        }

        std::size_t option_count = 0;
        foreach_decode_as_option(
            info,
            [&option_count](auto proto_name, [[maybe_unused]] auto handle) { ++option_count; });

        std::size_t idx = 0;
        auto options = msg.initOptions(option_count);
        foreach_decode_as_option(info,
                                 [&options, &idx](auto proto_name, [[maybe_unused]] auto handle) {
                                     options.set(idx++, proto_name);
                                 });

        capnp::writeMessage(out_stream, message);
        list = list->next;
    }
    return 0;
}

} // namespace sharkdb
