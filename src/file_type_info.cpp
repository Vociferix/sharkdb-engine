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

#include "file_type_info.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>
#include <wiretap/wtap.h>

#include <iostream>

#include "file_type_info.capnp.h"

namespace sharkdb {

static std::string_view to_strv(const char* s) {
    return s == nullptr ? std::string_view() : std::string_view(s);
}

int file_type_info() {
    kj::std::StdOutputStream out_stream{ std::cout };
    const auto num_file_types = wtap_get_num_file_types_subtypes();
    for (auto i = 0; i < num_file_types; ++i) {
        auto lname = wtap_file_type_subtype_string(i);
        auto sname = wtap_file_type_subtype_short_string(i);
        auto default_ext = to_strv(wtap_default_file_extension(i));

        if (sname == nullptr) { continue; }

        capnp::MallocMessageBuilder message;
        auto msg = message.initRoot<FileType>();
        msg.setId(i);
        msg.setName(sname);
        msg.setDescription(lname);

        auto exts = wtap_get_file_extensions_list(i, 0);
        auto e = exts;
        std::size_t default_idx = 0;
        std::size_t idx = 0;
        while (e != nullptr) {
            if (e->data != nullptr) {
                if (default_idx == 0 &&
                    default_ext == to_strv(reinterpret_cast<const char*>(e->data))) {
                    default_idx = idx;
                }
                ++idx;
            }
            e = e->next;
        }
        msg.setDefaultExtension(default_idx);

        auto exts_out = msg.initExtensions(idx);
        idx = 0;
        e = exts;
        while (e != nullptr) {
            if (e->data != nullptr) { exts_out.set(idx++, reinterpret_cast<const char*>(e->data)); }
            e = e->next;
        }
        wtap_free_extensions_list(exts);

        capnp::writeMessage(out_stream, message);
    }
    return 0;
}

} // namespace sharkdb
