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

#include "encap_info.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>
#include <wiretap/wtap.h>

#include <iostream>

#include "encap_info.capnp.h"

namespace sharkdb {

int encap_info() {
    kj::std::StdOutputStream out_stream{ std::cout };
    const auto num_encaps = wtap_get_num_encap_types();
    for (auto i = -1; i < num_encaps; ++i) {
        auto name = wtap_encap_name(i);
        auto desc = wtap_encap_description(i);

        capnp::MallocMessageBuilder message;
        auto msg = message.initRoot<Encap>();
        msg.setId(i);
        msg.setName(name);
        msg.setDescription(desc);

        capnp::writeMessage(out_stream, message);
    }
    return 0;
}

} // namespace sharkdb
