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

#include <glib.h>
#include <wsutil/privileges.h>

#include <iostream>
#include <string_view>

#include "read.hpp"

void help(const char* prog) { std::cerr << "Usage: " << prog << " [ read | dissect ]\n"; }

void init() {
    init_process_policies();
    relinquish_special_privs_perm();
}

int main(int argc, char** argv) {
    constexpr std::string_view read = "read";
    constexpr std::string_view dissect = "dissect";

    if (argc < 2) {
        help(*argv);
        return 1;
    }

    if (argc > 2) {
        std::cerr << "Unexpected arguments:";
        if (argv[1] == read || argv[1] == dissect) {
            for (int i = 2; i < argc; ++i) { std::cerr << ' ' << argv[i]; }
        } else {
            for (int i = 1; i < argc; ++i) { std::cerr << ' ' << argv[i]; }
        }
        std::cerr << '\n';
        help(*argv);
        return 1;
    }

    if (argv[1] == read) {
        init();
        return sharkdb::read();
    } else if (argv[1] == dissect) {
        init();
        std::cerr << "dissect mode\n";
        return 0;
    }

    std::cerr << "Unexpected argument: " << argv[1] << '\n';
    help(*argv);
    return 1;
}
