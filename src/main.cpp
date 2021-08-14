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

#include <epan/color_filters.h>
#include <epan/epan.h>
#include <epan/print.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <glib.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>

#include <array>
#include <iostream>
#include <string_view>

#include "pref_info.hpp"
#include "read.hpp"

void help(const char* prog) {
    std::cerr << "Usage: " << prog << " [ read | dissect | pref-info ]\n";
}

void init() {
    init_process_policies();
    relinquish_special_privs_perm();
}

int main(int argc, char** argv) {
    constexpr std::string_view read = "read";
    constexpr std::string_view dissect = "dissect";
    constexpr std::string_view pref_info = "pref-info";

    constexpr std::string_view modes[] = { read, dissect, pref_info };

    if (argc < 2) {
        help(*argv);
        return 1;
    }

    if (argc > 2) {
        std::cerr << "Unexpected arguments:";
        bool is_mode = false;
        for (const auto& mode : modes) {
            if (argv[1] == mode) {
                is_mode = true;
                break;
            }
        }
        if (is_mode) {
            for (int i = 2; i < argc; ++i) { std::cerr << ' ' << argv[i]; }
        } else {
            for (int i = 1; i < argc; ++i) { std::cerr << ' ' << argv[i]; }
        }
        std::cerr << '\n';
        help(*argv);
        return 1;
    }

    init_process_policies();
    relinquish_special_privs_perm();
    auto err_msg = init_progfile_dir(argv[0]);
    if (err_msg != nullptr) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
        return 1;
    }
#ifdef _WIN32
    ws_init_dll_search_path();
    load_wpcap();
#endif
    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
    wtap_init(1);
    if (epan_init(nullptr, nullptr, 1) == 0) { return 1; }
    register_all_plugin_tap_listeners();
    epan_load_settings();
    output_fields_new();
    if (color_filters_init(&err_msg, nullptr) == 0) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
        return 1;
    }
    err_msg = ws_init_sockets();
    if (err_msg != nullptr) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
        return 1;
    }

    if (argv[1] == read) {
        return sharkdb::read();
    } else if (argv[1] == dissect) {
        std::cerr << "dissect mode\n";
        return 0;
    } else if (argv[1] == pref_info) {
        return sharkdb::pref_info();
    }

    epan_cleanup();
    wtap_cleanup();

    std::cerr << "Unexpected argument: " << argv[1] << '\n';
    help(*argv);
    return 1;
}
