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

/* Must be included first */
#include <glib.h>
/* ---------------------- */

#include <epan/color_filters.h>
#include <epan/epan.h>
#include <epan/print.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>

#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>

#include "decode_as_info.hpp"
#include "encap_info.hpp"
#include "file_type_info.hpp"
#include "pref_info.hpp"
#include "proto_info.hpp"
#include "read.hpp"
#include "write.hpp"

void help(const char* prog) {
    std::cerr << "Usage: " << prog
              << " [ read | write | dissect | pref-info | proto-info | decode-as-info | "
                 "file-type-info | encap-info ]\n";
}

struct WSGuard {
    explicit WSGuard(const char* prog) {
        init_process_policies();
        relinquish_special_privs_perm();
        auto err_msg = init_progfile_dir(prog);
        if (err_msg != nullptr) {
            std::cerr << err_msg << '\n';
            g_free(err_msg);
            std::exit(1);
        }
#ifdef _WIN32
        ws_init_dll_search_path();
        load_wpcap();
#endif
        timestamp_set_type(TS_RELATIVE);
        timestamp_set_precision(TS_PREC_AUTO);
        timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
        wtap_init(1);
        if (epan_init(nullptr, nullptr, 1) == 0) { std::exit(1); }
        register_all_plugin_tap_listeners();
        epan_load_settings();
        output_fields_new();
        if (color_filters_init(&err_msg, nullptr) == 0) {
            std::cerr << err_msg << '\n';
            g_free(err_msg);
            std::exit(1);
        }
        err_msg = ws_init_sockets();
        if (err_msg != nullptr) {
            std::cerr << err_msg << '\n';
            g_free(err_msg);
            std::exit(1);
        }
    }

    ~WSGuard() {
        epan_cleanup();
        wtap_cleanup();
    }

    WSGuard(const WSGuard&) = delete;
    WSGuard(WSGuard&&) = delete;
    WSGuard& operator=(const WSGuard&) = delete;
    WSGuard& operator=(WSGuard&&) = delete;
};

int main(int argc, char** argv) {
    constexpr std::string_view read = "read";
    constexpr std::string_view write = "write";
    constexpr std::string_view dissect = "dissect";
    constexpr std::string_view pref_info = "pref-info";
    constexpr std::string_view proto_info = "proto-info";
    constexpr std::string_view decode_as_info = "decode-as-info";
    constexpr std::string_view file_type_info = "file-type-info";
    constexpr std::string_view encap_info = "encap-info";

    constexpr std::string_view modes[] = { read,       write,          dissect,        pref_info,
                                           proto_info, decode_as_info, file_type_info, encap_info };

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

    WSGuard guard{ argv[0] };

    int rc = -1;
    if (argv[1] == read) {
        return sharkdb::read();
    } else if (argv[1] == write) {
        return sharkdb::write();
    } else if (argv[1] == dissect) {
        std::cerr << "dissect mode\n";
        return 0;
    } else if (argv[1] == pref_info) {
        return sharkdb::pref_info();
    } else if (argv[1] == proto_info) {
        return sharkdb::proto_info();
    } else if (argv[1] == decode_as_info) {
        return sharkdb::decode_as_info();
    } else if (argv[1] == file_type_info) {
        return sharkdb::file_type_info();
    } else if (argv[1] == encap_info) {
        return sharkdb::encap_info();
    }

    std::cerr << "Unexpected argument: " << argv[1] << '\n';
    help(*argv);
    return 1;
}
