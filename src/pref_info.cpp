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

#include "pref_info.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <epan/epan.h>
#include <epan/prefs-int.h>
#include <epan/prefs.h>
#include <kj/std/iostream.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "pref_info.capnp.h"

namespace sharkdb {

template <typename F>
int foreach_pref_in_module(module_t* mod, F&& callback) {
    for (auto list = mod->prefs; list != nullptr && list->data != nullptr; list = list->next) {
        auto rc = callback(reinterpret_cast<pref_t*>(list->data));
        if (rc != 0) { return rc; }
    }
    return 0;
}

template <typename F>
guint foreach_pref_module_impl(module_t* mod, gpointer data) {
    auto& callback = *reinterpret_cast<F*>(data);
    return static_cast<guint>(callback(mod));
}

template <typename F>
int foreach_pref_module(module_t* mod, F&& callback) {
    using type_t = std::decay_t<F>;
    return static_cast<int>(
        prefs_modules_foreach_submodules(mod, &foreach_pref_module_impl<type_t>, &callback));
}

struct Module {
    module_t* mod;
    std::vector<Module> submods;
};

static guint collect_modules_impl(std::vector<Module>& top_level,
                                  std::unordered_map<module_t*, Module*>& lookup,
                                  module_t* mod) {
    if (lookup.find(mod) != lookup.end() || mod->obsolete) { return 0; }
    if (mod->parent == nullptr) {
        top_level.push_back(Module{ mod });
        lookup.emplace(mod, &top_level.back());
    } else {
        auto it = lookup.find(mod->parent);
        if (it == lookup.end()) {
            auto tmp = lookup.emplace(mod, nullptr).first;
            collect_modules_impl(top_level, lookup, mod->parent);
            lookup.erase(tmp);
            it = lookup.find(mod->parent);
            if (it == lookup.end()) { return 0; }
        }
        it->second->submods.push_back(Module{ mod });
        lookup.emplace(mod, &it->second->submods.back());
    }
    if (prefs_module_has_submodules(mod)) {
        foreach_pref_module(mod, [&top_level, &lookup](auto submod) {
            return collect_modules_impl(top_level, lookup, submod);
        });
    }
    return 0;
}

static std::vector<Module> collect_modules() {
    std::unordered_map<module_t*, Module*> lookup;
    std::vector<Module> top_level;
    foreach_pref_module(nullptr, [&top_level, &lookup](auto mod) {
        return collect_modules_impl(top_level, lookup, mod);
    });
    return top_level;
}

static void visit_uint_pref(pref_t* pref, Pref::Value::Builder out) {
    auto uint_out = out.initTypeUint();
    uint_out.setBase(prefs_get_uint_base(pref));
    uint_out.setInit(prefs_get_uint_value_real(pref, pref_default));
}

static void visit_bool_pref(pref_t* pref, Pref::Value::Builder out) {
    auto bool_out = out.initTypeBool();
    bool_out.setInit(prefs_get_bool_value(pref, pref_default) != 0);
}

static void visit_enum_pref(pref_t* pref, Pref::Value::Builder out) {
    auto enum_out = out.initTypeEnum();
    std::size_t choice_count = 0;
    auto enum_vals = prefs_get_enumvals(pref);
    while (enum_vals[choice_count].name != nullptr) { ++choice_count; }
    auto choices_out = enum_out.initChoices(choice_count);
    for (std::size_t i = 0; i < choice_count; ++i) {
        auto choice = choices_out[i];
        choice.setName(enum_vals[i].name);
        auto choice_desc = choice.initDescription();
        if (enum_vals[i].description != nullptr) { choice_desc.setSome(enum_vals[i].description); }
        choice.setValue(enum_vals[i].value);
    }
    enum_out.setInit(prefs_get_enum_value(pref, pref_default));
}

static void visit_string_pref(pref_t* pref, Pref::Value::Builder out) {
    auto string_out = out.initTypeString();
    auto init_out = string_out.initInit();
    auto def = prefs_get_string_value(pref, pref_default);
    if (def != nullptr) { init_out.setSome(def); }
}

static void visit_range_pref(pref_t* pref, Pref::Value::Builder out) {
    auto range_out = out.initTypeRange();
    range_out.setMax(prefs_get_max_value(pref));
    auto ranges = prefs_get_range_value_real(pref, pref_default);
    auto init_out = range_out.initInit(ranges->nranges);
    for (guint i = 0; i < ranges->nranges; ++i) {
        auto range = init_out[i];
        range.setLow(ranges->ranges[i].low);
        range.setHigh(ranges->ranges[i].high);
    }
}

static void visit_static_text_pref(pref_t* pref, Pref::Value::Builder out) {
    out.setTypeStaticText();
}

static void visit_uat_pref(pref_t* pref, Pref::Value::Builder out) {
    out.setTypeUat();
    // TODO?
}

static void visit_save_filename_pref(pref_t* pref, Pref::Value::Builder out) {
    auto string_out = out.initTypeSaveFilename();
    auto init_out = string_out.initInit();
    auto def = prefs_get_string_value(pref, pref_default);
    if (def != nullptr) { init_out.setSome(def); }
}

static void visit_dirname_pref(pref_t* pref, Pref::Value::Builder out) {
    auto string_out = out.initTypeDirname();
    auto init_out = string_out.initInit();
    auto def = prefs_get_string_value(pref, pref_default);
    if (def != nullptr) { init_out.setSome(def); }
}

static void visit_open_filename_pref(pref_t* pref, Pref::Value::Builder out) {
    auto string_out = out.initTypeOpenFilename();
    auto init_out = string_out.initInit();
    auto def = prefs_get_string_value(pref, pref_default);
    if (def != nullptr) { init_out.setSome(def); }
}

static guint visit_pref(pref_t* pref, Pref::Builder out) {
    auto type = prefs_get_type(pref);
    if (type == PREF_OBSOLETE || type == PREF_COLOR || type == PREF_CUSTOM ||
        type == PREF_DECODE_AS_UINT || type == PREF_DECODE_AS_RANGE) {
        return 0;
    }
    auto name = prefs_get_name(pref);
    auto title = prefs_get_title(pref);
    auto desc = prefs_get_description(pref);
    auto tname = prefs_pref_type_name(pref);
    auto name_out = out.initName();
    auto title_out = out.initTitle();
    auto desc_out = out.initDescription();
    auto type_name_out = out.initTypeName();
    auto value_out = out.initValue();
    if (name != nullptr) { name_out.setSome(name); }
    if (title != nullptr) { title_out.setSome(title); }
    if (desc != nullptr) { desc_out.setSome(desc); }
    if (tname != nullptr) { type_name_out.setSome(tname); }
    switch (type) {
    case PREF_UINT:
        visit_uint_pref(pref, value_out);
        break;
    case PREF_BOOL:
        visit_bool_pref(pref, value_out);
        break;
    case PREF_ENUM:
        visit_enum_pref(pref, value_out);
        break;
    case PREF_STRING:
        visit_string_pref(pref, value_out);
        break;
    case PREF_RANGE:
        visit_range_pref(pref, value_out);
        break;
    case PREF_STATIC_TEXT:
        visit_static_text_pref(pref, value_out);
        break;
    case PREF_UAT:
        visit_uat_pref(pref, value_out);
        break;
    case PREF_SAVE_FILENAME:
        visit_save_filename_pref(pref, value_out);
        break;
    case PREF_DIRNAME:
        visit_dirname_pref(pref, value_out);
        break;
    case PREF_OPEN_FILENAME:
        visit_open_filename_pref(pref, value_out);
        break;
    default:
        break;
    }
    return 0;
}

static void visit_mods(const std::vector<Module>& mods, capnp::List<PrefModule>::Builder out) {
    std::size_t idx = 0;
    for (const auto& mod : mods) {
        std::size_t num_prefs = 0;
        foreach_pref_in_module(mod.mod, [&num_prefs]([[maybe_unused]] auto pref) {
            ++num_prefs;
            return 0;
        });
        auto mod_out = out[idx++];
        auto name_out = mod_out.initName();
        auto title_out = mod_out.initTitle();
        auto desc_out = mod_out.initDescription();
        auto prefs_out = mod_out.initPrefs(num_prefs);
        auto submods_out = mod_out.initSubmodules(mod.submods.size());
        if (mod.mod->name != nullptr) { name_out.setSome(mod.mod->name); }
        if (mod.mod->title != nullptr) { title_out.setSome(mod.mod->title); }
        if (mod.mod->description != nullptr) { desc_out.setSome(mod.mod->description); }
        std::size_t pidx = 0;
        foreach_pref_in_module(mod.mod, [&prefs_out, &pidx](auto pref) {
            return visit_pref(pref, prefs_out[pidx++]);
        });
        visit_mods(mod.submods, submods_out);
    }
}

int pref_info() {
    capnp::MallocMessageBuilder message;
    auto msg = message.initRoot<PrefInfo>();
    auto mod_tree = collect_modules();
    visit_mods(mod_tree, msg.initModules(mod_tree.size()));
    kj::std::StdOutputStream out_stream{ std::cout };
    capnp::writeMessage(out_stream, message);
    return 0;
}

} // namespace sharkdb
