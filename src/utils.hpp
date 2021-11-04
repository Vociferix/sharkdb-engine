#ifndef SHARKDB_UTILS_HPP
#define SHARKDB_UTILS_HPP

#include <iostream>

namespace sharkdb {

struct JsonStr {
    const char* s;
};

inline JsonStr json_str(const char* s) { return { s }; }

inline std::ostream& operator<<(std::ostream& os, const JsonStr& s) {
    if (s.s == nullptr) {
        os << "null";
        return os;
    }

    os << '"';
    auto c = s.s;
    while (*c != '\0') {
        switch (*c) {
        case '\b':
            os << "\\b";
            break;
        case '\f':
            os << "\\f";
            break;
        case '\n':
            os << "\\n";
            break;
        case '\r':
            os << "\\r";
            break;
        case '\t':
            os << "\\t";
            break;
        case '"':
            os << "\\\"";
            break;
        case '\\':
            os << "\\\\";
            break;
        default:
            os << *c;
            break;
        }
        ++c;
    }
    os << '"';
    return os;
}

} // namespace sharkdb

#endif
