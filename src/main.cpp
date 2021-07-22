#include <iostream>
#include <string_view>

void help(const char* prog) { std::cerr << "Usage: " << prog << " [ read | dissect ]\n"; }

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
        std::cerr << "read mode\n";
        return 0;
    } else if (argv[1] == dissect) {
        std::cerr << "dissect mode\n";
        return 0;
    }

    std::cerr << "Unexpected argument: " << argv[1] << '\n';
    help(*argv);
    return 1;
}
