#include "sigil/cli.hpp"
#include "sigil/config.hpp"

int main(int argc, char *argv[])
{
    // Eagerly parse config if present to warm up any env overrides; CLI commands
    // will load explicit paths as needed. Failures are ignored here to allow
    // commands like --help to work without a config file.
    (void)sigil::ConfigLoader::load("config.toml");
    return sigil::cli::run(argc, argv);
}
