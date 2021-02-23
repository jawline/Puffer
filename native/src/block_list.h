#ifndef _BLOCK_LIST
#define _BLOCK_LIST

#include <regex>
#include <set>
#include <string>

class BlockList {
private:
    std::vector<std::string> block_includes;
    std::vector<std::string> allow_includes;

public:
    BlockList();
    BlockList(FILE *source_block, FILE *source_allow);

    bool block(std::string const& hostname) const;

    bool is_in_blocklist(std::string const& hostname) const;
    bool is_in_allowlist(std::string const& hostname) const;
};

#endif
