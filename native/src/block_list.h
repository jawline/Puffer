#ifndef _BLOCK_LIST
#define _BLOCK_LIST
#include <regex>
#include <set>
#include <string>

class BlockList {
private:
  std::vector<std::string> block_includes;

public:
  BlockList();
  BlockList(FILE *source);
  bool block(char const *hostname) const;
};

#endif
