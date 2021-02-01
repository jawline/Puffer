#ifndef _BLOCK_LIST
#define _BLOCK_LIST
#include <set>

class BlockList {
private:
  std::set<std::string> block_set;
public:
  BlockList(FILE* source);
  bool block(char const* hostname);
};

#endif