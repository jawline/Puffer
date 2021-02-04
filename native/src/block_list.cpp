#include "block_list.h"
#include <sstream>
#include <algorithm>
#include <cstring>
#include "log.h"

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

BlockList::BlockList() {}

BlockList::BlockList(FILE* source) {
  std::stringstream ss;
  char buffer[4096];

  while(fgets(buffer, sizeof(buffer), source)) {
    if (strlen(buffer) > 0 && buffer[0] != '#') {
      std::string line = buffer;
      auto delim = line.find(" ");
      if (delim != line.npos) {
      std::string token = line.substr(delim);
      trim(token);
      debug("block: \"%s\"\n", token.c_str());
      this->block_set.insert(token);
      }
    }
  }

  fclose(source);
}

bool BlockList::block(char const* hostname) {
  // TODO: Pass this as a string and ditch the copy construct
  return this->block_set.find(hostname) != this->block_set.end();
}
