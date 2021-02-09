#include "block_list.h"
#include <sstream>
#include <algorithm>
#include <cstring>
#include "log.h"

static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

BlockList::BlockList() {}

BlockList::BlockList(FILE* source) {
  char buffer[4096];

  bool first = true;
  int count;

  while(fgets(buffer, sizeof(buffer), source)) {
    if (strlen(buffer) > 0 && buffer[0] != '#') {
      std::string line = buffer;
      trim(line);
      debug("%s", line.c_str());
      this->block_includes.push_back(line);
    }
  }

  fclose(source);
}

bool BlockList::block(char const* hostname) const {
  //TODO: This should be a unified regular expression but it's too complex out of the box for C++'s regex style. We can improve this later
  auto host = std::string(hostname);
  for (size_t i = 0; i < this->block_includes.size(); i++) {
    if (host.find(this->block_includes[i]) != std::string::npos) {
      return true;
    }
  }
  return false;
}
