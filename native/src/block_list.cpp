#include "block_list.h"
#include "log.h"
#include <algorithm>
#include <cstring>
#include <sstream>

static inline void ltrim(std::string &s) {
    s.erase(s.begin(),
            std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

static inline std::vector<std::string> read_list_from_file(FILE *source) {
  std::vector<std::string> result_list;
  char buffer[4096];

  while (fgets(buffer, sizeof(buffer), source)) {
    if (strlen(buffer) > 0 && buffer[0] != '#') {
      std::string line = buffer;
      trim(line);
      debug("%s", line.c_str());
      result_list.push_back(line);
    }
  }

  fclose(source);

  return result_list;
}

BlockList::BlockList() {}

BlockList::BlockList(FILE *source_block, FILE *source_allow) {
  this->block_includes = read_list_from_file(source_block);
  this->allow_includes = read_list_from_file(source_allow);
}

bool BlockList::is_in_blocklist(std::string const& hostname) const {
  for (size_t i = 0; i < this->block_includes.size(); i++) {
    if (hostname.find(this->block_includes[i]) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool BlockList::is_in_allowlist(std::string const& hostname) const {
  for (size_t i = 0; i < this->allow_includes.size(); i++) {
    if (hostname.find(this->allow_includes[i]) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool BlockList::block(std::string const& hostname) const {
    // TODO: This should be a unified regular expression but it's too complex out
    // of the box for C++'s regex style. We can improve this later
    return is_in_blocklist(hostname) && !is_in_allowlist(hostname);
}
