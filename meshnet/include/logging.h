#ifndef GOSSIP_LOGGING_H
#define GOSSIP_LOGGING_H

#include <string>

namespace gossip {
namespace logging {

void debug(const std::string& message);
void info(const std::string& message);
void warn(const std::string& message);
void error(const std::string& message);

}  // namespace logging
}  // namespace gossip

#endif  // GOSSIP_LOGGING_H
