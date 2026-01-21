#include "logging.h"

#include <chrono>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace gossip {
namespace logging {

namespace {

constexpr size_t kMaxLogBytes = 2048;

std::mutex log_mutex;

std::ofstream& log_stream() {
    static std::ofstream stream("gossip.logs", std::ios::app);
    return stream;
}

std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

std::string sanitize(const std::string& input) {
    std::string trimmed = input.substr(0, std::min(input.size(), kMaxLogBytes));
    std::string result;
    result.reserve(trimmed.size());
    for (unsigned char ch : trimmed) {
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            result.push_back(' ');
        } else if (std::isprint(ch)) {
            result.push_back(static_cast<char>(ch));
        } else {
            result.push_back('?');
        }
    }
    while (!result.empty() && std::isspace(static_cast<unsigned char>(result.back()))) {
        result.pop_back();
    }
    return result;
}

void log_line(const char* level, const std::string& message) {
    auto& stream = log_stream();
    if (!stream.is_open()) {
        return;
    }
    std::string sanitized = sanitize(message);
    if (sanitized.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(log_mutex);
    stream << timestamp() << " [" << level << "] " << sanitized << '\n';
    stream.flush();
}

}  // namespace

void debug(const std::string& message) {
    log_line("DEBUG", message);
}

void info(const std::string& message) {
    log_line("INFO", message);
}

void warn(const std::string& message) {
    log_line("WARN", message);
}

void error(const std::string& message) {
    log_line("ERROR", message);
}

}  // namespace logging
}  // namespace gossip
