#ifndef TRICKSTER
#define TRICKSTER

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdint.h>
#include <string>
#include <string_view>

#include <cstring>
#include <errno.h>

#include <sys/types.h>
#include <sys/uio.h>

/**
 * trickster - an linux memory hacking library
 * created by zxv77 (github.com/zxv77)
 *
 * version 1.0
 */
namespace trickster {
  /**
   * internal trickster's namespace.
   * DO NOT use outside trickster.hpp
   * if you dont have to.
   */
  namespace internal {
    /**
     * Check if string contains only digits.
     * @param string string to check
     * @return true if only digits, false otherwise
     */
    inline bool onlyDigits(std::string_view string) noexcept { return std::all_of(string.begin(), string.end(), ::isdigit); }
  } // namespace internal

  /**
   * trickster's utilities namespace. contains
   * several utils in purpose to for example:
   * get process id without creating
   * `Process` object.
   */
  namespace utils {
    /**
     * Get process id by name.
     * @param processName name of the process.
     * @return id of the process or std::nullopt if function fails.
     */
    inline std::optional<int> getProcessIdByName(std::string_view processName) noexcept {
      if (processName.empty())
        return std::nullopt;

      for (const auto& process : std::filesystem::directory_iterator("/proc/")) {
        if (!process.is_directory())
          continue;

        if (!internal::onlyDigits(process.path().string().erase(0, 6)))
          continue;

        std::string line;
        std::ifstream processNameFileSteam(process.path() / "comm");
        if (processNameFileSteam.is_open()) {
          std::getline(processNameFileSteam, line);
          if (line == processName)
            return std::stoi(process.path().string().erase(0, 6));
        }
      }
      return std::nullopt;
    }

    /**
     * Get process modules.
     * @param processId id of the process.
     * @return std::vector containing modules as its entries, it is good
     * to check if returned vector is not empty because it means that process
     * with id provided in function call does not exist.
     */
    inline std::vector<std::string> getProcessModules(const int processId) noexcept {
      std::vector<std::string> modules;
      for (const auto& process : std::filesystem::directory_iterator("/proc/")) {
        if (!process.is_directory())
          continue;

        if (!internal::onlyDigits(process.path().string().erase(0, 6)))
          continue;

        if (process.path().string().erase(0, 6) == std::to_string(processId)) {
          std::string line;
          std::ifstream processMapFileStream(process.path() / "maps");
          if (processMapFileStream.is_open()) {
            while (std::getline(processMapFileStream, line))
              if (line.find(".so") != std::string::npos)
                modules.push_back(line.erase(0, 73));

            std::sort(modules.begin(), modules.end());
            modules.erase(std::unique(modules.begin(), modules.end()), modules.end());

            return modules;
          }
        }
      }
      return {};
    }
  } // namespace utils

  class Process {
  private:
    const int m_id;
    const std::string m_name;

  public:
    Process(std::string_view processName) : m_id(utils::getProcessIdByName(processName).value()), m_name(processName){};

    /**
     * Get process id.
     * @return process id
     */
    [[nodiscard]] int getId() const noexcept { return this->m_id; }

    /**
     * Get process name.
     * @return process name.
     */
    [[nodiscard]] std::string getName() const noexcept { return this->m_name; }

    /**
     * Get process modules.
     * @return std::vector containing modules as its entries, it is good
     * to check if returned vector is not empty because it means that process
     * with id provided in function call does not exist.
     */
    [[nodiscard]] std::vector<std::string> getProcessModules() const noexcept { return utils::getProcessModules(this->m_id); }
    
    /**
     * Read process memory.
     * @param address starting address
     * @return read data or nullopt if reading fails
     */
    template <typename Type> std::optional<Type> readMemory(std::uintptr_t address) const noexcept {
      Type buffer{};
      struct iovec local_iovec[ 1 ];
      struct iovec remote_iovec[ 1 ];

      local_iovec[ 0 ].iov_base = &buffer;
      local_iovec[ 0 ].iov_len = sizeof(Type);
      remote_iovec[ 0 ].iov_base = reinterpret_cast<void*>(address);
      remote_iovec[ 0 ].iov_len = sizeof(Type);

      if (process_vm_readv(this->m_id, local_iovec, 1, remote_iovec, 1, 0) == -1) {
#ifdef TRICKSTER_DEBUG
        std::cerr << "[READ FAIL] Error code: " << errno << std::endl << "Message: " << strerror(errno) << std::endl;
#endif
        return std::nullopt;
      }

      return buffer;
    }

    /**
     * Write process memory.
     * @param address starting address
     * @param data data to be written
     * @return boolean determining if bytes written are equal to size of requested bytes.
     * or std::nullopt if writing fails.
     *
     * NOTE: process_vm_readv return value may be less than the total number
     * of requested bytes, if a partial write occurred.
     */
    template <typename Type> std::optional<bool> writeMemory(std::uintptr_t address, Type data) const noexcept {
      struct iovec local_iovec[ 1 ];
      struct iovec remote_iovec[ 1 ];

      local_iovec[ 0 ].iov_base = &data;
      local_iovec[ 0 ].iov_len = sizeof(Type);
      remote_iovec[ 0 ].iov_base = reinterpret_cast<void*>(address);
      remote_iovec[ 0 ].iov_len = sizeof(Type);

      const auto result = process_vm_writev(this->m_id, local_iovec, 1, remote_iovec, 1, 0);

      if (result == -1) {
#ifdef TRICKSTER_DEBUG
        std::cerr << "[WRITE FAIL] Error code: " << errno << std::endl << "Message: " << strerror(errno) << std::endl;
#endif
        return std::nullopt;
      }

      return result == sizeof(Type);
    }
  };

} // namespace trickster

#endif // TRICKSTER