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
 * trickster - a linux memory hacking library
 * created by zxv77 (github.com/zxv77)
 *
 * version 1.1
 */
namespace trickster {

  /**
   * Each row in /proc/$PID/maps describes a region of
   * contiguous virtual memory in a process or thread.
   *
   * Each row has the following fields:
   *
   * address           perms offset  dev   inode   pathname
   * 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
   */
  struct MemoryRegion {
    /**
     * This is the starting and ending address of the region in the process's address space.
     */
    uint64_t start, end;

    /**
     * This describes how pages in the region can be accessed.
     * There are four different permissions: read, write, execute, and shared.
     * If read/write/execute are disabled, a - will appear instead of the r/w/x.
     * If a region is not shared, it is private, so a p will appear instead of an s.
     * If the process attempts to access memory in a way that is not permitted, a segmentation fault is generated.
     *
     * Permissions can be changed using the mprotect system call.
     */
    bool readable, writable, executable, shared;

    /**
     * If the region was mapped from a file (using mmap), this is the offset in the file where the mapping begins.
     * If the memory was not mapped from a file, it's just 0.
     */
    uint64_t offset;

    /**
     * If the region was mapped from a file, this is the major and minor device number (in hex) where the file lives.
     */
    uint64_t device_major, device_minor;

    /**
     * If the region was mapped from a file, this is the file number.
     */
    uint64_t inode;

    /**
     * If the region was mapped from a file, this is the name of the file.
     * This field is blank for anonymous mapped regions.
     * There are also special regions with names like [heap], [stack], or [vdso].
     * [vdso] stands for virtual dynamic shared object.
     * It's used by system calls to switch to kernel mode.
     */
    std::filesystem::path path;

    /**
     * This determines if region is special virtual dynamic shared object.
     */
    bool special;

    /**
     * This is shortened path to contain just the filename of module.
     */
    std::string filename;
  };

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
    inline bool only_digits(std::string_view string) noexcept { return std::all_of(string.begin(), string.end(), ::isdigit); }

    /**
     * Get process id by name.
     * @param process_name name of the process.
     * @return id of the process or std::nullopt if function fails.
     */
    inline std::optional<int> get_pid_by_name(std::string_view process_name) noexcept {
      if (process_name.empty())
        return std::nullopt;

      for (const auto& process : std::filesystem::directory_iterator("/proc/")) {
        if (!process.is_directory())
          continue;

        if (!internal::only_digits(process.path().string().erase(0, 6)))
          continue;

        std::string line;
        std::ifstream process_name_fs(process.path() / "comm");
        if (process_name_fs.is_open()) {
          std::getline(process_name_fs, line);
          if (line == process_name)
            return std::stoi(process.path().string().erase(0, 6));
        }
      }
#ifdef TRICKSTER_DEBUG
      std::cerr << "[trickster] Could not get " << process_name << " id. Consider checking if it exists." << std::endl;
#endif
      return std::nullopt;
    }

    /**
     * Get process memory regions.
     * @param pid process id.
     * @return std::vector containing memory regions as its entries, it is good
     * to check if returned vector is not empty because it means that process
     * with id provided in function call does not exist.
     */

    // String constructor may throw, thus the function is prone to only possibly be noexcept.
    inline std::vector<MemoryRegion> map_memory_regions(const int pid) noexcept(false) {
      std::vector<MemoryRegion> regions;
      for (const auto& process : std::filesystem::directory_iterator("/proc/")) {
        if (!process.is_directory())
          continue;

        if (!internal::only_digits(process.path().string().erase(0, 6)))
          continue;

        if (process.path().string().erase(0, 6) == std::to_string(pid)) {
          std::string line;
          std::ifstream process_memory_map_fs(process.path() / "maps");

          if (process_memory_map_fs.is_open()) {
            // TODO: Find faster and better way to do it.
            while (std::getline(process_memory_map_fs, line)) {
              MemoryRegion region;
              std::size_t cursor_position, previous_cursor_position = 0;

              cursor_position = line.find_first_of('-');

              region.start = std::stoul(line.substr(0, cursor_position), nullptr, 16);

              previous_cursor_position = cursor_position;

              cursor_position = line.find_first_of(' ');

              region.end = std::stoul(line.substr(previous_cursor_position + 1, cursor_position), nullptr, 16);

              region.readable = line.substr(cursor_position + 1, 1) == "r";
              region.writable = line.substr(cursor_position + 2, 1) == "w";
              region.executable = line.substr(cursor_position + 3, 1) == "x";
              region.shared = line.substr(cursor_position + 4, 1) != "p";

              cursor_position += 6;
              previous_cursor_position = cursor_position;

              region.offset = std::stoul(line.substr(previous_cursor_position, 8), nullptr, 16);

              cursor_position = line.find_first_of(' ', previous_cursor_position);

              cursor_position++;

              region.device_major = std::stol(line.substr(cursor_position, 2), nullptr, 16);

              cursor_position += 3; // 4 Because we want to skip the `:` device separator

              region.device_minor = std::stol(line.substr(cursor_position, 2), nullptr, 16);

              cursor_position += 1;
              previous_cursor_position = cursor_position;

              region.inode = std::stol(line.substr(cursor_position + 2, 9), nullptr, 16);

              if (line.find(".so") != std::string::npos || line.find("[") != std::string::npos) {
                if (line.find("[") != std::string::npos)
                  region.special = true;
                else
                  region.special = false;

                region.path = std::filesystem::path{line.erase(0, 73)};
                region.filename = region.path.string().erase(0, region.path.string().find_last_of("/") + 1);
              }

              regions.push_back(region);
            }
            return regions;
          }
        }
      }
#ifdef TRICKSTER_DEBUG
      std::cerr << "[trickster] Could not get modules of process with id: " << pid << ". Consider checking if it exists." << std::endl;
#endif
      return {};
    }
  } // namespace internal

  /**
   * trickster's utilities namespace.
   */
  namespace utils {
    /**
     * Utility function for getting list of shared objects
     * loaded into process memory without duplicate entries.
     * @param regions mapped memory regions where modules are located.
     * @return prettified list of loaded modules.
     */
    [[nodiscard]] std::vector<std::string> get_modules(const std::vector<MemoryRegion>& regions) noexcept {
      std::vector<std::string> modules;

      for (const auto& region : regions)
        if (region.filename.find(".so") != std::string::npos)
          modules.push_back(region.filename);
        else
          continue;

      std::sort(modules.begin(), modules.end());
      modules.erase(std::unique(modules.begin(), modules.end()), modules.end());

      return modules;
    }
  } // namespace utils

  class Process {
  private:
    const int m_id;
    const std::string m_name;
    std::vector<MemoryRegion> m_regions;

  public:
    Process(std::string_view process_name) : m_id(internal::get_pid_by_name(process_name).value_or(-1)), m_name(process_name){};

    /**
     * Get process id.
     * @return process id
     */
    [[nodiscard]] int get_id() const noexcept { return this->m_id; }

    /**
     * Get process name.
     * @return process name.
     */
    [[nodiscard]] const std::string& get_name() const noexcept { return this->m_name; }

     /**
     * Get process memory regions.
     * @return std::vector containing memory regions as its entries, it is good
     * to check if returned vector is not empty because it means that process
     * with id provided in function call does not exist.
     */
    [[nodiscard]] std::vector<MemoryRegion> get_memory_regions() const noexcept { return internal::map_memory_regions(this->m_id); }

    /**
     * Map memory regions.
     */
    void map_memory_regions() noexcept(false) { this->m_regions = internal::map_memory_regions(this->m_id); }

    /**
     * Read process memory.
     * @param address starting address
     * @return read data or nullopt if reading fails
     */
    template <typename Type> std::optional<Type> read_memory(std::uintptr_t address) const noexcept {
      Type buffer{};
      struct iovec local_iovec[ 1 ];
      struct iovec remote_iovec[ 1 ];

      local_iovec[ 0 ].iov_base = std::addressof(buffer);
      local_iovec[ 0 ].iov_len = sizeof(Type);
      remote_iovec[ 0 ].iov_base = reinterpret_cast<void*>(address);
      remote_iovec[ 0 ].iov_len = sizeof(Type);

      if (process_vm_readv(this->m_id, local_iovec, 1, remote_iovec, 1, 0) == -1) {
#ifdef TRICKSTER_DEBUG
        std::cerr << "[trickster] Memory reading failed. Error code: " << errno << std::endl << std::setw(21) << "Message: " << strerror(errno) << std::endl;
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
    template <typename Type> std::optional<bool> write_memory(std::uintptr_t address, const Type& data) const noexcept {
      struct iovec local_iovec[ 1 ];
      struct iovec remote_iovec[ 1 ];

      local_iovec[ 0 ].iov_base = const_cast<Type*>(std::addressof(data));
      local_iovec[ 0 ].iov_len = sizeof(Type);
      remote_iovec[ 0 ].iov_base = reinterpret_cast<void*>(address);
      remote_iovec[ 0 ].iov_len = sizeof(Type);

      const std::size_t result = process_vm_writev(this->m_id, local_iovec, 1, remote_iovec, 1, 0);

      if (result == -1) {
#ifdef TRICKSTER_DEBUG
        std::cerr << "[trickster] Memory writing failed. Error code: " << errno << std::endl << std::setw(21) << "Message: " << strerror(errno) << std::endl;
#endif
        return std::nullopt;
      }

      return result == sizeof(Type);
    }
  };

} // namespace trickster

#endif // TRICKSTER
