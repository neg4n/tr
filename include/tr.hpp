#ifndef TRICKSTER
#define TRICKSTER

#include <algorithm>
#include <assert.h>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include <cerrno>
#include <cstring>

#include <any>
#include <sys/types.h>
#include <sys/uio.h>

#define tr_assert( condition, message ) assert( condition && message )
/**
 * This macro provides ability to encrypt all tr's
 * strings during compilation using heavily vectorized
 * c++17 compile time string encryption library
 * (https://github.com/JustasMasiulis/xorstr)
 */
#ifdef JM_XORSTR_HPP
#define tr_string( string ) xorstr_( string )
#else
#define tr_string
#endif

/**
 * tr - a linux memory hacking library
 * created by neg4n (github.com/neg4n)
 *
 * version 1.3
 */
namespace tr {

  /**
   * Each row in /proc/$PID/maps describes a region of
   * contiguous virtual memory in a process or thread.
   *
   * Each row has the following fields:
   *
   * address           perms offset  dev   inode   pathname
   * 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
   */
  struct memory_region_t {
    /**
     * This is the starting and ending address of the region in the process's address space.
     */
    std::uint64_t start, end;

    /**
     * This describes how pages in the region can be accessed.
     * There are four different permissions: read, write, execute, and shared.
     * If read/write/execute are disabled, a - will appear instead of the r/w/x.
     * If a region is not shared, it is private, so a p will appear instead of an s.
     * If the process attempts to access memory in a way that is not permitted, a segmentation fault is
     * generated.
     *
     * Permissions can be changed using the mprotect system call.
     */
    bool readable, writable, executable, shared;

    /**
     * If the region was mapped from a file (using mmap), this is the offset in the file where the mapping
     * begins. If the memory was not mapped from a file, it's just 0.
     */
    std::uint64_t offset;

    /**
     * If the region was mapped from a file, this is the major and minor device number (in hex) where the file
     * lives.
     */
    std::uint64_t device_major, device_minor;

    /**
     * If the region was mapped from a file, this is the file number.
     */
    std::uint64_t inode;

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
   * internal tr's namespace.
   * DO NOT use outside tr.hpp
   * if you dont have to.
   */
  namespace _internal {

    enum class log_levels_t : std::uint8_t { info = 0, error };
    template <log_levels_t L, typename... Args> void log( std::string_view format, Args... args ) {
      std::string output { tr_string( "[tr] " ) };
      output.append( format );
      if constexpr ( L == log_levels_t::error ) {
        fprintf( stderr, output.append( tr_string( "\n" ) ).c_str( ), args... );
      } else if constexpr ( L == log_levels_t::info ) {
        fprintf( stdout, output.append( tr_string( "\n" ) ).c_str( ), args... );
      }
    }

    /**
     * Check if string contains only digits.
     * @param string string to check
     * @return true if only digits, false otherwise
     */
    [[nodiscard]] inline bool only_digits( std::string_view string ) {
      return std::all_of( string.begin( ), string.end( ), ::isdigit );
    }

    /**
     * Get process id by name.
     * @param process_name name of the process.
     * @return id of the process or std::nullopt if function fails.
     */
    [[nodiscard]] inline std::optional<int> get_pid_by_name( std::string_view process_name ) {
      tr_assert( !process_name.empty( ), "Process name is 0 length." );

      for ( const auto & process : std::filesystem::directory_iterator( tr_string( "/proc/" ) ) ) {
        if ( !process.is_directory( ) )
          continue;

        if ( !_internal::only_digits( process.path( ).string( ).erase( 0, 6 ) ) )
          continue;

        std::string   line;
        std::ifstream process_name_fs( process.path( ) / tr_string( "comm" ) );
        if ( process_name_fs.is_open( ) ) {
          std::getline( process_name_fs, line );
          if ( line == process_name )
            return std::stoi( process.path( ).string( ).erase( 0, 6 ) );
        }
      }

#ifdef TRICKSTER_DEBUG
      _internal::log<_internal::log_levels_t::error>(
          tr_string( "Could not get '%s' process id. Consider checking if it exists." ),
          process_name.data( ) );
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
    [[nodiscard]] inline std::vector<memory_region_t> map_memory_regions( const int pid ) {
      std::vector<memory_region_t> regions;
      for ( const auto & process : std::filesystem::directory_iterator( tr_string( "/proc/" ) ) ) {
        if ( !process.is_directory( ) )
          continue;

        if ( !_internal::only_digits( process.path( ).string( ).erase( 0, 6 ) ) )
          continue;

        if ( process.path( ).string( ).erase( 0, 6 ) == std::to_string( pid ) ) {
          std::string   line;
          std::ifstream process_memory_map_fs( process.path( ) / tr_string( "maps" ) );

          if ( process_memory_map_fs.is_open( ) ) {
            // TODO: Find faster and better way to do it.
            while ( std::getline( process_memory_map_fs, line ) ) {
              memory_region_t region;
              std::size_t     cursor_position, previous_cursor_position = 0;

              cursor_position = line.find_first_of( '-' );

              region.start = std::stoul( line.substr( 0, cursor_position ), nullptr, 16 );

              previous_cursor_position = cursor_position;

              cursor_position = line.find_first_of( ' ' );

              region.end =
                  std::stoul( line.substr( previous_cursor_position + 1, cursor_position ), nullptr, 16 );

              region.readable   = line.substr( cursor_position + 1, 1 ) == tr_string( "r" );
              region.writable   = line.substr( cursor_position + 2, 1 ) == tr_string( "w" );
              region.executable = line.substr( cursor_position + 3, 1 ) == tr_string( "x" );
              region.shared     = line.substr( cursor_position + 4, 1 ) != tr_string( "p" );

              cursor_position += 6;
              previous_cursor_position = cursor_position;

              region.offset = std::stoul( line.substr( previous_cursor_position, 8 ), nullptr, 16 );

              cursor_position = line.find_first_of( ' ', previous_cursor_position );

              cursor_position++;

              region.device_major = std::stol( line.substr( cursor_position, 2 ), nullptr, 16 );

              cursor_position += 3; // 4 Because we want to skip the `:` device separator

              region.device_minor = std::stol( line.substr( cursor_position, 2 ), nullptr, 16 );

              cursor_position += 1;
              previous_cursor_position = cursor_position;

              region.inode = std::stol( line.substr( cursor_position + 2, 9 ), nullptr, 16 );

              if ( line.find( tr_string( ".so" ) ) != std::string::npos ||
                   line.find( '[' ) != std::string::npos ) {
                region.special = line.find( '[' ) != std::string::npos;

                region.path     = std::filesystem::path { line.erase( 0, 73 ) };
                region.filename = region.path.string( ).erase(
                    0, region.path.string( ).find_last_of( tr_string( "/" ) ) + 1 );
              }

              regions.push_back( std::move( region ) );
            }
            return regions;
          }
        }
      }
#ifdef TRICKSTER_DEBUG
      _internal::log<_internal::log_levels_t::error>(
          tr_string( "Could not get memory regions of process with %i id. Consider checking if it exists." ),
          pid );
#endif
      return {};
    }
  } // namespace _internal

  /**
   * tr's utilities namespace.
   */
  namespace utils {

    // TODO: Error checking
    /**
     * Utility function for getting list of shared objects
     * loaded into process memory without duplicate entries.
     * @param regions mapped memory regions where modules are located.
     * @return prettified list of loaded modules.
     */
    [[nodiscard]] std::vector<std::string> get_modules( const std::vector<memory_region_t> & regions ) {
      std::vector<std::string> modules;

      modules.reserve( regions.size( ) );

      for ( auto & region : regions )
        if ( region.filename.find( tr_string( ".so" ) ) != std::string::npos )
          modules.push_back( std::move( region.filename ) );
        else
          continue;

      std::sort( modules.begin( ), modules.end( ) );
      modules.erase( std::unique( modules.begin( ), modules.end( ) ), modules.end( ) );

      modules.shrink_to_fit( );

      return modules;
    }
  } // namespace utils

  class process_t {
  private:
    const int                    m_id;
    const std::string            m_name;
    std::vector<memory_region_t> m_regions;

  public:
    constexpr static int invalid = -1;

    explicit process_t( std::string_view process_name )
        : m_id( _internal::get_pid_by_name( process_name ).value_or( invalid ) ), m_name( process_name ) {};

    /**
     * Check if process is valid.
     * @return state of statement above.
     */
    [[nodiscard]] bool is_valid( ) const { return m_id != invalid; }

    /**
     * Get process id.
     * @return process id
     */
    [[nodiscard]] int get_id( ) const { return m_id; }

    /**
     * Get process name.
     * @return process name.
     */
    [[nodiscard]] std::string_view get_name( ) const noexcept {
      tr_assert( is_valid( ), tr_string( "Process is invalid." ) );
      return m_name;
    }

    /**
     * Get process memory regions.
     * @return std::vector containing memory regions as its entries, it is good
     * to check if returned vector is not empty because it means that process
     * with id provided in function call does not exist.
     */
    [[nodiscard]] const std::vector<memory_region_t> & get_memory_regions( ) const noexcept {
      tr_assert( is_valid( ), tr_string( "Process is invalid." ) );
      return m_regions;
    }

    /**
     * Map memory regions.
     */
    void map_memory_regions( ) noexcept {
      tr_assert( is_valid( ), tr_string( "Process is invalid." ) );
      m_regions = _internal::map_memory_regions( m_id );
    }

    /**
     * Read process memory.
     * @param address starting address
     * @param size read size (default: sizeof(T))
     * @return read data or nullopt if reading fails
     *
     * NOTE: process_vm_readv return value may be less than the total number
     * of requested bytes, if a partial write occurred. Define TRICKSTER_DEBUG
     * to see if this situation (the one described above) happens.
     *
     * TODO: return bool (bytes requested == bytes written)
     */
    template <typename T>
    std::optional<T> read_memory( std::uintptr_t address, std::size_t size = sizeof( T ) ) const {
      tr_assert( is_valid( ), tr_string( "Process is invalid." ) );

      T     buffer {};
      iovec local[ 1 ], remote[ 1 ];

      local[ 0 ].iov_base  = std::addressof( buffer );
      local[ 0 ].iov_len   = size;
      remote[ 0 ].iov_base = (void *)( address );
      remote[ 0 ].iov_len  = size;

      const std::size_t result = process_vm_readv( m_id, local, 1, remote, 1, 0 );
#ifdef TRICKSTER_DEBUG
      if ( result != size ) {
        _internal::log<_internal::log_levels_t::info>(
            tr_string( "Partial read occured." ), errno, strerror( errno ) );
      }
#endif
      if ( result == -1 ) {
#ifdef TRICKSTER_DEBUG
        _internal::log<_internal::log_levels_t::error>(
            tr_string( "Memory reading failed with error code: %i, Message: %s" ), errno, strerror( errno ) );
#endif
        return std::nullopt;
      }

      return buffer;
    }

    /**
     * Write process memory.
     * @param address starting address
     * @param data data to be written
     * @param size read size (default: sizeof(T))
     * @return boolean determining if bytes written are equal to size of requested bytes.
     * or std::nullopt if writing fails.
     *
     * NOTE: process_vm_writev return value may be less than the total number
     * of requested bytes, if a partial write occurred. Define TRICKSTER_DEBUG
     * to see if this situation (the one described above) happens.
     */
    template <typename T>
    std::optional<bool>
    write_memory( std::uintptr_t address, const T & data, std::size_t size = sizeof( T ) ) const {
      tr_assert( is_valid( ), tr_string( "Process is invalid." ) );

      iovec local[ 1 ], remote[ 1 ];

      local[ 0 ].iov_base  = const_cast<T *>( std::addressof( data ) );
      local[ 0 ].iov_len   = size;
      remote[ 0 ].iov_base = (void *)( address );
      remote[ 0 ].iov_len  = size;

      const std::size_t result = process_vm_writev( m_id, local, 1, remote, 1, 0 );
#ifdef TRICKSTER_DEBUG
      if ( result != size ) {
        _internal::log<_internal::log_levels_t::info>(
            tr_string( "Partial write occured." ), errno, strerror( errno ) );
      }
#endif
      if ( result == -1 ) {
#ifdef TRICKSTER_DEBUG
        _internal::log<_internal::log_levels_t::error>(
            tr_string( "Memory writing failed with error code: %i, Message: %s" ), errno, strerror( errno ) );
#endif
        return std::nullopt;
      }

      return result == size;
    }

    [[nodiscard]] std::optional<std::uintptr_t> get_call_address( std::uintptr_t address ) const noexcept {
      tr_assert( is_valid( ), tr_string( "Process is invalid." ) );

      auto memory_opt = read_memory<std::uintptr_t>( address + 0x1, sizeof( std::uint32_t ) );
      if ( memory_opt.has_value( ) ) {
        return ( memory_opt.value( ) + ( address + 0x5 ) );
      } else {
#ifdef TRICKSTER_DEBUG
        _internal::log<_internal::log_levels_t::error>(
            tr_string( "Failed to get call address of %d. If this message is exactly after read memory "
                       "error, refer to it." ),
            address );
#endif
        return std::nullopt;
      }
    }
  };
} // namespace tr

#ifndef TRICKSTER_NO_GLOBALS

using tr_process_t = tr::process_t;
#define tr_get_modules_list trickster::utils::get_modules

#endif

#endif // TRICKSTER
