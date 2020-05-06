# tr (trickster)
linux memory hacking library

To start using tr, clone this repository  
and embed `./include/tr.hpp` in source code of  
your application or use this repository as  
[git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)

#### Debugging
To verify library code execution and see error messages, compile  
your program with `-DTRICKSTER_DEBUG` compiler flag. (g++)

#### Features

`tr` provides ability to:
- Get process id by name.
- Map process memory regions.
- Enumerate process modules.
- Manipulate process memory.
    - Write memory.
    - Read memory.
- Get callable address.

#### Example implementation:
```cpp
#include <memory>
// Enable logging
#define TRICKSTER_DEBUG
#include <tr.hpp>

constexpr std::uintptr_t value_address = 0x7ffc85c71c04;

int main( ) {
  // Create process object
  auto ctx = std::make_unique<tr_process_t>( "trtest" );
  // Print its id
  printf( "PID: %i\n\n", ctx->get_id( ) );
  // Map memory regions
  ctx->map_memory_regions( );
  // Print modules loaded into process memory (without duplicate segments)
  for ( const auto & module : tr_get_modules_list( ctx->get_memory_regions( ) ) ) {
    printf( "%s\n", module.c_str( ) );
  }
  printf("\n");
  // Read integer value at 0x7ffc85c71c04
  const auto read_opt = ctx->read_memory<int>( value_address );
  if ( read_opt.has_value( ) ) {
    printf( "Value: %i\n\n", read_opt.value( ).data );
  }
  // Increment value at 0x7ffc85c71c04
  const auto write_opt = ctx->write_memory( value_address, read_opt.value( ).data + 10 );
  // Check if write was 100% successful.
  printf( "Write bytes requested: %lu\nWrite bytes result: %lu\nPartial write: %i (1 == true, 0 == false)\n",
          write_opt.value( ).bytes_requested,
          write_opt.value( ).bytes_written,
          write_opt.value( ).partial_write );
}

```
#### Licensing
tr is available under the MIT License.
