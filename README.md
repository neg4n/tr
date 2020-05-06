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

#### Example implementation:
```cpp
#include <memory>
// Enable logging
#define TRICKSTER_DEBUG
#include <tr.hpp>

constexpr std::uintptr_t value_address = 0x7ffce9fb1a34;

int main( ) {
  // Create process object
  auto ctx = std::make_unique<tr_process_t>( "trtest" );
  // Print its id
  printf( "%i\n", ctx->get_id( ) );
  // Map memory regions
  ctx->map_memory_regions( );
  // Print modules loaded into process memory (without duplicate segments)
  for ( const auto & module : tr_get_modules_list( ctx->get_memory_regions( ) ) ) {
    printf( "%s", module.c_str( ) );
  }
  // Read integer value at 0x7ffce9fb1a34
  const auto read_opt = ctx->read_memory<int>( value_address );
  if ( read_opt.has_value( ) ) {
    printf( "%i", read_opt.value( ) );
  }
  // Write integer value (20) at 0x7ffce9fb1a34
  ctx->write_memory( value_address, 20 );
}
```
#### Licensing
tr is available under the MIT License.
