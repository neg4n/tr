# tr (trickster)
linux memory hacking library

To start using tr, clone this repository  
and embed `tr.hpp` in source code of  
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

#include "trickster.hpp"

int main() {
  // Create process_t object.
  auto hack_context = std::make_shared<trickster::process_t>("test");

  // Map memory regions.
  hack_context->map_memory_regions();

  // Print modules loaded into process memory.
  for (const auto& module : trickster::utils::get_modules(hack_context->get_memory_regions()))
    std::cout << module << std::endl;

  // Read int value at 0x7ffce9fb1a34 address.
  std::cout << "\nread_memory Test: " << hack_context->read_memory<int>(0x7ffce9fb1a34).value_or(-1) << std::endl;

  // Write int with value of 300 at 0x7ffce9fb1a34 address.
  hack_context->write_memory<int>(0x7ffce9fb1a34, 300);

  // Once again read value at 0x7ffce9fb1a34 address to see, if write above succeed.
  std::cout << "\nread_memory Test: " << hack_context->read_memory<int>(0x7ffce9fb1a34).value_or(-1) << std::endl;
  
  return 0;
}

```
#### Licensing
trickster is available under the MIT License.
