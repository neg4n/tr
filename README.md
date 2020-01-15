# trickster
linux memory hacking library

To start using trickster, clone this repository  
and embed `trickster.hpp` in source code of  
your application or use this repository as  
[git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)

#### Debugging
To verify library code execution and see error messages, compile  
your program with `-DTRICKSTER_DEBUG` compiler flag. (g++)

#### Features

`trickster` provides ability to:
- Enumerate process modules.
- Get process id by name.
- Manipulate process memory.
    - Write memory.
    - Read memory.

#### Example implementation:
```cpp
#include "trickster.hpp"
#include <memory>

int main() {
  // Create Process object.
  auto testProcess = std::make_shared<trickster::Process>("test");
  // Print process modules.
  for (const auto& module : testProcess->getProcessModules())
    std::cout << module << std::endl;
  // Read int value at 0x7ffce9fb1a34 address.
  std::cout << "\nreadMemory Test: " << testProcess->readMemory<int>(0x7ffce9fb1a34).value() << std::endl;
  // Write int with value of 300 at 0x7ffce9fb1a34 address.
  testProcess->writeMemory<int>(0x7ffce9fb1a34, 300);
  // Once again read value at 0x7ffce9fb1a34 address to see, if write above succeed.
  std::cout << "\nreadMemory Test: " << testProcess->readMemory<int>(0x7ffce9fb1a34).value() << std::endl;
  return 0;
}

```
#### Licensing
trickster is available under the MIT License.
