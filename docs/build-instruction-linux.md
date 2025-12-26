**Building DoloyRKN for Linux**

**Prerequisites**:
To build for Linux, ensure you have CMake and g++ installed on your system.

**Build steps**:
* *navigate to project root*:
```bash
cd DoloyRKN
```

* *Run command for creating build config*:
```bash
cmake -B build-linux -DCMAKE_TOOLCHAIN_FILE=cmake/compile-linux.cmake
```

* *Enter the build directory*:
```bash
cd build-linux
```

* *Build the project*:
```bash
cmake --build .
```

**Post building**:
Output files:
* DoloyRKN (executable)