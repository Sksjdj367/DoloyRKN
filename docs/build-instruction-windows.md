**Building DoloyRKN for Windows**

**Prerequisites**:
To build for Windows, ensure you have CMake and MinGW installed on your system.

**Build steps**:
* *navigate to project root*:
```batch
cd DoloyRKN
```

* *Run command for creating build config*:
```batch
cmake -B build-windows -DCMAKE_TOOLCHAIN_FILE=cmake/compile-windows.cmake
```

* *Enter the build directory*:
```batch
cd build-windows
```

* *Build the project*:
```batch
cmake --build .
```

**Post building**:
Output files:
* DoloyRKN.exe (executable)
* WinDivert.dll (dynamic library)
* WinDivert64.sys (system file)

**IMPORTANT!**
All this files are required for the executable work.
Ensure they remain in the same directory as the executable.