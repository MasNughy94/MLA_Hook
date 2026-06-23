# MLA Hook - Panduan Portable Build (Tanpa Administrator)

## Struktur Folder

```
D:\MLA_Hook/
├── .github/workflows/build.yml   # GitHub Actions CI
├── module/
│   ├── CMakeLists.txt             # Build config
│   ├── src/main.cpp               # Kode hooking (DobbyHook)
│   ├── include/hooking.h          # Header helpers
│   ├── Dobby/include/dobby.h      # Header Dobby API
│   └── prebuilt/arm64-v8a/
│       ├── libDobby.a             # Prebuilt static library
│       └── libDobby.so            # Prebuilt shared library
├── build_android.ps1              # Build script Windows
└── GUIDE.md                       # Panduan ini
```

---

## 1. Download Tools (Portable - ZIP)

Semua tool di-download sebagai ZIP, tinggal extract, tanpa installer.

### A. CMake Portable
- URL: https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-windows-x86_64.zip
- Extract ke: `D:\cmake-portable`

### B. Android NDK (Gunakan r27c, kompatibel dengan Dobby)
- URL: https://dl.google.com/android/repository/android-ndk-r27c-windows.zip
- Extract ke: `D:\android-ndk-r27c`

### C. Java (untuk apktool/jadx)
- URL: https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19+10/OpenJDK17U-jdk_x64_windows_hotspot_17.0.19_10.zip
- Extract ke: `D:\jdk-17.0.19+10`

---

## 2. Set Environment Variable (Sementara, via CMD)

Jangan ubah System PATH. Cukup set per session:

### CMD (command prompt)
```cmd
set PATH=D:\cmake-portable\bin;D:\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin;D:\android-ndk-r27c\prebuilt\windows-x86_64\bin;%PATH%
```

### PowerShell
```powershell
$env:PATH = "D:\cmake-portable\bin;D:\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin;D:\android-ndk-r27c\prebuilt\windows-x86_64\bin;$env:PATH"
```

---

## 3. Build Langsung (One-Click)

### PowerShell (recommended)
```powershell
cd D:\MLA_Hook
.\build_android.ps1
```

### Manual Step-by-step
```powershell
# 1. Set PATH
$env:PATH = "D:\cmake-portable\bin;D:\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin;D:\android-ndk-r27c\prebuilt\windows-x86_64\bin;$env:PATH"

# 2. Configure
cmake -G "Unix Makefiles" ^
    -DCMAKE_TOOLCHAIN_FILE="D:\android-ndk-r27c\build\cmake\android.toolchain.cmake" ^
    -DANDROID_ABI=arm64-v8a ^
    -DANDROID_PLATFORM=android-24 ^
    -DANDROID_STL=c++_shared ^
    -DCMAKE_BUILD_TYPE=Release ^
    -B D:\MLA_Hook\build\android ^
    -S D:\MLA_Hook\module

# 3. Compile
cmake --build D:\MLA_Hook\build\android --config Release --parallel
```

---

## 4. Output File

Setelah build selesai, file `.so` ada di:

```
D:\MLA_Hook\build\android\libmla_hook.so
```

Cara verifikasi:
```bash
file build/android/libmla_hook.so
# Output: libmla_hook.so: ELF 64-bit LSB shared object, ARM aarch64, ...
```

---

## 5. Cara Kerja CMakeLists.txt

```cmake
add_library(mla_hook SHARED src/main.cpp)
target_include_directories(mla_hook PRIVATE include Dobby/include)
add_library(Dobby STATIC IMPORTED)
target_link_libraries(mla_hook -Wl,--whole-archive Dobby -Wl,--no-whole-archive log dl)
```

Keterangan:
- `--whole-archive` memastikan semua simbol Dobby masuk ke `.so` kita
- `log` dan `dl` adalah library Android standard untuk logging dan dynamic loading

---

## 6. Cara Pakai DobbyHook di main.cpp

```cpp
#include "dobby.h"

// 1. Buat fungsi replacement
static void my_hook() {
    LOGI("Hooked!");
}

// 2. Pasang hook
dobby_dummy_func_t orig = nullptr;
int ret = DobbyHook(target_address, (dobby_dummy_func_t)my_hook, &orig);

// 3. Call original jika perlu
if (orig) ((void (*)())orig)();
```

---

## 7. Decompile MLA.APK

### Dengan apktool (smali)
```powershell
$env:JAVA_HOME = "D:\jdk-17.0.19+10"
$env:PATH = "D:\jdk-17.0.19+10\bin;$env:PATH"
java -jar D:\apktool_3.0.2.jar d -f -o D:\MLA\apktool D:\MLA\MLA.apk
```

### Dengan jadx (Java source)
```powershell
java -jar D:\jadx\lib\jadx-1.5.1-all.jar -d D:\MLA\jadx D:\MLA\MLA.apk
```

---

## 8. GitHub Actions CI

File `.github/workflows/build.yml` sudah disediakan.

Cara pakai:
1. Push repo ke GitHub
2. GitHub Actions akan build otomatis
3. Download artifact `mla_hook-arm64-v8a` berisi `libmla_hook.so`

Workflow menggunakan:
- `nttld/setup-ndk@v1` dengan NDK r27c
- CMake 3.31
- Prebuilt Dobby dari shadow3aaa/dobby-api

---

## 9. Troubleshooting

### "CMAKE_MAKE_PROGRAM is not set"
**Sebab:** Ninja tidak ditemukan.
**Solusi:** Gunakan generator "Unix Makefiles":
```powershell
cmake -G "Unix Makefiles" ...
```

### "Could NOT find NDK"
**Sebab:** PATH tidak set dengan benar.
**Solusi:** Set PATH dulu:
```powershell
$env:PATH = "D:\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin;...;$env:PATH"
```

### "unable to find library -lDobby"
**Sebab:** File libDobby.a tidak ditemukan.
**Solusi:** Jalankan download_prebuilt.ps1 atau download manual dari:
- https://raw.githubusercontent.com/shadow3aaa/dobby-api/master/prebuilt/android/arm64-v8a/libdobby.a
- https://raw.githubusercontent.com/shadow3aaa/dobby-api/master/prebuilt/android/arm64-v8a/libdobby.so

### "Permission denied" saat run cmake
**Sebab:** File cmake.exe tidak punya execute permission.
**Solusi:** Extract ulang cmake-portable.zip atau verify:
```powershell
Get-ChildItem D:\cmake-portable\bin\cmake.exe
```

### "java is not recognized"
**Sebab:** Java belum ada di PATH.
**Solusi:** Set JAVA_HOME dan PATH sementara:
```powershell
$env:JAVA_HOME = "D:\jdk-17.0.19+10"
$env:PATH = "D:\jdk-17.0.19+10\bin;$env:PATH"
```

---

## 10. Catatan Penting

1. **Tidak perlu admin** - semua tool portable
2. **NDK r27c** direkomendasikan karena Dobby belum kompatibel dengan NDK r28 (Clang 19)
3. **GitHub Actions** otomatis build di Ubuntu, tidak perlu Windows
4. **AES Key Moonton**: `moontonAgame1234` (untuk decrypt asset MLA)
