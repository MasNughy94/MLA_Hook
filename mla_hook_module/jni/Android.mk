LOCAL_PATH := $(call my-dir)
DOBBY_PATH := $(LOCAL_PATH)/../../Dobby

# Build Dobby as a static library from source
include $(CLEAR_VARS)
LOCAL_MODULE := dobby

LOCAL_SRC_FILES := \
    $(DOBBY_PATH)/source/dobby.cpp \
    $(DOBBY_PATH)/source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c \
    $(DOBBY_PATH)/source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc \
    $(DOBBY_PATH)/source/Backend/UserMode/UnifiedInterface/platform-posix.cc \
    $(DOBBY_PATH)/source/Backend/UserMode/UnifiedInterface/semaphore.cc \
    $(DOBBY_PATH)/source/Backend/UserMode/MultiThreadSupport/ThreadSupport.cpp \
    $(DOBBY_PATH)/source/Backend/UserMode/Thread/platform-thread-posix.cc \
    $(DOBBY_PATH)/source/Backend/UserMode/Thread/PlatformThread.cc \
    $(DOBBY_PATH)/source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc \
    $(DOBBY_PATH)/source/Backend/KernelMode/ExecMemory/clear-cache-tool-all.c \
    $(DOBBY_PATH)/source/core/assembler/assembler-arm.cc \
    $(DOBBY_PATH)/source/core/codegen/codegen-arm.cc \
    $(DOBBY_PATH)/source/core/emulator/dummy.cc \
    $(DOBBY_PATH)/source/InstructionRelocation/arm64/InstructionRelocationARM64.cc \
    $(DOBBY_PATH)/source/InterceptRouting/InstrumentRouting/instrument_routing.cpp \
    $(DOBBY_PATH)/source/InterceptRouting/NearBranchTrampoline/near_trampoline.cpp \
    $(DOBBY_PATH)/source/TrampolineBridge/Trampoline/trampoline_arm64.cc \
    $(DOBBY_PATH)/source/TrampolineBridge/ClosureTrampolineBridge/arm64/ClosureTrampolineARM64.cc \
    $(DOBBY_PATH)/source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.cc \
    $(DOBBY_PATH)/source/TrampolineBridge/ClosureTrampolineBridge/arm64/helper_arm64.cc \
    $(DOBBY_PATH)/source/TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.cpp \
    $(DOBBY_PATH)/source/TrampolineBridge/ClosureTrampolineBridge/common_bridge_code.cpp

LOCAL_C_INCLUDES := \
    $(DOBBY_PATH) \
    $(DOBBY_PATH)/include \
    $(DOBBY_PATH)/source \
    $(DOBBY_PATH)/source/core \
    $(DOBBY_PATH)/source/InterceptRouting \
    $(DOBBY_PATH)/source/InstructionRelocation \
    $(DOBBY_PATH)/source/TrampolineBridge \
    $(DOBBY_PATH)/source/TrampolineBridge/ClosureTrampolineBridge \
    $(DOBBY_PATH)/source/Backend/UserMode/ExecMemory \
    $(DOBBY_PATH)/source/Backend/UserMode/PlatformUtil/Linux \
    $(DOBBY_PATH)/source/Backend/UserMode/MultiThreadSupport \
    $(DOBBY_PATH)/external \
    $(DOBBY_PATH)/external/logging \
    $(DOBBY_PATH)/external/osbase

LOCAL_CPPFLAGS := -std=c++17 -Os -fvisibility=hidden -Wall
LOCAL_CFLAGS   := -std=c17 -Os -fvisibility=hidden -Wall

include $(BUILD_STATIC_LIBRARY)

# Build mla_hook shared library
include $(CLEAR_VARS)
LOCAL_MODULE       := mla_hook
LOCAL_SRC_FILES    := mla_hook.cpp
LOCAL_C_INCLUDES   := $(DOBBY_PATH)/include \
                       $(LOCAL_PATH)
LOCAL_WHOLE_STATIC_LIBRARIES := dobby
LOCAL_LDLIBS       := -llog -ldl
LOCAL_CPPFLAGS     := -std=c++17 -Os -fvisibility=hidden -Wall -Wextra
include $(BUILD_SHARED_LIBRARY)