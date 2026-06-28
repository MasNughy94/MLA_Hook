LOCAL_PATH := $(call my-dir)

# Prebuilt Dobby static library (built from submodule, copied here by CI)
include $(CLEAR_VARS)
LOCAL_MODULE     := dobby
LOCAL_SRC_FILES  := ../prebuilt/$(TARGET_ARCH_ABI)/libdobby.a
include $(PREBUILT_STATIC_LIBRARY)

# Our hook module
include $(CLEAR_VARS)
LOCAL_MODULE       := mla_hook
LOCAL_SRC_FILES    := mla_hook.c
# Dobby is a git submodule at repo root: $(LOCAL_PATH)/../../Dobby
LOCAL_C_INCLUDES   := $(LOCAL_PATH)/../../Dobby/include
LOCAL_STATIC_LIBRARIES := dobby
LOCAL_LDLIBS       := -llog
LOCAL_CPPFLAGS     := -std=c11 -Os -fvisibility=hidden -Wall -Wextra
include $(BUILD_SHARED_LIBRARY)
