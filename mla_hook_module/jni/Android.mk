LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE     := dobby
LOCAL_SRC_FILES  := ../prebuilt/$(TARGET_ARCH_ABI)/libdobby.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE       := mla_hook
LOCAL_SRC_FILES    := mla_hook.cpp
LOCAL_C_INCLUDES   := $(LOCAL_PATH)/../../Dobby/include \
                       $(LOCAL_PATH)
LOCAL_SHARED_LIBRARIES := dobby
LOCAL_LDLIBS       := -llog -ldl
LOCAL_CPPFLAGS     := -std=c++17 -Os -fvisibility=hidden -Wall -Wextra
include $(BUILD_SHARED_LIBRARY)