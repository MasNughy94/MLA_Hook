#ifndef MLA_HOOKING_H
#define MLA_HOOKING_H

#include <cstdint>
#include <android/log.h>

#define LOG_TAG "MLA_Hook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

namespace mla {

// Initialize all hooks
bool initialize();

// Cleanup all hooks
void cleanup();

} // namespace mla

#endif
