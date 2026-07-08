#ifndef MLA_HOOKING_H
#define MLA_HOOKING_H

#include <android/log.h>

#define LOG_TAG "MLA_Hook"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

typedef void* dobby_dummy_func_t;

#endif
