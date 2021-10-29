#pragma once
#include <ntifs.h>

#define DPRINT_LOG(message, ...) LogWrite(message, __VA_ARGS__);

VOID LogClose();
HANDLE LogOpen();
VOID LogWrite(const char* text, ...);