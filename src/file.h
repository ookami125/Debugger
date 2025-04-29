#pragma once
#include "error.h"

ErrorOr<char*> readFile(const char* path, size_t& length);
ErrorOr<void> writeFile(const char* path, const char* data, size_t length);