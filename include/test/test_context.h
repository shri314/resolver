#pragma once

#include "util/stringize.h"

#define TEST_CONTEXT(x)       __FILE__ + "("s + STRINGIZE(__LINE__) + "): "s + (x)
