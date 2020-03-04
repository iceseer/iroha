/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "profiler/profiler.hpp"

//#include <algorithm>
//#include <cstdlib>
#include <memory>
#include <unordered_map>

namespace {

static const size_t stack_depth = 1024;

class Profiler final {
    struct StackFrame{
        Hash f_id;
        uint16_t entry_count_;
    } f_stack_[stack_depth];

    struct FunctionContext {
        char const* f_name;
        uint64_t ns_counter;
    };

    struct FunctionChain {

    };

    std::unordered_map<Hash, FunctionContext> f_description_;
    std::unordered_map<Hash, FunctionChain> f_chains_;

public:
    Profiler(Profiler const&) = delete;
    Profiler& operator=(Profiler const&) = delete;

    Profiler(Profiler&&) = delete;
    Profiler& operator=(Profiler&&) = delete;

    Profiler() {
        static_assert(std::is_pod_v<StackFrame>, "StackFrame must be POD!");
        memset(f_stack_, 0, sizeof(f_stack_));
    }
    ~Profiler() = default;

public:
    inline void push(Hash hash, char const *tag) {
        
    }
    inline void pop(PerformanceCounter counter);
};

}

namespace iroha { namespace performance_tools {

thread_local std::unique_ptr<Profiler> profiler_instance;

void initThreadProfiler() {
    if (!profiler_instance)
        profiler_instance = std::make_unique<Profiler>();
}

void deinitThreadProfiler() {
    profiler_instance.reset();
}

inline void pushFunctionEntry(Hash f_hash, char const* tag) {

}

} }
