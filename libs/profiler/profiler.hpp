/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_HPP
#define IROHA_PROFILER_HPP

namespace iroha { namespace performance_tools {

struct {
    // функция
    // метка
    // такты
    // частота
};


struct Profiler final {
    using ProfilerHandle = uint64_t;
    using Hash = uint64_t;
    using PerformanceCounter = uint64_t;

    Profiler(Profiler const&) = delete;
    Profiler& operator=(Profiler const&) = delete;

    Profiler(Profiler&&) = delete;
    Profiler& operator=(Profiler&&) = delete;

    Profiler() = default;
    ~Profiler() = default;

public:
    inline void push(Hash hash, char const *tag);
    inline void pop(PerformanceCounter counter);
};


extern ProfilerHandle getProfilerHandle();


}}

#endif//IROHA_PROFILER_HPP