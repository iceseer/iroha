/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_PROFILER_HPP
#define IROHA_PROFILER_HPP

#include <cstdint>

namespace iroha { namespace performance_tools {

//struct {
    // функция
    // метка
    // такты
    // частота
//};

using Hash = uint64_t;
using PerformanceCounter = uint64_t;

inline void initThreadProfiler();
inline void deinitThreadProfiler();

inline void pushFunctionEntry(Hash f_hash, char const* tag);

}}

#endif//IROHA_PROFILER_HPP
