/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_CACHED_PORT_HPP
#define IROHA_ROCKSDB_CACHED_PORT_HPP

#include <charconv>
#include <string>
#include <string_view>

#include <fmt/compile.h>
#include <fmt/format.h>
#include <rocksdb/utilities/transaction.h>
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "interfaces/common_objects/types.hpp"

namespace {
  auto constexpr kValue{FMT_STRING("{}")};
}

namespace iroha::ametsuchi {

  class RocksDbCachedPort {
   public:
    RocksDbCachedPort(RocksDbCommon &db)
        : db_(db), key_buffer_(key_buffer), value_buffer_(value_buffer) {}

    auto encode(uint64_t number) {
      RocksDbCommon::encode(number);
      value_buffer_.clear();
      fmt::format_to(std::back_inserter(value_buffer_), kValue, number);
    }

    auto decode(uint64_t &number) {
      return std::from_chars(value_buffer_.data(),
                             value_buffer_.data() + value_buffer_.size(),
                             number);
    }

    template <typename S, typename... Args>
    auto get(S &fmtstring, Args &&... args) {
      key_buffer_.clear();
      fmt::format_to(key_buffer_, fmtstring, args...);

      value_buffer_.clear();
      return db_transaction_.Get(
          rocksdb::ReadOptions(),
          std::string_view(key_buffer_.data(), key_buffer_.size()),
          &value_buffer_);
    }

    template <typename S, typename... Args>
    auto put(S &fmtstring, Args &&... args) {
      key_buffer_.clear();
      fmt::format_to(key_buffer_, fmtstring, args...);

      return db_transaction_.Put(
          std::string_view(key_buffer_.data(), key_buffer_.size()),
          value_buffer_);
    }

    template <typename S, typename... Args>
    auto del(S &fmtstring, Args &&... args) {
      key_buffer_.clear();
      fmt::format_to(key_buffer_, fmtstring, args...);

      return db_transaction_.Delete(
          std::string_view(key_buffer_.data(), key_buffer_.size()));
    }

    template <typename S, typename... Args>
    auto seek(S &fmtstring, Args &&... args) {
      key_buffer_.clear();
      fmt::format_to(key_buffer_, fmtstring, args...);

      std::unique_ptr<rocksdb::Iterator> it;

      it.reset(db_transaction_.GetIterator(rocksdb::ReadOptions()));
      it->Seek(std::string_view(key_buffer_.data(), key_buffer_.size()));

      return it;
    }

    template <typename F, typename S, typename... Args>
    void enumerate(F &&func, S &fmtstring, Args &&... args) {
      key_buffer_.clear();
      fmt::format_to(key_buffer_, fmtstring, args...);
      std::string_view const key(key_buffer_.data(), key_buffer_.size());

      std::unique_ptr<rocksdb::Iterator> it(
          db_transaction_.GetIterator(rocksdb::ReadOptions()));
      for (it->Seek(key); it->Valid() && it->key().starts_with(key); it->Next())
        if (!std::forward<F>(func)(it, key.size()))
          break;
    }

   private:
    fmt::memory_buffer &key_buffer_;
    std::string &value_buffer_;
    RocksDbCommon &db_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_ROCKSDB_CACHED_PORT_HPP
