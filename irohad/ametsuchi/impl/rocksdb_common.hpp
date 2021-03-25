/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_COMMON_HPP
#define IROHA_ROCKSDB_COMMON_HPP

#include <charconv>
#include <string>
#include <string_view>

#include <fmt/compile.h>
#include <fmt/format.h>
#include <rocksdb/utilities/transaction.h>
#include "interfaces/common_objects/types.hpp"

/**
 * ######################################
 * ############# LEGEND MAP #############
 * ######################################
 *
 * ######################################
 * ###   Directory   ##   Mnemonics   ###
 * ######################################
 * ### DELIMITER     ##       /       ###
 * ### ROOT          ##    <empty>    ###
 * ### STORE         ##       s       ###
 * ### WSV           ##       w       ###
 * ### NETWORK       ##       n       ###
 * ### SETTINGS      ##       i       ###
 * ### ASSETS        ##       x       ###
 * ### ROLES         ##       r       ###
 * ### TRANSACTIONS  ##       t       ###
 * ### ACCOUNTS      ##       a       ###
 * ### PEERS         ##       p       ###
 * ### STATUSES      ##       u       ###
 * ### DETAILS       ##       d       ###
 * ### GRANTABLE_PER ##       g       ###
 * ### POSITION      ##       P       ###
 * ### TIMESTAMP     ##       T       ###
 * ### DOMAIN        ##       D       ###
 * ### SIGNATORIES   ##       S       ###
 * ### OPTIONS       ##       O       ###
 * ######################################
 *
 * ######################################
 * ###     File      ##   Mnemonics   ###
 * ######################################
 * ### F_QUORUM      ##       q       ###
 * ### F_ASSET SIZE  ##       I       ###
 * ######################################
 *
 * ######################################
 * ############# EXAMPLE ################
 * ######################################
 *
 * GetAccountTransactions(ACCOUNT, TS) -> KEY: wta/ACCOUNT/T/TS/
 * GetAccountAssets(DOMAIN,ACCOUNT)    -> KEY: wD/DOMAIN/a/ACCOUNT/x
 */

#define RDB_DELIMITER     "/"
#define RDB_XXX RDB_DELIMITER "{}" RDB_DELIMITER

#define RDB_ROOT          ""
#define RDB_STORE         "s"
#define RDB_WSV           "w"
#define RDB_NETWORK       "n"
#define RDB_SETTINGS      "i"
#define RDB_ASSETS        "x"
#define RDB_ROLES         "r"
#define RDB_TRANSACTIONS  "t"
#define RDB_ACCOUNTS      "a"
#define RDB_PEERS         "p"
#define RDB_STATUSES      "u"
#define RDB_DETAILS       "d"
#define RDB_GRANTABLE_PER "g"
#define RDB_POSITION      "P"
#define RDB_TIMESTAMP     "T"
#define RDB_DOMAIN        "D"
#define RDB_SIGNATORIES   "S"
#define RDB_OPTIONS       "O"

#define RDB_F_QUORUM      "q"
#define RDB_F_ASSET_SIZE  "I"

#define RDB_PATH_DOMAIN RDB_ROOT /**/ RDB_WSV /**/ RDB_DOMAIN /**/ RDB_XXX
#define RDB_PATH_ACCOUNT RDB_PATH_DOMAIN /**/ RDB_ACCOUNTS /**/ RDB_XXX

namespace iroha::ametsuchi::fmtstrings {

  // domain_id/account_name
  static auto constexpr kQuorum{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_QUORUM)};

  // domain_id/account_name/role_name
  static auto constexpr kAccountRole{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ROLES /**/ RDB_XXX)};

  // role_name ➡️ permissions
  static auto constexpr kRole{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_ROLES /**/
                     RDB_XXX)};

  // domain_id ➡️ default role
  static auto constexpr kDomain{FMT_STRING(RDB_PATH_DOMAIN)};

  // domain_id/account_name/pubkey ➡️ ""
  static auto constexpr kSignatory{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_SIGNATORIES /**/ RDB_XXX)};

  // domain_id/asset_name ➡️ precision
  static auto constexpr kAsset{
      FMT_STRING(RDB_PATH_DOMAIN /**/ RDB_ASSETS /**/ RDB_XXX)};

  // account_domain_id/account_name/asset_id ➡️ amount
  static auto constexpr kAccountAsset{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ASSETS /**/ RDB_XXX)};

  // account_domain_id/account_name ➡️ size
  static auto constexpr kAccountAssetSize{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_OPTIONS /**/ RDB_F_ASSET_SIZE)};

  // domain_id/account_name/writer_domain_id/writer_account_name/key ➡️ value
  static auto constexpr kAccountDetail{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_DETAILS /**/ RDB_XXX /**/
                     RDB_XXX /**/ RDB_XXX)};

  // pubkey ➡️ address
  static auto constexpr kPeer{FMT_STRING(
      RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK /**/ RDB_PEERS /**/ RDB_XXX)};

  // domain_id/account_name ➡️ permissions
  // TODO(iceseer): Role is a Permission set, Account have role -> it determines Permissions for Account -> Delete a Role just drop Permissions for this Role.
  /*static auto constexpr kPermissions{FMT_STRING(
      "permissions/{}/{}")};  */

  // domain_id/account_name/grantee_domain_id/grantee_account_name
  // ➡️ permissions
  static auto constexpr kGranted{FMT_STRING(
      RDB_PATH_ACCOUNT /**/ RDB_GRANTABLE_PER /**/ RDB_XXX /**/ RDB_XXX)};

  // key ➡️ value
  static auto constexpr kSetting{
      FMT_STRING(RDB_ROOT /**/ RDB_WSV /**/ RDB_SETTINGS /**/ RDB_XXX)};
}

#undef RDB_OPTIONS
#undef RDB_F_ASSET_SIZE
#undef RDB_PATH_DOMAIN
#undef RDB_PATH_ACCOUNT
#undef RDB_F_QUORUM
#undef RDB_DELIMITER
#undef RDB_ROOT
#undef RDB_STORE
#undef RDB_WSV
#undef RDB_NETWORK
#undef RDB_SETTINGS
#undef RDB_ASSETS
#undef RDB_ROLES
#undef RDB_TRANSACTIONS
#undef RDB_ACCOUNTS
#undef RDB_PEERS
#undef RDB_STATUSES
#undef RDB_DETAILS
#undef RDB_GRANTABLE_PER
#undef RDB_POSITION
#undef RDB_TIMESTAMP
#undef RDB_DOMAIN
#undef RDB_SIGNATORIES
#undef RDB_ITEM

namespace {
  auto constexpr kValue{FMT_STRING("{}")};
}

namespace iroha::ametsuchi {

  class RocksDbCommon {
   public:
    RocksDbCommon(rocksdb::Transaction &db_transaction,
                  fmt::memory_buffer &key_buffer,
                  std::string &value_buffer)
        : db_transaction_(db_transaction),
          key_buffer_(key_buffer),
          value_buffer_(value_buffer) {
      key_buffer_.clear();
      value_buffer_.clear();
    }

    auto encode(uint64_t number) {
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
    auto enumerate(F &&func, S &fmtstring, Args &&... args) {
      key_buffer_.clear();
      fmt::format_to(key_buffer_, fmtstring, args...);

      std::unique_ptr<rocksdb::Iterator> it(db_transaction_.GetIterator(rocksdb::ReadOptions()));


      //it->Seek(std::string_view(key_buffer_.data(), key_buffer_.size()));

      return it;
    }

   private:
    rocksdb::Transaction &db_transaction_;
    fmt::memory_buffer &key_buffer_;
    std::string &value_buffer_;
  };

}  // namespace iroha::ametsuchi

#endif
