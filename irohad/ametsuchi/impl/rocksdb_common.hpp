/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_COMMON_HPP
#define IROHA_ROCKSDB_COMMON_HPP

#include <charconv>
#include <string>
#include <string_view>
#include <mutex>

#include <fmt/compile.h>
#include <fmt/format.h>
#include <rocksdb/utilities/transaction.h>
#include <rocksdb/utilities/optimistic_transaction_db.h>
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
  static constexpr size_t kDelimiterSize = sizeof(RDB_DELIMITER)/sizeof(RDB_DELIMITER[0]) - 1ul;

  /**
   * Paths
   */
  static auto constexpr kPathAccountRoles{
      FMT_STRING(RDB_PATH_ACCOUNT /**/ RDB_ROLES)};

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

  struct RocksDBContext {
    std::unique_ptr<rocksdb::Transaction> transaction;
    fmt::memory_buffer key_buffer;
    std::string value_buffer;
  };

  struct RocksDBPort : std::enable_shared_from_this<RocksDBPort> {
    RocksDBPort(RocksDBPort const&) = delete;
    RocksDBPort& operator=(RocksDBPort const&) = delete;
    RocksDBPort() = default;

    void initialize(std::string const &db_name) {
      rocksdb::Options options;
      options.create_if_missing = true;
      options.error_if_exists = true;

      rocksdb::OptimisticTransactionDB *transaction_db;
      auto status = rocksdb::OptimisticTransactionDB::Open(
          options, db_name, &transaction_db);
      transaction_db_.reset(transaction_db);

      if (!status.ok())
        throw std::runtime_error(status.ToString());
    }

    void prepareTransaction(RocksDBContext &tx_context) {
      assert(transaction_db_);
      tx_context.transaction.reset(
          transaction_db_->BeginTransaction(rocksdb::WriteOptions()));
      tx_context.key_buffer.clear();
      tx_context.value_buffer.clear();
    }

   private:
    std::unique_ptr<rocksdb::OptimisticTransactionDB> transaction_db_;
  };

  template<typename Tx>
  class RocksDbCommon {
    inline auto &valueBuffer() {
      return tx_context_->value_buffer;
    }
    inline auto &keyBuffer() {
      return tx_context_->key_buffer;
    }
    inline auto &transaction() {
      return tx_context_->transaction;
    }

   public:
    RocksDbCommon(Tx tx_context) : tx_context_(std::move(tx_context)) {
      assert(tx_context_);
    }

    auto encode(uint64_t number) {
      valueBuffer().clear();
      fmt::format_to(std::back_inserter(valueBuffer()), kValue, number);
    }

    auto decode(uint64_t &number) {
      return std::from_chars(valueBuffer().data(),
                             valueBuffer().data() + valueBuffer().size(),
                             number);
    }

    template <typename S, typename... Args>
    auto get(S &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, args...);

      valueBuffer().clear();
      return transaction()->Get(
          rocksdb::ReadOptions(),
          std::string_view(keyBuffer().data(), keyBuffer().size()),
          &valueBuffer());
    }

    template <typename S, typename... Args>
    auto put(S &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, args...);

      return transaction()->Put(
          std::string_view(keyBuffer().data(), keyBuffer().size()),
          valueBuffer());
    }

    template <typename S, typename... Args>
    auto del(S &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, args...);

      return transaction()->Delete(
          std::string_view(keyBuffer().data(), keyBuffer().size()));
    }

    template <typename S, typename... Args>
    auto seek(S &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, args...);

      std::unique_ptr<rocksdb::Iterator> it;

      it.reset(transaction()->GetIterator(rocksdb::ReadOptions()));
      it->Seek(std::string_view(keyBuffer().data(), keyBuffer().size()));

      return it;
    }

    template <typename F, typename S, typename... Args>
    void enumerate(F &&func, S &fmtstring, Args &&... args) {
      keyBuffer().clear();
      fmt::format_to(keyBuffer(), fmtstring, args...);
      std::string_view const key(keyBuffer().data(), keyBuffer().size());

      std::unique_ptr<rocksdb::Iterator> it(
          transaction()->GetIterator(rocksdb::ReadOptions()));
      for (it->Seek(key); it->Valid() && it->key().starts_with(key); it->Next())
        if (!std::forward<F>(func)(it, key.size()))
          break;
    }

   private:
    Tx tx_context_;
  };

}  // namespace iroha::ametsuchi

#endif
