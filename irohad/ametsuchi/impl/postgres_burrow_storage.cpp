/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_burrow_storage.hpp"

#include <soci/soci.h>
#include <sys/types.h>
#include <algorithm>
#include <optional>

#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_string_view.hpp"
#include "common/result.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::expected;

PostgresBurrowStorage::PostgresBurrowStorage(
    soci::session &sql,
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index)
    : sql_(sql), tx_hash_(tx_hash), cmd_index_(cmd_index) {}

Result<std::optional<std::string>, std::string>
PostgresBurrowStorage::getAccount(std::string_view address) {
  try {
    std::optional<std::string> data;
    sql_ << "select data from burrow_account_data "
            "where address = lower(:address)",
        soci::use(address, "address"), soci::into(data);
    return data;
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::updateAccount(
    std::string_view address, std::string_view account) {
  try {
    int check = 0;
    sql_ << "insert into burrow_account_data (address, data) "
            "values (lower(:address), :data) "
            "on conflict (address) do update set data = excluded.data "
            "returning 1",
        soci::use(address, "address"), soci::use(account, "data"),
        soci::into(check);
    if (check == 0) {
      return makeError("account data update failed");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::removeAccount(
    std::string_view address) {
  try {
    int check = 0;
    sql_ << "delete from burrow_account_key_value "
            "where address = lower(:address); "
            "delete from burrow_account_data "
            "where address = lower(:address) "
            "returning 1",
        soci::use(address, "address"), soci::into(check);
    if (check == 0) {
      return makeError("account deletion failed");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<std::optional<std::string>, std::string>
PostgresBurrowStorage::getStorage(std::string_view address,
                                  std::string_view key) {
  try {
    std::optional<std::string> value;
    sql_ << "select value from burrow_account_key_value "
            "where address = lower(:address) and key = lower(:key) ",
        soci::use(address, "address"), soci::use(key, "key"), soci::into(value);
    return value;
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::setStorage(
    std::string_view address, std::string_view key, std::string_view value) {
  try {
    int check = 0;
    sql_ << "insert into burrow_account_key_value (address, key, value) "
            "values (lower(:address), lower(:key), :value) "
            "on conflict (address, key) do update set value = excluded.value "
            "returning 1",
        soci::use(address, "address"), soci::use(key, "key"),
        soci::use(value, "value"), soci::into(check);
    if (check == 0) {
      return makeError("account key-value storage update failed");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}

Result<void, std::string> PostgresBurrowStorage::storeTxReceipt(
    std::string_view address,
    std::string_view data,
    std::vector<std::string_view> topics) {
  try {
    std::optional<size_t> log_idx;
    sql_ << "insert into burrow_tx_logs (tx_hash, cmd_index, address, data) "
            "values (lower(:tx_hash), :cmd_index, lower(:address), :data) "
            "returning log_idx",
        soci::use(tx_hash_, "tx_hash"), soci::use(cmd_index_, "cmd_index"),
        soci::use(address, "address"), soci::use(data, "data"),
        soci::into(log_idx);
    if (not log_idx) {
      return makeError("could not insert log data");
    }
    std::vector<int> check{0, topics.size()};
    sql_ << "insert into burrow_tx_logs_topics (topic, log_idx) "
            "values (lower(:topic), :log_idx) "
            "returning 1",
        soci::use(topics, ":topic"), soci::use(log_idx.value(), "log_idx"),
        soci::into(check);
    if (not std::all_of(
            check.begin(), check.end(), [](int i) { return i == 1; })) {
      return makeError("could not insert log topics");
    }
    return Value<void>{};
  } catch (std::exception const &e) {
    return makeError(e.what());
  }
}
