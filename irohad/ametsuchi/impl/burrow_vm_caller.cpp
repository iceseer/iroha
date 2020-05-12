/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/burrow_vm_caller.hpp"

#include <soci/session.h>
#include BURROW_VM_CALL_HEADER
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/postgres_burrow_storage.hpp"
#include "ametsuchi/query_executor.hpp"
#include "common/hexutils.hpp"
#include "common/result.hpp"

using namespace iroha::ametsuchi;

iroha::expected::Result<std::string, std::string> BurrowVmCaller::call(
    soci::session &sql,
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    shared_model::interface::types::EvmCodeHexString const &input,
    shared_model::interface::types::AccountIdType const &caller,
    std::optional<shared_model::interface::types::EvmCalleeHexStringView>
        callee,
    CommandExecutor &command_executor,
    SpecificQueryExecutor &query_executor) const {
  const char *callee_raw = callee
      ? static_cast<std::string_view &>(callee.value()).data()
      : static_cast<const char *>(nullptr);
  const char *input_raw =
      const_cast<char *>(static_cast<const std::string &>(input).c_str());
  std::string nonce = tx_hash;
  const char *nonce_raw =
      const_cast<char *>(nonce.append(uint64ToHexstring(cmd_index)).c_str());
  auto burrow_storage =
      std::make_unique<PostgresBurrowStorage>(sql, tx_hash, cmd_index);
  auto res = VmCall(input_raw,
                    caller.c_str(),
                    callee_raw,
                    nonce_raw,
                    &command_executor,
                    &query_executor,
                    burrow_storage.get());
  if (res.r1 != nullptr) {
    return iroha::expected::makeError("Internal error.");
  }
  if (res.r0 != nullptr) {
    return iroha::expected::makeValue(res.r0);
  }
  return iroha::expected::makeValue("");
}
