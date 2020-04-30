/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_VM_CALLER_HPP
#define IROHA_AMETSUCHI_VM_CALLER_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "common/result_fwd.hpp"
#include "interfaces/common_objects/string_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace soci {
  class session;
}

namespace iroha::ametsuchi {
  class CommandExecutor;
  class SpecificQueryExecutor;

  class VmCaller {
   public:
    virtual iroha::expected::Result<std::string, std::string> call(
        soci::session &sql,
        std::string const &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        shared_model::interface::types::EvmCodeHexString const &input,
        shared_model::interface::types::AccountIdType const &caller,
        std::optional<std::reference_wrapper<const std::string>> callee,
        CommandExecutor &command_executor,
        SpecificQueryExecutor &query_executor) const = 0;
  };
}  // namespace iroha::ametsuchi

#endif
