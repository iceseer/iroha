/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_burrow_storage.hpp"

#include <algorithm>
#include <memory>
#include <optional>
#include <string_view>

#include <gtest/gtest.h>
#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>
#include "ametsuchi/impl/soci_std_optional.hpp"
#include "ametsuchi/impl/soci_string_view.hpp"
#include "common/result.hpp"
#include "framework/test_db_manager.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"

using namespace std::literals;
using namespace iroha::ametsuchi;
using namespace iroha::expected;

using iroha::integration_framework::TestDbManager;

static const std::string kTxHash{"tx hash"};
static const shared_model::interface::types::CommandIndexType kCmdIdx{418};

class PostgresBurrowStorageTest : public testing::Test {
 protected:
  std::unique_ptr<TestDbManager> test_db_manager_{
      TestDbManager::createWithRandomDbName(
          1, getTestLoggerManager()->getChild("TestDbManager"))
          .assumeValue()};
  std::unique_ptr<soci::session> sql_{test_db_manager_->getSession()};
  PostgresBurrowStorage storage_{*sql_, kTxHash, kCmdIdx};
};

TEST_F(PostgresBurrowStorageTest, Store2Receipts) {
  // given
  const auto addr{"Mytischi"sv};
  const auto data1{"Achtung"sv};
  const auto data2{"Semki"sv};

  // when
  storage_.storeTxReceipt(addr, data1, {});
  storage_.storeTxReceipt(addr, data2, {});

  // then
  // TODO -- use GetEngineReceipts query?
}
