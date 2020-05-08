/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/format.hpp>
#include "ametsuchi/burrow_storage.hpp"
#include "backend/protobuf/queries/proto_get_engine_response.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "interfaces/query_responses/engine_response_record.hpp"
#include "queries.pb.h"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::Amount;
using shared_model::interface::permissions::Role;

static const std::string kTxHash{"hash"};
static const CommandIndexType kCmdIndex1{123ul};
static const CommandIndexType kCmdIndex2{456ul};

static const EvmAddressHexString kAddress1{"Patriarch's Ponds"};
static const EvmDataHexString kData1{"Ann has spilt the oil."};
static const EvmDataHexString kTopic1_1{"wasted"};
static const EvmDataHexString kTopic1_2{"fate"};

static const EvmAddressHexString kAddress2{"302A Sadovaya Street"};
static const EvmDataHexString kData2{"Primus is being repared."};

static const EvmAddressHexString kAddress3{"Satan's ball"};
static const EvmDataHexString kData3{"Manuscripts don't burn."};
static const EvmDataHexString kTopic3_1{"not wasted"};
static const EvmDataHexString kTopic3_2{"deal"};
static const EvmDataHexString kTopic3_3{"fate"};
static const EvmDataHexString kTopic3_4{"Walpurgisnacht"};

namespace {
  using namespace shared_model::interface;
  using namespace testing;
  const testing::Matcher<
      shared_model::interface::EngineReceiptsResponse const &>
      kSpecificResponseChecker{Property(
          &EngineReceiptsResponse::engineReceipts,
          UnorderedElementsAre(
              Matcher<EngineReceipt const &>(AllOf(
                  Property(&EngineReceipt::getCaller, kUserId),
                  Property(
                      &EngineReceipt::getPayloadType,
                      EngineReceipt::PayloadType::kPayloadTypeContractAddress),
                  Property(&EngineReceipt::getPayload, kAddress1),
                  Property(&EngineReceipt::getEngineLogs,
                           UnorderedElementsAre(Pointee(AllOf(
                               Property(&EngineLog::getAddress, kAddress1),
                               Property(&EngineLog::getData, kData1),
                               Property(&EngineLog::getTopics,
                                        UnorderedElementsAre(kTopic1_1,
                                                             kTopic1_2)))))))),
              Matcher<EngineReceipt const &>(AllOf(
                  Property(&EngineReceipt::getCaller, kUserId),
                  Property(&EngineReceipt::getPayloadType,
                           EngineReceipt::PayloadType::kPayloadTypeCallee),
                  Property(&EngineReceipt::getPayload, kAddress1),
                  Property(&EngineReceipt::getEngineLogs,
                           UnorderedElementsAre(
                               Pointee(AllOf(
                                   Property(&EngineLog::getAddress, kAddress2),
                                   Property(&EngineLog::getData, kData2),
                                   Property(&EngineLog::getTopics, IsEmpty()))),
                               Pointee(AllOf(
                                   Property(&EngineLog::getAddress, kAddress3),
                                   Property(&EngineLog::getData, kData3),
                                   Property(&EngineLog::getTopics,
                                            UnorderedElementsAre(
                                                kTopic3_1,
                                                kTopic3_2,
                                                kTopic3_3,
                                                kTopic3_4))))))))))};
}  // namespace

struct GetEngineReceiptsTest : public ExecutorTestBase {
  QueryExecutorResult getEngineReceipts(std::string const &tx_hash,
                                        AccountIdType const &issuer) {
    iroha::protocol::Query proto_query;
    {
      auto query = proto_query.mutable_payload()->mutable_get_engine_receipts();
      query->set_tx_hash(tx_hash);
    }
    return getItf().executeQuery(
        shared_model::proto::GetEngineReceipts{proto_query}, issuer);
  }

  void prepareState() {
    SCOPED_TRACE("prepareState");
    getItf().createDomain(kSecondDomain);
    IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
        kUser, kDomain, kUserKeypair.publicKey(), {}));

    {  // cmd 1
      const auto burrow_storage =
          getBackendParam()->makeBurrowStorage(kTxHash, kCmdIndex1);
      burrow_storage->storeTxReceipt(kAddress1, kData1, {kTopic1_1, kTopic1_2});
    }

    {  // cmd 2
      const auto burrow_storage =
          getBackendParam()->makeBurrowStorage(kTxHash, kCmdIndex2);
      burrow_storage->storeTxReceipt(kAddress2, kData2, {});
      burrow_storage->storeTxReceipt(
          kAddress3, kData3, {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4});
    }
  }
};

using GetEngineReceiptsBasicTest = BasicExecutorTest<GetEngineReceiptsTest>;

/**
 * @given a user with all related permissions
 * @when GetEngineReceipts is queried on the nonexistent tx
 * @then there is an EngineReceiptsResponse reporting no receipts
 */
TEST_P(GetEngineReceiptsBasicTest, NoReceipts) {
  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(kTxHash, kAdminId), [](const auto &response) {
        using namespace testing;
        EXPECT_EQ(boost::size(response.engineReceipts()), 0);
      });
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetEngineReceiptsBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetEngineReceiptsPermissionTest =
    query_permission_test::QueryPermissionTest<GetEngineReceiptsTest>;

TEST_P(GetEngineReceiptsPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({}));
  // prepareState();
  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(kTxHash, getSpectator()),
      [](const shared_model::interface::EngineReceiptsResponse &response) {
        EXPECT_THAT(response, kSpecificResponseChecker);
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetEngineReceiptsPermissionTest,
    query_permission_test::getParams({Role::kGetMyEngineReceipts},
                                     {Role::kGetDomainEngineReceipts},
                                     {Role::kGetAllEngineReceipts}),
    query_permission_test::paramToString);
