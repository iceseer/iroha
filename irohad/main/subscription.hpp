/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_HPP
#define IROHA_SUBSCRIPTION_HPP

#include <memory>

#include "subscription/common.hpp"
#include "subscription/subscriber_impl.hpp"
#include "subscription/subscription_manager.hpp"

namespace iroha {
  enum SubscriptionEngineHandlers {
    kYac = 0,
    //---------------
    kTotalCount
  };

  enum EventTypes {
    kOnOutcome = 0,
    kOnSynchronization,
    kOnCurrentRoundPeers,
    kOnRoundSwitch,
    kOnProposal,
    kOnVerifiedProposal,
    kOnProcessedHashes,
    kOnOutcomeFromYac,
    kOnOutcomeDelayed,
    kOnBlock,
    kOnBlockCreatorEvent,
    kOnFinalizedTxs,
    kOnApplyState,

    // MST
    kOnStateUpdate,
    kOnPreparedBatches,
    kOnExpiredBatches
  };

  using Subscription = subscription::SubscriptionManager<
      SubscriptionEngineHandlers::kTotalCount>;
  using SubscriptionDispatcher = typename Subscription::Dispatcher;

  template <typename ObjectType, typename EventDataType>
  using BaseSubscriber = subscription::SubscriberImpl<EventTypes,
                                                      SubscriptionDispatcher,
                                                      ObjectType,
                                                      EventDataType>;

  std::shared_ptr<Subscription> getSubscription();
}  // namespace iroha

#endif  // IROHA_SUBSCRIPTION_HPP
