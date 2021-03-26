/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_MOCKS_HPP
#define IROHA_SUBSCRIPTION_MOCKS_HPP

#include <gmock/gmock.h>
#include "main/subscription.hpp"

namespace iroha::subscription {

  template <typename EventKey, typename Dispatcher, typename Argument>
  class MockSubscriber : public Subscriber<EventKey, Dispatcher, Argument> {
   public:
    using Parent = Subscriber<EventKey, Dispatcher, Argument>;
    using SubscriptionEngineType = SubscriptionEngine<
        typename Parent::EventType,
        Dispatcher,
        Subscriber<typename Parent::EventType, Dispatcher, Argument>>;
    using SubscriptionEnginePtr = std::shared_ptr<SubscriptionEngineType>;

    SubscriptionEnginePtr engine_;
    MockSubscriber(SubscriptionEnginePtr const &engine) : engine_(engine) {}

    template <typename Dispatcher::Tid kTid>
    void subscribe(const typename Parent::EventType &key) {
      engine_->template subscribe<kTid>(0ull, key, Parent::weak_from_this());
    }

    MOCK_METHOD3_T(on_notify,
                   void(SubscriptionSetId, const EventKey &, Argument &&));
    MOCK_METHOD1(print, void (std::stringstream &));
  };

  class MockDispatcher {
   public:
    using Tid = uint32_t;

   public:
    MockDispatcher() = default;

    template <Tid kId>
    static constexpr void checkTid() {}

    template <typename F>
    void add(Tid, F &&f) {
      std::forward<F>(f)();
    }

    template <typename F>
    void addDelayed(Tid, std::chrono::microseconds, F &&f) {
      std::forward<F>(f)();
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_MOCKS_HPP
