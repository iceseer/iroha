/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/cluster_order.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      boost::optional<ClusterOrdering> ClusterOrdering::create(
          const std::vector<std::shared_ptr<shared_model::interface::Peer>>
              &order,
          std::vector<size_t> const &peer_positions) {
        if (order.empty()) {
          return boost::none;
        }
        return ClusterOrdering(order, peer_positions);
      }

      ClusterOrdering::ClusterOrdering(
          std::vector<std::shared_ptr<shared_model::interface::Peer>> const
              &order,
          std::vector<size_t> const &peer_positions) {
        order_.reserve(order.size());
        if (!peer_positions.empty()) {
          BOOST_ASSERT_MSG(peer_positions.size() == order.size(), 
            "Peer positions must be the same size to define ordering.");
          
          for (auto const &i : peer_positions) {
            order_.emplace_back(order[i]);
          }
        } else {
          order_ = order;
        }
      }

      // TODO :  24/03/2018 x3medima17: make it const, IR-1164
      const shared_model::interface::Peer &ClusterOrdering::currentLeader() {
        if (index_ >= order_.size()) {
          index_ = 0;
        }
        return *order_.at(index_);
      }

      bool ClusterOrdering::hasNext() const {
        return index_ != order_.size();
      }

      ClusterOrdering &ClusterOrdering::switchToNext() {
        ++index_;
        return *this;
      }

      const std::vector<std::shared_ptr<shared_model::interface::Peer>>
          &ClusterOrdering::getPeers() const {
        return order_;
      }

      size_t ClusterOrdering::getNumberOfPeers() const {
        return order_.size();
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
