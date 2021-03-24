/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/common_objects/amount.hpp"

#include <sstream>
#include <type_traits>
#include <utility>

#include <gtest/gtest.h>
#include <boost/math/special_functions/sign.hpp>

using namespace shared_model::interface;

struct AmountTest : public ::testing::Test {
  /// Check sign, precision and string representation of a valid amount.
  void checkValid(const Amount &tested,
                  int ref_sign,
                  types::PrecisionType ref_precision,
                  std::string ref_str) {
    EXPECT_EQ(boost::math::sign(tested.sign()), boost::math::sign(ref_sign));
    EXPECT_EQ(tested.precision(), ref_precision);
    EXPECT_EQ(tested.toStringRepr(), ref_str);
  }

  /// Check sign, precision and string representation of an invalid amount.
  void checkInvalid(const Amount &tested) {
    EXPECT_EQ(tested.sign(), 0);
    EXPECT_EQ(tested.precision(), 0);
    EXPECT_EQ(tested.toStringRepr(), "NaN");
  }
};

TEST_F(AmountTest, Basic) {
  checkValid(Amount{"0"}, 0, 0, "0");
  checkValid(Amount{"0.1"}, 1, 1, "0.1");
  checkValid(Amount{"1234"}, 1, 0, "1234");
  checkValid(Amount{"23.45"}, 1, 2, "23.45");
}

TEST_F(AmountTest, Strange) {
  checkValid(Amount{"000.000"}, 0, 3, "0.000");
  checkValid(Amount{"000.001"}, 1, 3, "0.001");
  checkValid(Amount{"0000000"}, 0, 0, "0");
  checkValid(Amount{"0000009"}, 1, 0, "9");
  checkValid(Amount{"1.00000"}, 1, 5, "1.00000");
}

TEST_F(AmountTest, Invalid) {
  checkInvalid(Amount{"-100"});
  checkInvalid(Amount{"-1.23"});
  checkInvalid(Amount{"0xFF"});
  checkInvalid(Amount{"12.34.56"});
  checkInvalid(Amount{".3456"});
  checkInvalid(Amount{".12.34"});
  checkInvalid(Amount{"0A"});
  checkInvalid(Amount{"1."});
  checkInvalid(Amount{"."});
  checkInvalid(Amount{""});
  checkInvalid(Amount{std::string("0.").append(255, '0').append("1")});
  checkInvalid(
      Amount{"11579208923731619542357098500868790785326998466564056403945758400"
             "7913129639936"});
}

TEST_F(AmountTest, Add) {
  checkValid(Amount{"000.000"} += Amount{"1.0"}, 1, 3, "1.000");
  checkValid(Amount{"000.000"} += Amount{"0.1"}, 1, 3, "0.100");
  checkValid(Amount{"000.000"} += Amount{"0.01"}, 1, 3, "0.010");
  checkInvalid(Amount{"000.000"} += Amount{"1.0001"});
  checkInvalid(Amount{"11579208923731619542357098500868790785326998466564056403"
                      "945758400791312963993.5"} += Amount{"0.1"});
  checkInvalid(Amount{"11579208923731619542357098500868790785326998466564056403"
                      "945758400791312963993.5"} += Amount{"1"});
  checkInvalid(Amount{"0."
                      "00000000000000000000000000000000000000000000000000000000"
                      "00000000000000000000001"} += Amount{"1"});
}

TEST_F(AmountTest, Sub) {
  checkValid(Amount{"1.000"} -= Amount{"0.1"}, 1, 3, "0.900");
  checkInvalid(Amount{"1.000"} -= Amount{"2.0"});
}
