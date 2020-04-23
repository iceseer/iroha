/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SOCI_STD_STRING_VIEW_HPP
#define IROHA_SOCI_STD_STRING_VIEW_HPP

#include <soci/type-conversion-traits.h>

#include <string_view>

namespace soci {

  template <typename T>
  struct type_conversion<
      T,
      std::enable_if_t<std::is_same_v<std::decay_t<T>, std::string_view>>> {
    using base_type = std::string;

    static void from_base(base_type const &in,
                          indicator ind,
                          std::string_view &out) {
      // throw soci_error("Value assignment is not allowed to
      // std::string_view.");
    }

    static void to_base(std::string_view const &in,
                        base_type &out,
                        indicator &ind) {
      out.assign(in);
    }
  };

}  // namespace soci

#endif
