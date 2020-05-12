/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_HEXUTILS_HPP
#define IROHA_HEXUTILS_HPP

#include <iterator>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/optional.hpp>
#include "common/result.hpp"
#include "interfaces/common_objects/byte_range.hpp"

namespace iroha {

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  template <typename OutputContainer>
  inline void bytestringToHexstringAppend(
      shared_model::interface::types::ByteRange input,
      OutputContainer &destination) {
    static_assert(sizeof(*input.data()) == sizeof(uint8_t), "type mismatch");
    const auto beg = reinterpret_cast<const uint8_t *>(input.data());
    const auto end = beg + input.size();
    destination.reserve(destination.size() + input.size() * 2);
    boost::algorithm::hex_lower(beg, end, std::back_inserter(destination));
  }

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  inline std::string bytestringToHexstring(std::string_view str) {
    std::string result;
    bytestringToHexstringAppend(
        shared_model::interface::types::makeByteRange(str), result);
    return result;
  }

  /**
   * Convert printable hex string to string of raw bytes
   * @param str - hex string to convert
   * @return - raw bytes converted string or boost::noneif provided string
   * was not a correct hex string
   */
  inline iroha::expected::Result<std::string, const char *>
  hexstringToBytestringResult(std::string_view str) {
    using namespace iroha::expected;
    if (str.empty()) {
      return makeError("Empty hex string.");
    }
    if (str.size() % 2 != 0) {
      return makeError("Hex string contains uneven number of characters.");
    }
    std::string result;
    result.reserve(str.size() / 2);
    try {
      boost::algorithm::unhex(
          str.begin(), str.end(), std::back_inserter(result));
    } catch (const boost::algorithm::hex_decode_error &e) {
      return makeError(e.what());
    }
    return iroha::expected::makeValue(std::move(result));
  }

  [[deprecated]] inline boost::optional<std::string> hexstringToBytestring(
      const std::string &str) {
    return iroha::expected::resultToOptionalValue(
        hexstringToBytestringResult(str));
  }

  /**
   * Convert uint64_t number to a printable hex string
   * @param val - unsinged integer value
   * @return - converted hex string
   */
  inline std::string uint64ToHexstring(const uint64_t val) {
    std::stringstream ss;
    ss << std::hex << val;
    auto res = ss.str();
    if (res.size() & 0x1)
      res.insert(0, "0");
    return res;
  }

}  // namespace iroha

#endif  // IROHA_HEXUTILS_HPP
