/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_command_executor.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <fmt/core.h>
#include <rocksdb/utilities/transaction.h>
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/setting_query.hpp"
#include "ametsuchi/vm_caller.hpp"
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/call_engine.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/compare_and_set_account_detail.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_peer.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/set_setting_value.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

using shared_model::interface::GrantablePermissionSet;
using shared_model::interface::RolePermissionSet;

/**
 * RocksDB data structure.
 *
 * |ROOT|-+-|STORE|-+-<height_1, value:block>
 *        |         +-<height_2, value:block>
 *        |         +-<height_3, value:block>
 *        |
 *        +-|WSV|-+-|NETWORK|-+-|PEERS|-+-<peer_1_pubkey, value:address>
 *                |           |         +-<peer_2_pubkey, value:address>
 *                |           |
 *                |           +-|STORE|-+-<store height>
 *                |                     +-<top block hash>
 *                |                     +-<transactions count>
 *                |
 *                +-|SETTINGS|-+-<key_1, value_1>
 *                |            +-<key_2, value_2>
 *                |            +-<key_3, value_3>
 *                |
 *                +-|ROLES|-+-<role_1, value:permissions bitfield>
 *                |         +-<role_2, value:permissions bitfield>
 *                |         +-<role_3, value:permissions bitfield>
 *                |
 *                +-|TRANSACTIONS|-+-|ACCOUNTS|-+-<account_1>-+-|POSITION|-+-<height_index, value:tx_hash_1>
 *                |                |            |             |            +-<height_index, value:tx_hash_2>
 *                |                |            |             |            +-<height_index, value:tx_hash_3>
 *                |                |            |             |
 *                |                |            |             +-|TIMESTAMP|-+-<ts_1, value:tx_hash_1>
 *                |                |            |                           +-<ts_2, value:tx_hash_2>
 *                |                |            |                           +-<ts_3, value:tx_hash_3>
 *                |                |            |
 *                |                |            +-<account_2>-+-|POSITION|-+-<height_index, value:tx_hash_4>
 *                |                |                          |            +-<height_index, value:tx_hash_5>
 *                |                |                          |            +-<height_index, value:tx_hash_6>
 *                |                |                          |
 *                |                |                          +-|TIMESTAMP|-+-<ts_1, value:tx_hash_4>
 *                |                |                                        +-<ts_2, value:tx_hash_5>
 *                |                |                                        +-<ts_3, value:tx_hash_6>
 *                |                |
 *                |                +-|STATUSES|-+-<tx_hash_1, value:status_height_index>
 *                |                             +-<tx_hash_2, value:status_height_index>
 *                |
 *                +-|DOMAIN|-+-|DOMAIN_1|-+-|ASSETS|-+-<asset_1, value:precision>
 *                           |            |          +-<asset_2, value:precision>
 *                           |            |
 *                           |            +-|ACCOUNTS|-|NAME_1|-+-|ASSETS|-+-<asset_1, value:quantity>
 *                           |                                  |          +-<asset_2, value:quantity>
 *                           |                                  |
 *                           |                                  +-|OPTIONS|-+-<quorum>
 *                           |                                  |           +-<asset_size>
 *                           |                                  |
 *                           |                                  +-|DETAILS|-+-<domain>-<account>-<key>
 *                           |                                  |
 *                           |                                  +-|ROLES|-+-<role_1, value:flag>
 *                           |                                  |         +-<role_2, value:flag>
 *                           |                                  |
 *                           |                                  +-|GRANTABLE_PER|-+-<domain_account_1, value:permissions>
 *                           |                                  |                 +-<domain_account_2, value:permissions>
 *                           |                                  |
 *                           |                                  +-|SIGNATORIES|-+-<signatory_1>
 *                           |                                                  +-<signatory_2>
 *                           |
 *                           +-|DOMAIN_2|
 */

#define IROHA_ERROR_IF_CONDITION(condition, code, command_name, error_extra)   \
  if (condition) {                                                             \
    return expected::makeError(CommandError{command_name, code, error_extra}); \
  }

#define IROHA_ERROR_NOT_IMPLEMENTED() \
  IROHA_ERROR_IF_CONDITION(true, 100, command.toString(), "")

#define IROHA_ERROR_IF_NOT_OK() \
  IROHA_ERROR_IF_CONDITION(     \
      not status.ok(), 1, command.toString(), status.ToString())

#define IROHA_ERROR_IF_FOUND(code)                              \
  IROHA_ERROR_IF_CONDITION(                                     \
      status.ok(), code, command.toString(), status.ToString()) \
  IROHA_ERROR_IF_CONDITION(                                     \
      not status.IsNotFound(), code, command.toString(), status.ToString())

#define IROHA_ERROR_IF_NOT_FOUND(code)                                  \
  IROHA_ERROR_IF_CONDITION(                                             \
      status.IsNotFound(), code, command.toString(), status.ToString()) \
  IROHA_ERROR_IF_NOT_OK()

#define IROHA_ERROR_IF_NOT_SUBSET()                         \
  IROHA_ERROR_IF_CONDITION(                                 \
      not role_permissions.isSubsetOf(creator_permissions), \
      2,                                                    \
      command.toString(),                                   \
      "")

#define IROHA_ERROR_IF_NOT_SET(elem) \
  IROHA_ERROR_IF_CONDITION(          \
      not creator_permissions.isSet(elem), 2, command.toString(), "")

#define IROHA_ERROR_IF_NOT_ROLE_OR_GRANTABLE_SET(role, grantable) \
  IROHA_ERROR_IF_CONDITION(                                       \
      not(creator_permissions.isSet(role)                         \
          or granted_account_permissions.isSet(grantable)),       \
      2,                                                          \
      command.toString(),                                         \
      "")

#define IROHA_ERROR_IF_NOT_GRANTABLE_SET(elem) \
  IROHA_ERROR_IF_NOT_ROLE_OR_GRANTABLE_SET(Role::kRoot, elem)

#define IROHA_ERROR_IF_ANY_NOT_SET(all, domain)                             \
  IROHA_ERROR_IF_CONDITION(not((creator_permissions.isSet(all))             \
                               or (domain_id == creator_domain_id           \
                                   and creator_permissions.isSet(domain))), \
                           2,                                               \
                           command.toString(),                              \
                           "")

#define IROHA_CHECK_ERROR(name,value) \
  decltype(value)::ValueInnerType name; \
            if (auto result = (value); result.which() == 1) { \
return expected::makeError(CommandError{ result.assumeError() }); \
} else { \
name = std::move(boost::get<decltype(result)::ValueInnerType>(result)); \
}


RocksDbCommandExecutor::RocksDbCommandExecutor(
    std::shared_ptr<RocksDBPort> db_port,
    std::shared_ptr<shared_model::interface::PermissionToString> perm_converter,
    std::optional<std::reference_wrapper<const VmCaller>> vm_caller)
    : db_port_(std::move(db_port)),
      perm_converter_{std::move(perm_converter)},
      vm_caller_{std::move(vm_caller)} {
  db_port_->prepareTransaction(*db_context_);
}

RocksDbCommandExecutor::~RocksDbCommandExecutor() = default;

expected::Result<RolePermissionSet, CommandError>
    RocksDbCommandExecutor::getAccountPermissions(std::string_view domain, std::string_view account) {
  assert(!domain.empty());
  assert(!account.empty());

  /// TODO(iceseer): remove this vector!
  std::vector<std::string> roles;
  RocksDbCommon common(db_context_);

  common.enumerate(
      [&](std::unique_ptr<rocksdb::Iterator> const &it,
          size_t const prefix_size) {
        if (!it->status().ok())
          return false;
        auto const key = it->key().ToStringView();

        auto const role =
            key.substr(prefix_size + fmtstrings::kDelimiterSize,
                       key.size() - prefix_size
                       - 2ul * fmtstrings::kDelimiterSize);

        if(!role.empty())
          roles.emplace_back(role);
        else {
          assert(!"Role can not be empty string!");
        }
      },
      fmtstrings::kPathAccountRoles,
      domain,
      account);

  auto cmd = [&](){
    return fmt::format(fmtstrings::kPathAccountRoles,
                       domain,
                       account);
  };

  IROHA_ERROR_IF_CONDITION(roles.empty(), 1001, cmd(), "");
  RolePermissionSet permissions;

  for (auto &role : roles) {
    auto status = common.get(fmtstrings::kRole, role);
    IROHA_ERROR_IF_CONDITION(!status.ok(), 1002, cmd(), "");

    permissions |= RolePermissionSet{db_context_->value_buffer};
  }
  return permissions;
}

CommandResult RocksDbCommandExecutor::execute(
    const shared_model::interface::Command &cmd,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation) {
  return boost::apply_visitor(
      [this, &creator_account_id, &tx_hash, cmd_index, do_validation](
          const auto &command) -> CommandResult {
        RocksDbCommon common(db_context_);
        RolePermissionSet creator_permissions;

        if (do_validation) {
          auto names = splitId(creator_account_id);
          auto &account_name = names.at(0);
          auto &domain_id = names.at(1);

          // get account permissions
          IROHA_CHECK_ERROR(permissions, getAccountPermissions(domain_id, account_name));
          creator_permissions = std::move(permissions);
        }

        return (*this)(command,
                       creator_account_id,
                       tx_hash,
                       cmd_index,
                       do_validation,
                       creator_permissions);
      },
      cmd.get());
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddAssetQuantity &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {

  RocksDbCommon common(db_context_);
  rocksdb::Status status;

  //TODO(iceseer): fix the case there will be no delimiter
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.assetId());
  auto &asset_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &amount = command.amount();

  shared_model::interface::Amount result("");

  if (do_validation) {
    IROHA_ERROR_IF_ANY_NOT_SET(Role::kAddAssetQty, Role::kAddDomainAssetQty)
  }

  // check if asset exists
  status = common.get(fmtstrings::kAsset, domain_id, asset_name);
  IROHA_ERROR_IF_NOT_FOUND(3)

  uint64_t precision;
  common.decode(precision);
  result = shared_model::interface::Amount(precision);

  uint64_t account_asset_size = 0;
  status = common.get(
      fmtstrings::kAccountAssetSize, creator_domain_id, creator_account_name);
  if (status.ok()) {
    common.decode(account_asset_size);
  } else if (not status.IsNotFound()) {
    IROHA_ERROR_IF_NOT_OK()
  }

  status = common.get(fmtstrings::kAccountAsset,
                      creator_domain_id,
                      creator_account_name,
                      command.assetId());

  if (status.ok()) {
    result = shared_model::interface::Amount(db_context_->value_buffer);
  } else if (status.IsNotFound()) {
    ++account_asset_size;
  } else {
    IROHA_ERROR_IF_NOT_OK()
  }

  result += amount;
  db_context_->value_buffer.assign(result.toStringRepr());
  IROHA_ERROR_IF_CONDITION(db_context_->value_buffer[0] == 'N', 4, command.toString(), "")

  status = common.put(fmtstrings::kAccountAsset,
                      creator_domain_id,
                      creator_account_name,
                      command.assetId());
  IROHA_ERROR_IF_NOT_OK()

  common.encode(account_asset_size);
  status = common.put(
      fmtstrings::kAccountAssetSize, creator_domain_id, creator_account_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddPeer &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddSignatory &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AppendRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &role_name = command.roleName();

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SET(Role::kAppendRole)
  }

  rocksdb::Status status;
  auto status = common.get(fmtstrings::kPermissions, domain_id, account_name);
  IROHA_ERROR_IF_NOT_FOUND(3)
  RolePermissionSet account_permissions{value_buffer_};

  status = common.get(fmtstrings::kRole, role_name);
  IROHA_ERROR_IF_NOT_FOUND(4)
  RolePermissionSet role_permissions{value_buffer_};

  if (do_validation) {
    // check if account already has role
    status = common.get(
        fmtstrings::kAccountRole, domain_id, account_name, role_name);
    IROHA_ERROR_IF_FOUND(1)

    IROHA_ERROR_IF_NOT_SUBSET()
  }

  account_permissions |= role_permissions;
  value_buffer_.assign(account_permissions.toBitstring());
  status = common.put(fmtstrings::kPermissions, domain_id, account_name);
  IROHA_ERROR_IF_NOT_OK()

  status =
      common.put(fmtstrings::kAccountRole, domain_id, account_name, role_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CallEngine &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CompareAndSetAccountDetail &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateAccount &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto &account_name = command.accountName();
  auto &domain_id = command.domainId();
  auto pubkey = command.pubkey();
  boost::algorithm::to_lower(pubkey);

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SET(Role::kCreateAccount)
  }

  // check if domain exists
  auto status = common.get(fmtstrings::kDomain, domain_id);
  IROHA_ERROR_IF_NOT_FOUND(3)

  auto default_role = value_buffer_;

  status = common.get(fmtstrings::kRole, value_buffer_);
  IROHA_ERROR_IF_NOT_OK()
  RolePermissionSet role_permissions{value_buffer_};

  status = common.put(
      fmtstrings::kAccountRole, domain_id, account_name, default_role);
  IROHA_ERROR_IF_NOT_OK()

  status = common.put(fmtstrings::kPermissions, domain_id, account_name);
  IROHA_ERROR_IF_NOT_OK()

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SUBSET()

    // check if account already exists
    status = common.get(fmtstrings::kQuorum, domain_id, account_name);
    IROHA_ERROR_IF_FOUND(4)
  }

  value_buffer_.clear();
  status = common.put(fmtstrings::kSignatory, domain_id, account_name, pubkey);
  IROHA_ERROR_IF_NOT_OK()

  common.encode(1);
  status = common.put(fmtstrings::kQuorum, domain_id, account_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateAsset &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto &domain_id = command.domainId();
  auto &asset_name = command.assetName();

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SET(Role::kCreateAsset)

    // check if asset already exists
    auto status = common.get(fmtstrings::kAsset, domain_id, asset_name);
    IROHA_ERROR_IF_FOUND(3)

    // check if domain exists
    status = common.get(fmtstrings::kDomain, domain_id);
    IROHA_ERROR_IF_NOT_FOUND(4)
  }

  common.encode(command.precision());
  auto status = common.put(fmtstrings::kAsset, domain_id, asset_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateDomain &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto &domain_id = command.domainId();
  auto &default_role = command.userDefaultRole();

  if (do_validation) {
    // no privilege escalation check here
    IROHA_ERROR_IF_NOT_SET(Role::kCreateDomain)

    // check if domain already exists
    auto status = common.get(fmtstrings::kDomain, domain_id);
    IROHA_ERROR_IF_FOUND(3)

    // check if role exists
    status = common.get(fmtstrings::kRole, default_role);
    IROHA_ERROR_IF_NOT_FOUND(4)
  }

  value_buffer_.assign(default_role);
  auto status = common.put(fmtstrings::kDomain, domain_id);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto &role_name = command.roleName();
  auto role_permissions = command.rolePermissions();
  if (role_permissions.isSet(Role::kRoot)) {
    role_permissions.setAll();
  }

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SET(Role::kCreateRole)
    IROHA_ERROR_IF_NOT_SUBSET()

    // check if role already exists
    auto status = common.get(fmtstrings::kRole, role_name);
    IROHA_ERROR_IF_FOUND(3)
  }

  value_buffer_.assign(role_permissions.toBitstring());
  auto status = common.put(fmtstrings::kRole, role_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::DetachRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &role_name = command.roleName();

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SET(Role::kDetachRole)
  }

  auto status = common.get(fmtstrings::kPermissions, domain_id, account_name);
  IROHA_ERROR_IF_NOT_FOUND(3)

  status = common.get(fmtstrings::kRole, role_name);
  IROHA_ERROR_IF_NOT_FOUND(5)

  if (do_validation) {
    // check if account has role
    status = common.get(
        fmtstrings::kAccountRole, domain_id, account_name, role_name);
    IROHA_ERROR_IF_NOT_FOUND(4)
  }

  status =
      common.del(fmtstrings::kAccountRole, domain_id, account_name, role_name);
  IROHA_ERROR_IF_NOT_OK()

  RolePermissionSet account_permissions;
  auto it = common.seek(fmtstrings::kAccountRole, domain_id, account_name, "");
  status = it->status();
  IROHA_ERROR_IF_NOT_OK()
  rocksdb::Slice key_buffer_slice(key_buffer_.data(), key_buffer_.size());
  for (; it->Valid() and it->key().starts_with(key_buffer_slice); it->Next()) {
    auto value = it->value();
    account_permissions |=
        RolePermissionSet{std::string_view{value.data(), value.size()}};
  }
  status = it->status();
  IROHA_ERROR_IF_NOT_OK()

  value_buffer_.assign(account_permissions.toBitstring());
  status = common.put(fmtstrings::kPermissions, domain_id, account_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::GrantPermission &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto grantee_names = splitId(creator_account_id);
  auto &grantee_account_name = grantee_names.at(0);
  auto &grantee_domain_id = grantee_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  auto granted_perm = command.permissionName();
  auto required_perm =
      shared_model::interface::permissions::permissionFor(granted_perm);

  if (do_validation) {
    IROHA_ERROR_IF_NOT_SET(required_perm)

    // check if account exists
    auto status = common.get(fmtstrings::kQuorum, domain_id, account_name);
    IROHA_ERROR_IF_NOT_FOUND(3)
  }

  GrantablePermissionSet granted_account_permissions;

  auto status = common.get(fmtstrings::kGranted,
                           domain_id,
                           account_name,
                           grantee_domain_id,
                           grantee_account_name);
  if (status.ok()) {
    granted_account_permissions = GrantablePermissionSet{value_buffer_};
  } else if (not status.IsNotFound()) {
    IROHA_ERROR_IF_NOT_OK()
  }

  // check if already granted
  IROHA_ERROR_IF_CONDITION(granted_account_permissions.isSet(granted_perm),
                           1,
                           command.toString(),
                           "");

  granted_account_permissions.set(granted_perm);

  value_buffer_.assign(granted_account_permissions.toBitstring());
  status = common.put(fmtstrings::kGranted,
                      domain_id,
                      account_name,
                      grantee_domain_id,
                      grantee_account_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RemovePeer &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RemoveSignatory &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RevokePermission &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetAccountDetail &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);

  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  if (do_validation) {
    if (command.accountId() != creator_account_id) {
      GrantablePermissionSet granted_account_permissions;

      auto status = common.get(fmtstrings::kGranted,
                               creator_domain_id,
                               creator_account_name,
                               domain_id,
                               account_name);
      if (status.ok()) {
        granted_account_permissions = GrantablePermissionSet{value_buffer_};
      } else if (not status.IsNotFound()) {
        IROHA_ERROR_IF_NOT_OK()
      }

      IROHA_ERROR_IF_NOT_ROLE_OR_GRANTABLE_SET(Role::kSetDetail,
                                               Grantable::kSetMyAccountDetail)
    }

    // check if account exists
    auto status = common.get(fmtstrings::kQuorum, domain_id, account_name);
    IROHA_ERROR_IF_NOT_FOUND(3)
  }

  value_buffer_.assign(command.value());
  auto status = common.put(fmtstrings::kAccountDetail,
                           domain_id,
                           account_name,
                           creator_domain_id,
                           creator_account_name,
                           command.key());
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetQuorum &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SubtractAssetQuantity &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions){
    IROHA_ERROR_NOT_IMPLEMENTED()}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::TransferAsset &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);
  rocksdb::Status status;
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto source_names = splitId(command.srcAccountId());
  auto &source_account_name = source_names.at(0);
  auto &source_domain_id = source_names.at(1);

  auto destination_names = splitId(command.destAccountId());
  auto &destination_account_name = destination_names.at(0);
  auto &destination_domain_id = destination_names.at(1);

  auto names = splitId(command.assetId());
  auto &asset_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &amount = command.amount();
  auto &description = command.description();

  if (do_validation) {
    // check if destination account exists
    status = common.get(
        fmtstrings::kQuorum, destination_domain_id, destination_account_name);
    IROHA_ERROR_IF_NOT_FOUND(4)

    // get account permissions
    auto status = common.get(fmtstrings::kPermissions,
                             destination_domain_id,
                             destination_account_name);
    IROHA_ERROR_IF_NOT_OK()
    auto destination_permissions = RolePermissionSet{value_buffer_};
    IROHA_ERROR_IF_CONDITION(not destination_permissions.isSet(Role::kReceive),
                             2,
                             command.toString(),
                             "")

    if (command.srcAccountId() != creator_account_id) {
      // check if source account exists
      status = common.get(
          fmtstrings::kQuorum, source_domain_id, source_account_name);
      IROHA_ERROR_IF_NOT_FOUND(3)

      GrantablePermissionSet granted_account_permissions;
      auto status = common.get(fmtstrings::kGranted,
                               creator_domain_id,
                               creator_account_name,
                               source_domain_id,
                               source_account_name);
      if (status.ok()) {
        granted_account_permissions = GrantablePermissionSet{value_buffer_};
      } else if (not status.IsNotFound()) {
        IROHA_ERROR_IF_NOT_OK()
      }
      IROHA_ERROR_IF_NOT_GRANTABLE_SET(Grantable::kTransferMyAssets)
    } else {
      IROHA_ERROR_IF_NOT_SET(Role::kTransfer)
    }

    // check if asset exists
    status = common.get(fmtstrings::kAsset, domain_id, asset_name);
    IROHA_ERROR_IF_NOT_FOUND(5)

    status = common.get(fmtstrings::kSetting,
                        iroha::ametsuchi::kMaxDescriptionSizeKey);
    if (status.ok()) {
      uint64_t max_description_size;
      common.decode(max_description_size);
      IROHA_ERROR_IF_CONDITION(
          description.size() > max_description_size, 8, command.toString(), "")
    } else if (not status.IsNotFound()) {
      IROHA_ERROR_IF_NOT_OK()
    }
  }

  status = common.get(fmtstrings::kAccountAsset,
                      source_domain_id,
                      source_account_name,
                      command.assetId());
  IROHA_ERROR_IF_NOT_FOUND(6)
  shared_model::interface::Amount source_balance(value_buffer_);

  source_balance -= amount;
  IROHA_ERROR_IF_CONDITION(
      source_balance.toStringRepr()[0] == 'N', 6, command.toString(), "")

  uint64_t account_asset_size = 0;
  status = common.get(fmtstrings::kAccountAssetSize,
                      destination_domain_id,
                      destination_account_name);
  if (status.ok()) {
    common.decode(account_asset_size);
  } else if (not status.IsNotFound()) {
    IROHA_ERROR_IF_NOT_OK()
  }

  shared_model::interface::Amount destination_balance(
      source_balance.precision());
  status = common.get(fmtstrings::kAccountAsset,
                      destination_domain_id,
                      destination_account_name,
                      command.assetId());
  if (status.ok()) {
    destination_balance = shared_model::interface::Amount(value_buffer_);
  } else if (status.IsNotFound()) {
    ++account_asset_size;
  } else {
    IROHA_ERROR_IF_NOT_OK()
  }

  destination_balance += amount;
  IROHA_ERROR_IF_CONDITION(
      destination_balance.toStringRepr()[0] == 'N', 7, command.toString(), "")

  value_buffer_.assign(source_balance.toStringRepr());
  status = common.put(fmtstrings::kAccountAsset,
                      source_domain_id,
                      source_account_name,
                      command.assetId());
  IROHA_ERROR_IF_NOT_OK()

  value_buffer_.assign(destination_balance.toStringRepr());
  status = common.put(fmtstrings::kAccountAsset,
                      destination_domain_id,
                      destination_account_name,
                      command.assetId());
  IROHA_ERROR_IF_NOT_OK()

  common.encode(account_asset_size);
  status = common.put(fmtstrings::kAccountAssetSize,
                      destination_domain_id,
                      destination_account_name);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetSettingValue &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &,
    shared_model::interface::types::CommandIndexType,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_transaction_, key_buffer_, value_buffer_);
  rocksdb::Status status;

  auto &key = command.key();
  auto &value = command.value();

  value_buffer_.assign(value);
  status = common.put(fmtstrings::kSetting, key);
  IROHA_ERROR_IF_NOT_OK()

  return {};
}
