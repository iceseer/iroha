use crate::mock::*;
//use crate::RawEvent;
use frame_support::{assert_err, assert_ok};

/// Total supply
#[test]
fn test_total_supply_correct() {
    run_test(|| {
        // initial supply
        let desired_total = ALICE_BALANCE + BOB_BALANCE;
        let total = Storehouse::get_dot_balance();

        assert_eq!(desired_total, total);
    })
}

/// Total value
#[test]
fn test_total_value_correct() {
    run_test(|| {
        // initial supply
        let desired_total_value = 0;
        let increase_amount: Balance = 5;
        let decrease_amount: Balance = 3;

        let total_value = Storehouse::get_total_value();
        assert_eq!(desired_total_value, total_value);

        Storehouse::inc_total_value(increase_amount);
        let increased_value = Storehouse::get_total_value();
        assert_eq!(total_value + increase_amount, increased_value);

        Storehouse::dec_total_value(decrease_amount);
        let decreased_value = Storehouse::get_total_value();
        assert_eq!(increased_value - decrease_amount, decreased_value);
    })
}

/// Lock value
#[test]
fn test_lock_value_succeeds() {
    run_test(|| {
        let sender = ALICE;
        let amount: Balance = 5;

        let init_value = Storehouse::get_value_from_account(&ALICE);
        let init_total = Storehouse::get_total_value();

        assert_ok!(Storehouse::allock_value(&sender, amount));
        //let lock_event = TestEvent::test_events(RawEvent::ValueAlloced(ALICE, amount));

        //assert!(System::events().iter().any(|a| a.event == lock_event));

        let value = Storehouse::get_value_from_account(&ALICE);
        let total = Storehouse::get_total_value();

        assert_eq!(value, init_value + amount);
        assert_eq!(total, init_total + amount);
    })
}

#[test]
fn test_lock_value_fails() {
    run_test(|| {
        let sender = ALICE;
        let amount = ALICE_BALANCE + 5;

        let init_value = Storehouse::get_value_from_account(&ALICE);
        let init_total = Storehouse::get_total_value();

        assert_err!(
            Storehouse::allock_value(&sender, amount),
            Error::NotEnoughTokens
        );

        let value = Storehouse::get_value_from_account(&ALICE);
        let total = Storehouse::get_total_value();

        assert_eq!(value, init_value);
        assert_eq!(total, init_total);
    })
}

/// Release value
#[test]
fn test_release_value_succeeds() {
    run_test(|| {
        let sender = ALICE;
        let amount = ALICE_BALANCE;

        assert_ok!(Storehouse::allock_value(&sender, amount));

        let init_value = Storehouse::get_value_from_account(&ALICE);
        let init_total = Storehouse::get_total_value();

        assert_ok!(Storehouse::release_value(&sender, amount));
    //    let release_event = TestEvent::test_events(RawEvent::ValueReleased(ALICE, amount));

      //  assert!(System::events().iter().any(|a| a.event == release_event));

        let value = Storehouse::get_value_from_account(&ALICE);
        let total = Storehouse::get_total_value();

        assert_eq!(value, init_value - amount);
        assert_eq!(total, init_total - amount);
    })
}

#[test]
fn test_release_value_fails() {
    run_test(|| {
        let sender = ALICE;
        let lock_amount = ALICE_BALANCE;

        let init_value = Storehouse::get_value_from_account(&ALICE);
        let init_total = Storehouse::get_total_value();

        assert_err!(
            Storehouse::release_value(&sender, lock_amount),
            Error::NotEnoughReservedTokens
        );

        let value = Storehouse::get_value_from_account(&ALICE);
        let total = Storehouse::get_total_value();

        assert_eq!(value, init_value);
        assert_eq!(total, init_total);
    })
}

#[test]
fn test_release_value_partially_succeeds() {
    run_test(|| {
        let sender = ALICE;
        let amount = ALICE_BALANCE;
        let release_amount = ALICE_BALANCE - 10;

        assert_ok!(Storehouse::allock_value(&sender, amount));

        let init_value = Storehouse::get_value_from_account(&ALICE);
        let init_total = Storehouse::get_total_value();

        assert_ok!(Storehouse::release_value(&sender, release_amount));
//        let release_event =
//            TestEvent::test_events(RawEvent::ValueReleased(ALICE, release_amount));
//
//        assert!(System::events().iter().any(|a| a.event == release_event));

        let value = Storehouse::get_value_from_account(&ALICE);
        let total = Storehouse::get_total_value();

        assert_eq!(value, init_value - release_amount);
        assert_eq!(total, init_total - release_amount);
    })
}

/// Slash value
#[test]
fn test_move_value_succeeds() {
    run_test(|| {
        let sender = ALICE;
        let receiver = BOB;
        let amount = ALICE_BALANCE;

        assert_ok!(Storehouse::allock_value(&sender, amount));

        let init_value_alice = Storehouse::get_value_from_account(&ALICE);
        let init_value_bob = Storehouse::get_value_from_account(&BOB);
        let init_total = Storehouse::get_total_value();

        assert_ok!(Storehouse::move_value(sender, receiver, amount));
//        let slash_event = TestEvent::test_events(RawEvent::SlashCollateral(ALICE, BOB, amount));
//
//        assert!(System::events().iter().any(|a| a.event == slash_event));

        let collateral_alice = Storehouse::get_value_from_account(&ALICE);
        let collateral_bob = Storehouse::get_value_from_account(&BOB);
        let total = Storehouse::get_total_value();

        assert_eq!(collateral_alice, init_value_alice - amount);
        assert_eq!(collateral_bob, init_value_bob + amount);
        assert_eq!(total, init_total);
    })
}

#[test]
fn test_move_value_fails() {
    run_test(|| {
        let sender = ALICE;
        let receiver = BOB;
        let amount = ALICE_BALANCE;

        let init_value_alice = Storehouse::get_value_from_account(&ALICE);
        let init_value_bob = Storehouse::get_value_from_account(&BOB);
        let init_total = Storehouse::get_total_value();

        assert_err!(
            Storehouse::move_value(sender, receiver, amount),
            Error::NotEnoughReservedTokens
        );

        let collateral_alice = Storehouse::get_value_from_account(&ALICE);
        let collateral_bob = Storehouse::get_value_from_account(&BOB);
        let total = Storehouse::get_total_value();

        assert_eq!(collateral_alice, init_value_alice);
        assert_eq!(collateral_bob, init_value_bob);
        assert_eq!(total, init_total);
    })
}

#[test]
fn test_move_value_partially_succeeds() {
    run_test(|| {
        let sender = ALICE;
        let receiver = BOB;
        let amount = ALICE_BALANCE;
        let slash_amount = ALICE_BALANCE;

        assert_ok!(Storehouse::allock_value(&sender, amount));

        let init_value_alice = Storehouse::get_value_from_account(&ALICE);
        let init_value_bob = Storehouse::get_value_from_account(&BOB);
        let init_total = Storehouse::get_total_value();

        assert_ok!(Storehouse::move_value(sender, receiver, slash_amount));
//        let slash_event =
//            TestEvent::test_events(RawEvent::SlashCollateral(ALICE, BOB, slash_amount));
//
//        assert!(System::events().iter().any(|a| a.event == slash_event));

        let collateral_alice = Storehouse::get_value_from_account(&ALICE);
        let collateral_bob = Storehouse::get_value_from_account(&BOB);
        let total = Storehouse::get_total_value();

        assert_eq!(collateral_alice, init_value_alice - slash_amount);
        assert_eq!(collateral_bob, init_value_bob + slash_amount);
        assert_eq!(total, init_total);
    })
}