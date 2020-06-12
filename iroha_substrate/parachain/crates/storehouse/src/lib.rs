#![deny(warnings)]
#![cfg_attr(test, feature(proc_macro_hygiene))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use frame_support::traits::{Currency, ReservableCurrency};
use frame_support::{decl_event, decl_module, decl_storage, ensure, sp_runtime::ModuleId};
use errors::Error;

type BalanceOf<T> = <<T as Trait>::DOT as Currency<<T as system::Trait>::AccountId>>::Balance;
const _MODULE_ID: ModuleId = ModuleId(*b"srm/strh");

pub trait Trait: system::Trait {
    type DOT: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as Storehouse {
        TotalCollateral: BalanceOf<T>;
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
        Balance = BalanceOf<T>,
    {
        ValueAlloced(AccountId, Balance),
        ValueReleased(AccountId, Balance),
        ValueMoved(AccountId, AccountId, Balance),
    }
);

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;
    }
}

impl<T: Trait> Module<T> {
    pub fn get_dot_balance() -> BalanceOf<T> {
        T::DOT::total_issuance()
    }

    pub fn get_total_value() -> BalanceOf<T> {
        <TotalCollateral<T>>::get()
    }

    pub fn inc_total_value(amount: BalanceOf<T>) {
        let val = Self::get_total_value() + amount;
        <TotalCollateral<T>>::put(val);
    }

    pub fn dec_total_value(amount: BalanceOf<T>) {
        let val = Self::get_total_value() - amount;
        <TotalCollateral<T>>::put(val);
    }

    pub fn get_value_from_account(account: &T::AccountId) -> BalanceOf<T> {
        T::DOT::reserved_balance(account)
    }

    pub fn allock_value(sender: &T::AccountId, amount: BalanceOf<T>) -> Result<(), Error> {
        T::DOT::reserve(sender, amount).map_err(|_| Error::NotEnoughTokens)?;
        Self::inc_total_value(amount);
        Self::deposit_event(RawEvent::ValueAlloced(sender.clone(), amount));
        Ok(())
    }

    pub fn release_value(sender: &T::AccountId, amount: BalanceOf<T>) -> Result<(), Error> {
        ensure!(
            T::DOT::reserved_balance(&sender) >= amount,
            Error::NotEnoughReservedTokens
        );
        T::DOT::unreserve(sender, amount);
        Self::dec_total_value(amount);
        Self::deposit_event(RawEvent::ValueReleased(sender.clone(), amount));
        Ok(())
    }

    pub fn move_value(sender: T::AccountId, receiver: T::AccountId, amount: BalanceOf<T>) -> Result<(), Error> {
        ensure!(
            T::DOT::reserved_balance(&sender) >= amount,
            Error::NotEnoughReservedTokens
        );
        let (slashed, _remainder) = T::DOT::slash_reserved(&sender, amount);
        T::DOT::resolve_creating(&receiver, slashed);
        T::DOT::reserve(&receiver, amount).map_err(|_| Error::NotEnoughTokens)?;
        Self::deposit_event(RawEvent::ValueMoved(sender, receiver, amount));
        Ok(())
    }
}
