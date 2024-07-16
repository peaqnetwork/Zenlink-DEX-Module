// Copyright 2021-2022 Zenlink.
// Licensed under Apache 2.0.

use super::*;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_system::RawOrigin;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

use frame_support::{
	assert_ok, parameter_types, traits::Contains, PalletId,
};
use sp_runtime::BuildStorage;
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	RuntimeDebug,
};

use crate::mock::CurrencyId::VaultToken;
use orml_traits::parameter_type_with_key;

use crate as vault;
use crate::primitives::VaultAssetGenerate;

type Block = frame_system::mocking::MockBlock<Test>;

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;

	pub const BlockHashCount: u64 = 250;
	pub const VaultAssetPalletId: PalletId = PalletId(*b"/zlkvtat");
	pub const MaxReserves: u32 = 50;
	pub const MaxLocks:u32 = 50;
}

parameter_type_with_key! {
	pub ExistentialDeposits: |_currency_id: CurrencyId| -> u128 {
		0
	};
}

pub type AccountId = u128;
pub type TokenSymbol = u8;

pub struct MockDustRemovalWhitelist;
impl Contains<AccountId> for MockDustRemovalWhitelist {
	fn contains(_a: &AccountId) -> bool {
		true
	}
}

#[derive(
	Encode,
	Decode,
	Eq,
	PartialEq,
	Copy,
	Clone,
	RuntimeDebug,
	PartialOrd,
	MaxEncodedLen,
	Ord,
	TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CurrencyId {
	Token(TokenSymbol),
	VaultToken(TokenSymbol),
}

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Block = Block;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u128;
	type Lookup = IdentityLookup<Self::AccountId>;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type AccountData = pallet_balances::AccountData<u128>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type PalletInfo = PalletInfo;
	type BlockWeights = ();
	type BlockLength = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
	type RuntimeTask = ();
}

impl orml_tokens::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type Balance = Balance;
	type Amount = i128;
	type CurrencyId = CurrencyId;
	type WeightInfo = ();
	type ExistentialDeposits = ExistentialDeposits;
	type MaxLocks = ();
	type DustRemovalWhitelist = MockDustRemovalWhitelist;
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];
	type CurrencyHooks = ();
}

impl pallet_balances::Config for Test {
	type Balance = u128;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = frame_system::Pallet<Test>;
	type WeightInfo = ();
	type MaxLocks = ();
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];

    type RuntimeHoldReason = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
	type RuntimeFreezeReason = ();
}

pub struct VaultAssetGenerator;

impl VaultAssetGenerate<CurrencyId> for VaultAssetGenerator {
	fn generate(asset: CurrencyId) -> Option<CurrencyId> {
		match asset {
			CurrencyId::Token(sym) => Some(VaultToken(sym)),
			VaultToken(_) => None,
		}
	}
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type AssetId = CurrencyId;
	type MultiAsset = Tokens;
	type VaultAssetGenerate = VaultAssetGenerator;
	type PalletId = VaultAssetPalletId;
	type WeightInfo = ();
}

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system = 0,

		Balances: pallet_balances = 8,
		Tokens: orml_tokens = 11,
		Vaults: vault
	}
);

pub type VaultPallet = Pallet<Test>;

pub const ALICE: u128 = 1;
pub const BOB: u128 = 2;
pub const CHARLIE: u128 = 3;

pub const TOKEN1_SYMBOL: u8 = 1;
pub const TOKEN2_SYMBOL: u8 = 2;

pub const TOKEN1_DECIMAL: u8 = 18;
pub const TOKEN2_DECIMAL: u8 = 12;

pub const TOKEN1_UNIT: u128 = 1_000_000_000_000_000_000;
pub const TOKEN2_UNIT: u128 = 1_000_000_000_000;

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap().into();
	pallet_balances::GenesisConfig::<Test> { balances: vec![(ALICE, u128::MAX)] }
		.assimilate_storage(&mut t)
		.unwrap();

	orml_tokens::GenesisConfig::<Test> {
		balances: vec![
			(ALICE, CurrencyId::Token(TOKEN1_SYMBOL), TOKEN1_UNIT * 50),
			(ALICE, CurrencyId::Token(TOKEN2_SYMBOL), TOKEN2_UNIT * 50),
			(BOB, CurrencyId::Token(TOKEN1_SYMBOL), TOKEN1_UNIT * 30),
			(BOB, CurrencyId::Token(TOKEN2_SYMBOL), TOKEN2_UNIT * 30),
			(CHARLIE, CurrencyId::Token(TOKEN1_SYMBOL), TOKEN1_UNIT * 20),
			(CHARLIE, CurrencyId::Token(TOKEN2_SYMBOL), TOKEN2_UNIT * 20),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	t.into()
}

pub fn get_user_balance(currency_id: CurrencyId, user: &AccountId) -> Balance {
	<Test as Config>::MultiAsset::free_balance(currency_id, user)
}

pub fn transfer_from(currency_id: CurrencyId, from: &AccountId, amount: Balance, to: &AccountId) {
	assert_ok!(<Test as Config>::MultiAsset::transfer(
		RawOrigin::Signed(from.clone()).into(),
		to.clone(),
		currency_id,
		amount
	));
}

pub fn set_balance(currency_id: CurrencyId, amount: Balance, to: &AccountId) {
	assert_ok!(<Test as Config>::MultiAsset::set_balance(
		RawOrigin::Root.into(),
		to.clone(),
		currency_id,
		amount,
		0
	));
}
