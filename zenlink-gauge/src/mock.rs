use super::*;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use frame_support::{parameter_types, traits::Contains, PalletId};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	RuntimeDebug,
};
use sp_runtime::BuildStorage;

use orml_traits::parameter_type_with_key;

use crate as gauge;

type Block = frame_system::mocking::MockBlock<Test>;

pub type Moment = u64;
pub const MILLISECS_PER_BLOCK: Moment = 12000;
pub const SLOT_DURATION: Moment = MILLISECS_PER_BLOCK;

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;

	pub const BlockHashCount: u64 = 250;
	pub const GaugePalletId: PalletId = PalletId(*b"/zlkgaug");
	pub const MaxReserves: u32 = 50;
	pub const MaxLocks:u32 = 50;
	pub const MinimumPeriod: Moment = SLOT_DURATION / 2;
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
    type MaxHolds = ();
    type MaxFreezes = ();
}

impl pallet_timestamp::Config for Test {
	type MinimumPeriod = MinimumPeriod;
	type Moment = u64;
	type OnTimestampSet = ();
	type WeightInfo = ();
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type CurrencyId = CurrencyId;
	type MultiCurrency = Tokens;
	type PoolId = u32;
	type TimeProvider = TimestampPallet;
	type PalletId = GaugePalletId;
}

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system = 0,
		TimestampPallet: pallet_timestamp = 1,

		Balances: pallet_balances = 8,
		Tokens: orml_tokens = 11,
		Gauge: gauge
	}
);

pub type GaugePallet = Pallet<Test>;

pub const ALICE: u128 = 1;
pub const BOB: u128 = 2;

pub const TOKEN1_SYMBOL: u8 = 1;
pub const TOKEN1_UNIT: u128 = 1_000_000_000_000_000_000;

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap().into();
	pallet_balances::GenesisConfig::<Test> { balances: vec![(ALICE, u128::MAX)] }
		.assimilate_storage(&mut t)
		.unwrap();

	orml_tokens::GenesisConfig::<Test> {
		balances: vec![
			(ALICE, CurrencyId::Token(TOKEN1_SYMBOL), TOKEN1_UNIT * 50),
			(BOB, CurrencyId::Token(TOKEN1_SYMBOL), TOKEN1_UNIT * 30),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	t.into()
}

pub fn get_user_balance(currency_id: CurrencyId, user: &AccountId) -> Balance {
	<Test as Config>::MultiCurrency::free_balance(currency_id, user)
}

pub fn mine_block() {
	let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

	System::set_block_number(System::block_number() + 1);
	set_block_timestamp(now);
}

// timestamp in second
pub fn set_block_timestamp(timestamp: u64) {
	TimestampPallet::set_timestamp(timestamp * 1000);
}
