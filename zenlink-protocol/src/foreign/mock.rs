// Copyright 2021-2022 Zenlink.
// Licensed under Apache 2.0.

//! Test utilities
use frame_support::{parameter_types, PalletId};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
};
use sp_runtime::BuildStorage;

use crate as pallet_zenlink;
pub use crate::{
	AssetId, Config, MultiAssetsHandler, PairLpGenerate, Pallet, ParaId, ZenlinkMultiAssets,
	LIQUIDITY, LOCAL, NATIVE, RESERVED,
};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system = 0,
		Balances: pallet_balances = 8,
		Zenlink: pallet_zenlink = 9,
	}
);

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;

	pub const BlockHashCount: u64 = 250;
	pub const ZenlinkPalletId: PalletId = PalletId(*b"/zenlink");
	pub const MaxReserves: u32 = 50;
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

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MultiAssetsHandler = ZenlinkMultiAssets<Zenlink, Balances>;
	type PalletId = ZenlinkPalletId;
	type AssetId = AssetId;
	type LpGenerate = PairLpGenerate<Self>;
	type TargetChains = ();
	type SelfParaId = ();
	type WeightInfo = ();
	type ControlOrigin = frame_system::EnsureRoot<u128>;
}

pub type DexPallet = Pallet<Test>;

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap().into();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(1, 34028236692093846346337460743176821145),
			(2, 10),
			(3, 10),
			(4, 10),
			(5, 10),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();
	t.into()
}
