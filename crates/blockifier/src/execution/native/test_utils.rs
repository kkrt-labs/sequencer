use std::collections::HashMap;
use std::sync::Arc;

use cairo_native::starknet::SyscallResult;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{class_hash, contract_address, felt, patricia_key};
use starknet_types_core::felt::Felt;

use crate::abi::abi_utils::selector_from_name;
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::{CallInfo, OrderedEvent};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::{
    CallEntryPoint,
    ConstructorContext,
    EntryPointExecutionContext,
};
use crate::execution::execution_utils::execute_deployment;
use crate::execution::native::utils::{
    contract_address_to_native_felt,
    decode_felts_as_str,
    encode_str_as_felts,
};
use crate::execution::syscalls::hint_processor::FAILED_TO_CALCULATE_CONTRACT_ADDRESS;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::cached_state::get_erc20_class_hash_mapping;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::{
    erc20_external_entry_point,
    TEST_ERC20_FULL_CONTRACT_ADDRESS,
    TEST_ERC20_FULL_CONTRACT_CLASS_HASH,
};
use crate::transaction::objects::TransactionInfo;

pub fn create_erc20_deploy_test_state() -> CachedState<DictStateReader> {
    let address_to_class_hash: HashMap<ContractAddress, ClassHash> = HashMap::from([(
        contract_address!(TEST_ERC20_FULL_CONTRACT_ADDRESS),
        class_hash!(TEST_ERC20_FULL_CONTRACT_CLASS_HASH),
    )]);

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class: get_erc20_class_hash_mapping(),
        ..Default::default()
    })
}

pub fn deploy_contract(
    state: &mut dyn State,
    class_hash: Felt,
    contract_address_salt: Felt,
    calldata: &[Felt],
) -> SyscallResult<(Felt, Vec<Felt>)> {
    let deployer_address = ContractAddress::default();

    let class_hash = ClassHash(class_hash);

    let wrapper_calldata = Calldata(Arc::new(calldata.to_vec()));

    let calculated_contract_address = calculate_contract_address(
        ContractAddressSalt(contract_address_salt),
        class_hash,
        &wrapper_calldata,
        deployer_address,
    )
    .map_err(|_| vec![Felt::from_hex(FAILED_TO_CALCULATE_CONTRACT_ADDRESS).unwrap()])?;

    let ctor_context = ConstructorContext {
        class_hash,
        code_address: Some(calculated_contract_address),
        storage_address: calculated_contract_address,
        caller_address: deployer_address,
    };

    let call_info = execute_deployment(
        state,
        &mut Default::default(),
        &mut EntryPointExecutionContext::new(
            Arc::new(TransactionContext {
                block_context: BlockContext::create_for_testing(),
                tx_info: TransactionInfo::Current(Default::default()),
            }),
            ExecutionMode::Execute,
            false,
        )
        .unwrap(),
        ctor_context,
        wrapper_calldata,
        u64::MAX,
    )
    .map_err(|err| encode_str_as_felts(&err.to_string()))?;

    let return_data = call_info.execution.retdata.0;
    let contract_address_felt = *calculated_contract_address.0.key();

    Ok((contract_address_felt, return_data))
}

pub fn prepare_erc20_deploy_test_state() -> (ContractAddress, CachedState<DictStateReader>) {
    let mut state = create_erc20_deploy_test_state();

    let class_hash = Felt::from_hex(TEST_ERC20_FULL_CONTRACT_CLASS_HASH).unwrap();

    let (contract_address, _) = deploy_contract(
        &mut state,
        class_hash,
        Felt::from(0),
        &[
            contract_address_to_native_felt(Signers::Alice.into()), // Recipient
            contract_address_to_native_felt(Signers::Alice.into()), // Owner
        ],
    )
    .unwrap_or_else(|e| panic!("Failed to deploy contract: {:?}", decode_felts_as_str(&e)));

    let contract_address = ContractAddress(PatriciaKey::try_from(contract_address).unwrap());

    (contract_address, state)
}

#[derive(Debug, Clone, Copy)]
pub enum Signers {
    Alice,
    Bob,
    Charlie,
}

impl Signers {
    pub fn get_address(&self) -> ContractAddress {
        match self {
            Signers::Alice => ContractAddress(patricia_key!(0x001u128)),
            Signers::Bob => ContractAddress(patricia_key!(0x002u128)),
            Signers::Charlie => ContractAddress(patricia_key!(0x003u128)),
        }
    }
}

impl From<Signers> for ContractAddress {
    fn from(val: Signers) -> ContractAddress {
        val.get_address()
    }
}

impl From<Signers> for Felt {
    fn from(val: Signers) -> Felt {
        contract_address_to_native_felt(val.get_address())
    }
}

#[derive(Debug, Clone)]
pub struct TestEvent {
    pub data: Vec<Felt>,
    pub keys: Vec<Felt>,
}

impl From<OrderedEvent> for TestEvent {
    fn from(value: OrderedEvent) -> Self {
        let event_data = value.event.data.0;
        let event_keys = value.event.keys.iter().map(|e| e.0).collect();
        Self { data: event_data, keys: event_keys }
    }
}

pub struct TestContext {
    pub contract_address: ContractAddress,
    pub state: CachedState<DictStateReader>,
    pub caller_address: ContractAddress,
    pub events: Vec<TestEvent>,
}

impl Default for TestContext {
    fn default() -> Self {
        let (contract_address, state) = prepare_erc20_deploy_test_state();
        Self { contract_address, state, caller_address: contract_address, events: vec![] }
    }
}

impl TestContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_caller(mut self, caller_address: ContractAddress) -> Self {
        self.caller_address = caller_address;
        self
    }

    pub fn call_entry_point(&mut self, entry_point_name: &str, calldata: Vec<Felt>) -> Vec<Felt> {
        let result = self.call_entry_point_raw(entry_point_name, calldata).unwrap();
        result.execution.retdata.0.to_vec()
    }

    pub fn call_entry_point_raw(
        &mut self,
        entry_point_name: &str,
        calldata: Vec<Felt>,
    ) -> Result<CallInfo, String> {
        let entry_point_selector = selector_from_name(entry_point_name);
        let calldata = Calldata(Arc::new(calldata));

        let entry_point_call = CallEntryPoint {
            calldata,
            entry_point_selector,
            code_address: Some(self.contract_address),
            storage_address: self.contract_address,
            caller_address: self.caller_address,
            ..erc20_external_entry_point()
        };

        let result =
            entry_point_call.execute_directly(&mut self.state).map_err(|e| e.to_string())?;

        let events = result.execution.events.clone();

        self.events.extend(events.iter().map(|e| e.clone().into()));

        Ok(result)
    }

    pub fn get_event(&self, index: usize) -> Option<TestEvent> {
        self.events.get(index).cloned()
    }

    pub fn get_caller(&self) -> ContractAddress {
        self.caller_address
    }
}
