use std::collections::{HashMap, HashSet};
use std::ops::{Deref, Index};
use std::sync::Arc;

use cairo_lang_casm;
use cairo_lang_casm::hints::Hint;
use cairo_lang_starknet_classes::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_lang_starknet_classes::NestedIntList;
use cairo_vm::serde::deserialize_program::{
    ApTracking,
    FlowTrackingData,
    HintParams,
    ReferenceManager,
};
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::Itertools;
use num_traits::Num;

use semver::Version;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_api::contract_class::{ContractClass, EntryPointType};
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass,
    EntryPointOffset,
    EntryPointV0,
    Program as DeprecatedProgram,
};
use starknet_api::transaction::fields::GasVectorComputationMode;
use starknet_types_core::felt::Felt;

use super::execution_utils::{sn_api_to_cairo_vm_program, cairo_vm_to_sn_api_program, poseidon_hash_many_cost};
use crate::abi::constants;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::PreExecutionError;

#[cfg(feature = "cairo_native")]
use crate::execution::native::contract_class::NativeCompiledClassV1;
use crate::transaction::errors::TransactionExecutionError;
use crate::versioned_constants::CompilerVersion;

#[cfg(test)]
#[path = "contract_class_test.rs"]
pub mod test;

pub trait HasSelector {
    fn selector(&self) -> &EntryPointSelector;
}

/// The resource used to run a contract function.
#[cfg_attr(feature = "transaction_serde", derive(serde::Deserialize))]
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Serialize)]
pub enum TrackedResource {
    #[default]
    CairoSteps, // AKA VM mode.
    SierraGas, // AKA Sierra mode.
}

/// Represents a runnable Starknet compiled class.
/// Meaning, the program is runnable by the VM (or natively).
#[derive(Clone, Debug, Eq, PartialEq, derive_more::From, Serialize, Deserialize)]
pub enum RunnableCompiledClass {
    V0(CompiledClassV0),
    V1(CompiledClassV1),
    #[cfg(feature = "cairo_native")]
    V1Native(NativeCompiledClassV1),
}

impl TryFrom<ContractClass> for RunnableCompiledClass {
    type Error = ProgramError;

    fn try_from(raw_contract_class: ContractClass) -> Result<Self, Self::Error> {
        let contract_class: Self = match raw_contract_class {
            ContractClass::V0(raw_contract_class) => Self::V0(raw_contract_class.try_into()?),
            ContractClass::V1(raw_contract_class) => Self::V1(raw_contract_class.try_into()?),
        };

        Ok(contract_class)
    }
}

impl RunnableCompiledClass {
    pub fn constructor_selector(&self) -> Option<EntryPointSelector> {
        match self {
            Self::V0(class) => class.constructor_selector(),
            Self::V1(class) => class.constructor_selector(),
            #[cfg(feature = "cairo_native")]
            Self::V1Native(class) => class.constructor_selector(),
        }
    }

    pub fn estimate_casm_hash_computation_resources(&self) -> ExecutionResources {
        match self {
            Self::V0(class) => class.estimate_casm_hash_computation_resources(),
            Self::V1(class) => class.estimate_casm_hash_computation_resources(),
            #[cfg(feature = "cairo_native")]
            Self::V1Native(_) => {
                todo!("Use casm to estimate casm hash computation resources")
            }
        }
    }

    pub fn get_visited_segments(
        &self,
        visited_pcs: &HashSet<usize>,
    ) -> Result<Vec<usize>, TransactionExecutionError> {
        match self {
            Self::V0(_) => {
                panic!("get_visited_segments is not supported for v0 contracts.")
            }
            Self::V1(class) => class.get_visited_segments(visited_pcs),
            #[cfg(feature = "cairo_native")]
            Self::V1Native(_) => {
                panic!("get_visited_segments is not supported for native contracts.")
            }
        }
    }

    pub fn bytecode_length(&self) -> usize {
        match self {
            Self::V0(class) => class.bytecode_length(),
            Self::V1(class) => class.bytecode_length(),
            #[cfg(feature = "cairo_native")]
            Self::V1Native(_) => {
                todo!("implement bytecode_length for native contracts.")
            }
        }
    }

    /// Returns whether this contract should run using Cairo steps or Sierra gas.
    pub fn tracked_resource(
        &self,
        min_sierra_version: &CompilerVersion,
        gas_mode: GasVectorComputationMode,
    ) -> TrackedResource {
        match gas_mode {
            GasVectorComputationMode::All => match self {
                Self::V0(_) => TrackedResource::CairoSteps,
                Self::V1(contract_class) => contract_class.tracked_resource(min_sierra_version),
                #[cfg(feature = "cairo_native")]
                Self::V1Native(contract_class) => {
                    contract_class.casm().tracked_resource(min_sierra_version)
                }
            },
            GasVectorComputationMode::NoL2Gas => TrackedResource::CairoSteps,
        }
    }
}

// V0.

/// Represents a runnable Cairo 0 Starknet contract class (meaning, the program is runnable by the
/// VM). We wrap the actual class in an Arc to avoid cloning the program when cloning the
/// class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct CompiledClassV0(pub Arc<CompiledClassV0Inner>);
impl Deref for CompiledClassV0 {
    type Target = CompiledClassV0Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CompiledClassV0 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    fn n_entry_points(&self) -> usize {
        self.entry_points_by_type.values().map(|vec| vec.len()).sum()
    }

    pub fn n_builtins(&self) -> usize {
        self.program.builtins_len()
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    fn estimate_casm_hash_computation_resources(&self) -> ExecutionResources {
        let hashed_data_size = (constants::CAIRO0_ENTRY_POINT_STRUCT_SIZE * self.n_entry_points())
            + self.n_builtins()
            + self.bytecode_length()
            + 1; // Hinted class hash.
        // The hashed data size is approximately the number of hashes (invoked in hash chains).
        let n_steps = constants::N_STEPS_PER_PEDERSEN * hashed_data_size;

        ExecutionResources {
            n_steps,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(BuiltinName::pedersen, hashed_data_size)]),
        }
    }

    pub fn tracked_resource(&self) -> TrackedResource {
        TrackedResource::CairoSteps
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<CompiledClassV0, ProgramError> {
        let contract_class: CompiledClassV0Inner = serde_json::from_str(raw_contract_class)?;
        Ok(CompiledClassV0(Arc::new(contract_class)))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct CompiledClassV0Inner {
    #[serde(deserialize_with = "deserialize_program", serialize_with = "serialize_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPointV0>>,
}

impl TryFrom<DeprecatedContractClass> for CompiledClassV0 {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(CompiledClassV0Inner {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })))
    }
}

// V1.

/// Represents a runnable Cario (Cairo 1) Starknet compiled class (meaning, the program is runnable
/// by the VM). We wrap the actual class in an Arc to avoid cloning the program when cloning the
/// class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledClassV1(pub Arc<CompiledClassV1Inner>);
impl Deref for CompiledClassV1 {
    type Target = CompiledClassV1Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for CompiledClassV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the CompiledClassV1 instance to CasmContractClass
        let casm_contract_class: CasmContractClass = self
            .try_into()
            .map_err(|err: ProgramError| serde::ser::Error::custom(err.to_string()))?;

        // Serialize the JSON string to bytes
        casm_contract_class.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CompiledClassV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into a JSON value
        let json_value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // Convert into a JSON string
        let json_string = serde_json::to_string(&json_value)
            .map_err(|err| DeserializationError::custom(err.to_string()))?;

        // Use try_from_json_string to deserialize into CompiledClassV1
        CompiledClassV1::try_from_json_string(&json_string)
            .map_err(|err| DeserializationError::custom(err.to_string()))
    }
}

impl CompiledClassV1 {
    pub fn constructor_selector(&self) -> Option<EntryPointSelector> {
        self.0.entry_points_by_type.constructor.first().map(|ep| ep.selector)
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    pub fn bytecode_segment_lengths(&self) -> &NestedIntList {
        &self.bytecode_segment_lengths
    }

    pub fn get_entry_point(
        &self,
        call: &CallEntryPoint,
    ) -> Result<EntryPointV1, PreExecutionError> {
        self.entry_points_by_type.get_entry_point(call)
    }

    /// Returns whether this contract should run using Cairo steps or Sierra gas.
    pub fn tracked_resource(&self, min_sierra_version: &CompilerVersion) -> TrackedResource {
        if *min_sierra_version <= self.compiler_version {
            TrackedResource::SierraGas
        } else {
            TrackedResource::CairoSteps
        }
    }

    /// Returns the estimated VM resources required for computing Casm hash.
    /// This is an empiric measurement of several bytecode lengths, which constitutes as the
    /// dominant factor in it.
    fn estimate_casm_hash_computation_resources(&self) -> ExecutionResources {
        estimate_casm_hash_computation_resources(&self.bytecode_segment_lengths)
    }

    // Returns the set of segments that were visited according to the given visited PCs.
    // Each visited segment must have its starting PC visited, and is represented by it.
    fn get_visited_segments(
        &self,
        visited_pcs: &HashSet<usize>,
    ) -> Result<Vec<usize>, TransactionExecutionError> {
        let mut reversed_visited_pcs: Vec<_> = visited_pcs.iter().cloned().sorted().rev().collect();
        get_visited_segments(&self.bytecode_segment_lengths, &mut reversed_visited_pcs, &mut 0)
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<CompiledClassV1, ProgramError> {
        let casm_contract_class: CasmContractClass = serde_json::from_str(raw_contract_class)?;
        let contract_class = CompiledClassV1::try_from(casm_contract_class)?;

        Ok(contract_class)
    }
}

/// Returns the estimated VM resources required for computing Casm hash (for Cairo 1 contracts).
///
/// Note: the function focuses on the bytecode size, and currently ignores the cost handling the
/// class entry points.
pub fn estimate_casm_hash_computation_resources(
    bytecode_segment_lengths: &NestedIntList,
) -> ExecutionResources {
    // The constants in this function were computed by running the Casm code on a few values
    // of `bytecode_segment_lengths`.
    match bytecode_segment_lengths {
        NestedIntList::Leaf(length) => {
            // The entire contract is a single segment (old Sierra contracts).
            &ExecutionResources {
                n_steps: 463,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::from([(BuiltinName::poseidon, 10)]),
            } + &poseidon_hash_many_cost(*length)
        }
        NestedIntList::Node(segments) => {
            // The contract code is segmented by its functions.
            let mut execution_resources = ExecutionResources {
                n_steps: 480,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::from([(BuiltinName::poseidon, 11)]),
            };
            let base_segment_cost = ExecutionResources {
                n_steps: 24,
                n_memory_holes: 1,
                builtin_instance_counter: HashMap::from([(BuiltinName::poseidon, 1)]),
            };
            for segment in segments {
                let NestedIntList::Leaf(length) = segment else {
                    panic!(
                        "Estimating hash cost is only supported for segmentation depth at most 1."
                    );
                };
                execution_resources += &poseidon_hash_many_cost(*length);
                execution_resources += &base_segment_cost;
            }
            execution_resources
        }
    }
}

// Returns the set of segments that were visited according to the given visited PCs and segment
// lengths.
// Each visited segment must have its starting PC visited, and is represented by it.
// visited_pcs should be given in reversed order, and is consumed by the function.
fn get_visited_segments(
    segment_lengths: &NestedIntList,
    visited_pcs: &mut Vec<usize>,
    bytecode_offset: &mut usize,
) -> Result<Vec<usize>, TransactionExecutionError> {
    let mut res = Vec::new();

    match segment_lengths {
        NestedIntList::Leaf(length) => {
            let segment = *bytecode_offset..*bytecode_offset + length;
            if visited_pcs.last().is_some_and(|pc| segment.contains(pc)) {
                res.push(segment.start);
            }

            while visited_pcs.last().is_some_and(|pc| segment.contains(pc)) {
                visited_pcs.pop();
            }
            *bytecode_offset += length;
        }
        NestedIntList::Node(segments) => {
            for segment in segments {
                let segment_start = *bytecode_offset;
                let next_visited_pc = visited_pcs.last().copied();

                let visited_inner_segments =
                    get_visited_segments(segment, visited_pcs, bytecode_offset)?;

                if next_visited_pc.is_some_and(|pc| pc != segment_start)
                    && !visited_inner_segments.is_empty()
                {
                    return Err(TransactionExecutionError::InvalidSegmentStructure(
                        next_visited_pc.unwrap(),
                        segment_start,
                    ));
                }

                res.extend(visited_inner_segments);
            }
        }
    }
    Ok(res)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledClassV1Inner {
    pub program: Program,
    pub entry_points_by_type: EntryPointsByType<EntryPointV1>,
    pub hints: HashMap<String, Hint>,
    pub compiler_version: CompilerVersion,
    bytecode_segment_lengths: NestedIntList,
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct EntryPointV1 {
    pub selector: EntryPointSelector,
    pub offset: EntryPointOffset,
    pub builtins: Vec<BuiltinName>,
}

impl EntryPointV1 {
    pub fn pc(&self) -> usize {
        self.offset.0
    }
}

// Implementation of the TryInto trait to convert a reference of CompiledClassV1 into
// CasmContractClass.
impl TryInto<CasmContractClass> for &CompiledClassV1 {
    // Definition of the error type that can be returned during the conversion.
    type Error = ProgramError;

    // Implementation of the try_into function which performs the conversion.
    fn try_into(self) -> Result<CasmContractClass, Self::Error> {
        // Converting the program data into a vector of BigUintAsHex.
        let bytecode: Vec<cairo_lang_utils::bigint::BigUintAsHex> = self
            .program
            .iter_data()
            .map(|x| cairo_lang_utils::bigint::BigUintAsHex {
                value: x.get_int_ref().unwrap().to_biguint(),
            })
            .collect();

        // Serialize the Program object to JSON bytes.
        let serialized_program = self.program.serialize()?;
        // Deserialize the JSON bytes into a serde_json::Value.
        let json_value: serde_json::Value = serde_json::from_slice(&serialized_program)?;

        // Extract the hints from the JSON value.
        let hints = json_value.get("hints").ok_or_else(|| {
            ProgramError::Parse(serde::ser::Error::custom("failed to parse hints"))
        })?;

        // Transform the hints into a vector of tuples (usize, Vec<Hint>).
        let hints: Vec<(usize, Vec<Hint>)> = hints
            .as_object() // Convert to JSON object.
            .unwrap()
            .iter()
            .map(|(key, value)| {
                // Transform each hint value into a Vec<Hint>.
                let hints: Vec<Hint> = value
                    .as_array() // Convert to JSON array.
                    .unwrap()
                    .iter()
                    .map(|hint_params| {
                        // Extract the "code" parameter and convert to a string.
                        let hint_param_code = hint_params.get("code").unwrap().clone();
                        let hint_string = hint_param_code.as_str().expect("failed to parse hint as string");

                        // Retrieve the hint from the self.hints map.
                        self.hints.get(hint_string).expect("failed to get hint").clone()
                    })
                    .collect();
                // Convert the key to usize and create a tuple (usize, Vec<Hint>).
                (key.parse().unwrap(), hints)
            })
            .collect();

        // Define the bytecode segment lengths
        let bytecode_segment_lengths = Some(self.bytecode_segment_lengths.clone());

        // Transform the entry points of type Constructor into CasmContractEntryPoint.
        let constructor = self
            .entry_points_by_type
            .constructor
            .iter()
            .map(|constructor| CasmContractEntryPoint {
                selector: num_bigint::BigUint::from_bytes_be(&constructor.selector.0.to_bytes_be()),
                offset: constructor.offset.0,
                builtins: constructor
                    .builtins
                    .clone()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect(),
            })
            .collect();

        // Transform the entry points of type External into CasmContractEntryPoint.
        let external = self
            .entry_points_by_type
            .external
            .iter()
            .map(|external| CasmContractEntryPoint {
                selector: num_bigint::BigUint::from_bytes_be(&external.selector.0.to_bytes_be()),
                offset: external.offset.0,
                builtins: external
                    .builtins
                    .clone()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect(),
            })
            .collect();

        // Transform the entry points of type L1Handler into CasmContractEntryPoint.
        let l1_handler = self
            .entry_points_by_type
            .l1_handler
            .iter()
            .map(|l1_handler| CasmContractEntryPoint {
                selector: num_bigint::BigUint::from_bytes_be(&l1_handler.selector.0.to_bytes_be()),
                offset: l1_handler.offset.0,
                builtins: l1_handler
                    .builtins
                    .clone()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect(),
            })
            .collect();

        // Construct the CasmContractClass from the extracted and transformed data.
        Ok(CasmContractClass {
            prime: num_bigint::BigUint::from_str_radix(&self.program.prime()[2..], 16)
                .expect("failed to parse prime"),
            compiler_version: self.compiler_version.0.to_string(),
            bytecode,
            bytecode_segment_lengths,
            hints,
            pythonic_hints: None,
            entry_points_by_type:
                cairo_lang_starknet_classes::casm_contract_class::CasmContractEntryPoints {
                    constructor,
                    external,
                    l1_handler,
                },
        })
    }
}

impl HasSelector for EntryPointV1 {
    fn selector(&self) -> &EntryPointSelector {
        &self.selector
    }
}

impl TryFrom<CasmContractClass> for CompiledClassV1 {
    type Error = ProgramError;

    fn try_from(class: CasmContractClass) -> Result<Self, Self::Error> {
        let data: Vec<MaybeRelocatable> =
            class.bytecode.iter().map(|x| MaybeRelocatable::from(Felt::from(&x.value))).collect();

        let mut hints: HashMap<usize, Vec<HintParams>> = HashMap::new();
        for (i, hint_list) in class.hints.iter() {
            let hint_params: Result<Vec<HintParams>, ProgramError> =
                hint_list.iter().map(hint_to_hint_params).collect();
            hints.insert(*i, hint_params?);
        }

        // Collect a sting to hint map so that the hint processor can fetch the correct [Hint]
        // for each instruction.
        let mut string_to_hint: HashMap<String, Hint> = HashMap::new();
        for (_, hint_list) in class.hints.iter() {
            for hint in hint_list.iter() {
                string_to_hint.insert(serde_json::to_string(hint)?, hint.clone());
            }
        }

        let builtins = vec![]; // The builtins are initialize later.
        let main = Some(0);
        let reference_manager = ReferenceManager { references: Vec::new() };
        let identifiers = HashMap::new();
        let error_message_attributes = vec![];
        let instruction_locations = None;

        let program = Program::new(
            builtins,
            data,
            main,
            hints,
            reference_manager,
            identifiers,
            error_message_attributes,
            instruction_locations,
        )?;

        let entry_points_by_type = EntryPointsByType {
            constructor: convert_entry_points_v1(&class.entry_points_by_type.constructor),
            external: convert_entry_points_v1(&class.entry_points_by_type.external),
            l1_handler: convert_entry_points_v1(&class.entry_points_by_type.l1_handler),
        };
        let bytecode_segment_lengths = class
            .bytecode_segment_lengths
            .unwrap_or_else(|| NestedIntList::Leaf(program.data_len()));
        let compiler_version = CompilerVersion(
            Version::parse(&class.compiler_version)
                .unwrap_or_else(|_| panic!("Invalid version: '{}'", class.compiler_version)),
        );
        Ok(CompiledClassV1(Arc::new(CompiledClassV1Inner {
            program,
            entry_points_by_type,
            hints: string_to_hint,
            compiler_version,
            bytecode_segment_lengths,
        })))
    }
}

// V0 utilities.

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}

/// Converts the program type from Cairo VM into a SN API-compatible type.
pub fn serialize_program<S: Serializer>(
    program: &Program,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let deprecated_program = cairo_vm_to_sn_api_program(program.clone())
        .map_err(|err| serde::ser::Error::custom(err.to_string()))?;
    deprecated_program.serialize(serializer)
}

// V1 utilities.

// TODO(spapini): Share with cairo-lang-runner.
fn hint_to_hint_params(hint: &Hint) -> Result<HintParams, ProgramError> {
    Ok(HintParams {
        code: serde_json::to_string(hint)?,
        accessible_scopes: vec![],
        flow_tracking_data: FlowTrackingData {
            ap_tracking: ApTracking::new(),
            reference_ids: HashMap::new(),
        },
    })
}

fn convert_entry_points_v1(external: &[CasmContractEntryPoint]) -> Vec<EntryPointV1> {
    external
        .iter()
        .map(|ep| EntryPointV1 {
            selector: EntryPointSelector(Felt::from(&ep.selector)),
            offset: EntryPointOffset(ep.offset),
            builtins: ep
                .builtins
                .iter()
                .map(|builtin| match BuiltinName::from_str(builtin) {
                    Some(builtin) => builtin,
                    None => {
                        BuiltinName::from_str_with_suffix(builtin).expect("Unrecognized builtin.")
                    }
                })
                .collect(),
        })
        .collect()
}

// TODO(Yoni): organize this file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
/// Modelled after [cairo_lang_starknet_classes::contract_class::ContractEntryPoints].
pub struct EntryPointsByType<EP: HasSelector> {
    pub constructor: Vec<EP>,
    pub external: Vec<EP>,
    pub l1_handler: Vec<EP>,
}

impl<EP: Clone + HasSelector> EntryPointsByType<EP> {
    pub fn get_entry_point(&self, call: &CallEntryPoint) -> Result<EP, PreExecutionError> {
        call.verify_constructor()?;

        let entry_points_of_same_type = &self[call.entry_point_type];
        let filtered_entry_points: Vec<_> = entry_points_of_same_type
            .iter()
            .filter(|ep| *ep.selector() == call.entry_point_selector)
            .collect();

        match filtered_entry_points[..] {
            [] => Err(PreExecutionError::EntryPointNotFound(call.entry_point_selector)),
            [entry_point] => Ok(entry_point.clone()),
            _ => Err(PreExecutionError::DuplicatedEntryPointSelector {
                selector: call.entry_point_selector,
                typ: call.entry_point_type,
            }),
        }
    }
}

impl<EP: HasSelector> Index<EntryPointType> for EntryPointsByType<EP> {
    type Output = Vec<EP>;

    fn index(&self, index: EntryPointType) -> &Self::Output {
        match index {
            EntryPointType::Constructor => &self.constructor,
            EntryPointType::External => &self.external,
            EntryPointType::L1Handler => &self.l1_handler,
        }
    }
}
