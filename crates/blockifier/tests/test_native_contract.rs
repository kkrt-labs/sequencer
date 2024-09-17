// Test command: cargo test --test test_native_contract --features testing
use blockifier::execution::contract_class::NativeContractClassV1;
use blockifier::test_utils::contracts::FeatureContract;

#[test]
fn test_partial_eq() {
    let contract_a = NativeContractClassV1::from_file(
        &FeatureContract::TestContractEntryPointA.get_compiled_path(),
    );
    let contract_b = NativeContractClassV1::from_file(
        &FeatureContract::TestContractEntryPointB.get_compiled_path(),
    );
    assert_eq!(contract_b, contract_b);
    assert_eq!(contract_a, contract_a);
    assert_ne!(
        contract_a, contract_b,
        "Contracts should be considered different because they have different entry points. \
         Specifically, the selectors are different due to having different names."
    );
}
