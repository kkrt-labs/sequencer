// Test command: cargo test --test test_native_contract --features testing

#[cfg(test)]
mod native_contract_tests {
    use blockifier::execution::contract_class::NativeContractClassV1;

    #[test]
    fn test_partial_eq() {
        let contract_a = NativeContractClassV1::from_file(
            format!("feature_contracts/cairo1/compiled/test_contract_entrypoint_a.sierra.json")
                .as_str(),
        );
        let contract_b = NativeContractClassV1::from_file(
            format!("feature_contracts/cairo1/compiled/test_contract_entrypoint_b.sierra.json")
                .as_str(),
        );
        assert_eq!(contract_b, contract_b);
        assert_eq!(contract_a, contract_a);
        assert_ne!(contract_a, contract_b, "Contracts should be considered different because they have different entry points. Specifically, the selectors are different due to having different names.");
    }
}
