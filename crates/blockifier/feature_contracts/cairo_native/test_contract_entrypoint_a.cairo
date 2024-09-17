// Basic contract with an external entrypoint function.
// Used for comparison to its counterpart.
// `test_contract_entrypoint_a.cairo` : Has an external entrypoint for function: `number_a`.
// `test_contract_entrypoint_b.cairo` : Has an external entrypoint for function: `number_b`.
// These two contracts both have the same `sierra_program`, and both have an entrypoint with the same signature,
// However, they are different contracts because the function names used for the entrypoints are different.

#[starknet::contract]
mod TestContract {
    #[storage]
    struct Storage {
        my_storage_var: felt252,
        two_counters: starknet::storage::Map<felt252, (felt252, felt252)>,
        ec_point: (felt252, felt252),
    }

    #[constructor]
    fn constructor(ref self: ContractState, arg1: felt252, arg2: felt252) -> felt252 {
        self.my_storage_var.write(arg1 + arg2);
        arg1
    }

    #[external(v0)]
    fn get_num(
        ref self: ContractState
    ) -> felt252 {
        let val_a = number_a(ref self);
        let val_b = number_b(ref self);
        self.my_storage_var.write(val_a);
        val_a + val_b
    }

    // Functions for external entrypoints.
    // Reference: https://book.cairo-lang.org/ch14-02-contract-functions.html#external-functions

    // Note that although the function signatures are identical, the selector will be different.
    // Reference: https://book.cairo-lang.org/ch15-01-contract-class-abi.html?highlight=abi#function-selector
    // In the blockifier: `selector_from_name` uses `starknet_keccak` on `entry_point_name`.

    // First contract entrypoint.
    #[external(v0)]
    fn number_a(
        ref self: ContractState
    ) -> felt252 {
        73
    }

    // Second contract entrypoint.
    // #[external(v0)]
    fn number_b(
        ref self: ContractState
    ) -> felt252 {
        73
    }
}
