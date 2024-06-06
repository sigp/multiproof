# Merkle Multiproof Inputs Generation For Forge

This is a simple library to generate Merkle Multiproof inputs for OpenZeppelin's `MerkleProof` library. It is written in Solidity and can be used in Forge framework. The library has been tested to work with at most 10k of arbitrary leaves and arbitrary indices of any size.

Note that this library is not gas-efficient and should be used for testing purposes only.

## Usage

See `MerkleGen.t.sol` for a sample. First, deploy `MerkleGen` contract. Then, prepare the leaves and indices. Finally, call `gen()` to generate the necessary inputs.

A mock prover contract is provided in `Prover.sol` which forwards all inputs to OpenZeppelin's `MerkleProof.multiProofVerifyCalldata()`.

## How to run tests

The following command will run a normal test and a (pretty long) fuzzing test of 100k runs. To modify the number of runs, change the parameter in `foundry.toml`.

```
forge test
```

## License

MIT
