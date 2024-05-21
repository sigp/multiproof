# Merkle Multiproof Inputs Generation For Forge

This is a simple library to generate Merkle Multiproof inputs for OpenZeppelin's `MerkleProof` library. It is written in Solidity and can be used in Forge framework.

Note that this library is not gas-efficient and should be used for testing purposes only.

## Usage

See `MerkleGen.t.sol` for a sample. First, deploy `MerkleGen` contract. Then, prepare the leaves and indices. Finally, call `gen()` to generate the necessary inputs.

## How to run tests

The following command will run a normal test and a (pretty long) fuzzing test of 100k runs. To modify the number of runs, change the parameter in `foundry.toml`.

```
forge test
```

## License

MIT
```