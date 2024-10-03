> [!WARNING]
> Note that this library has not had a security review yet, is not gas-efficient, and should only be used for testing.

# Merkle MultiProof and SingleProof Inputs Generation For Forge

This simple library generates Merkle MultiProof and SingleProof inputs for OpenZeppelin's `MerkleProof` library. It is written in Solidity and can be used in the Forge framework. The library has been tested to work with at most 10k arbitrary leaves and arbitrary indices of any size.

## Usage

See `MerkleGen.t.sol` for example:
- Import the `MerkleGen` library.
- Prepare the leaves and indices.
- Call `generateMultiproof` to generate the MultiProof or `generateSingleProof` to generate the SingleProof inputs.

A wrapper Prover library is provided in `Prover.sol`, which forwards all the inputs to OpenZeppelin's `MerkleProof` library.

## How to run tests

The following command will run a standard test and a (pretty long) fuzzing test of 100k runs. To modify the number of runs, change the `runs` parameter in `foundry.toml`.

```
forge test
```

## License

MIT