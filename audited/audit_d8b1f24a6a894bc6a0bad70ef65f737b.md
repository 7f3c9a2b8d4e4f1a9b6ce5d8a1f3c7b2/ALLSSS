### Title
Predictable NFT Symbol Generation Allows Miner Manipulation via Known Block Height Random Seed

### Summary
The `GenerateSymbolNumber()` function uses `Context.CurrentHeight.Sub(1)` to retrieve the random seed, which is already stored on-chain and publicly known at the time miners select transactions for inclusion. This allows miners to predict the exact NFT symbol that will be generated for any pending transaction and selectively censor, delay, or front-run transactions based on symbol desirability.

### Finding Description

The vulnerability exists in the NFT symbol generation mechanism: [1](#0-0) 

The function retrieves the random bytes from height H-1 when executing at height H. The random hash for height H-1 is generated and stored during the consensus transaction execution: [2](#0-1) 

The random hash is verified using EC-VRF and stored in `State.RandomHashes[Context.CurrentHeight]` during block production. This means when a miner is building block H, the random hash for H-1 is already finalized and publicly accessible: [3](#0-2) 

The execution order confirms that system transactions (including consensus transactions) execute before regular user transactions: [4](#0-3) 

**Root Cause**: The random seed used for symbol generation is deterministic and known before transaction inclusion decisions are made. The symbol generation combines the known random hash with the known sender address: [5](#0-4) 

This makes the outcome 100% predictable to miners before they commit to including the transaction.

**Why Protections Fail**: There is no protection against miners using this predictability to their advantage. The collision check loop cannot prevent manipulation as it only ensures uniqueness, not fairness.

### Impact Explanation

**Direct Impact:**
- **Unfair Symbol Allocation**: Certain NFT symbols may have higher value (e.g., lower numbers like "AR0001" vs "AR9999", patterns, memorable sequences). Miners can ensure these valuable symbols go to themselves or allies.
- **Censorship Attack**: Miners can indefinitely delay transactions that would generate desirable symbols, preventing legitimate users from obtaining them.
- **Front-Running**: Miners can observe pending NFT creation transactions, identify which would generate valuable symbols, and submit their own transactions first to claim those symbols.

**Who Is Affected:**
- All users attempting to create NFT protocols via the `Create` method are vulnerable to manipulation.
- The NFT protocol fairness and integrity is compromised.
- Users lose the ability to fairly compete for desirable symbols.

**Severity Justification**: HIGH severity because:
1. Miners have complete predictability and control over symbol assignment
2. Attack is passive (requires no special tools, just transaction simulation)
3. Economic incentive exists when certain symbols have higher market value
4. Users cannot defend against this manipulation

### Likelihood Explanation

**Attacker Capabilities**: 
- Only requires being a block producer (miner) in the AEDPoS consensus
- No special privileges beyond normal mining capabilities needed
- Attack is passive observation and transaction selection

**Attack Complexity**: LOW
- Miners can trivially simulate NFT creation transactions before including them
- Random hash for H-1 is publicly readable from chain state
- No complex cryptographic attacks or state manipulation required

**Feasibility Conditions**:
- Happens naturally during normal block production
- No additional setup or preconditions needed
- Works on every block where NFT creation transactions are present

**Detection/Operational Constraints**:
- Censorship is difficult to detect (appears as normal transaction pool dynamics)
- Front-running may be observable but not provably malicious
- No on-chain evidence of manipulation

**Probability**: HIGH - Any rational profit-seeking miner will exploit this when economically viable, especially for high-value symbol numbers.

### Recommendation

**Code-Level Mitigation**: Change line 73 to use current block height instead of previous:

```csharp
// Change from:
Value = Context.CurrentHeight.Sub(1)
// To:
Value = Context.CurrentHeight
```

This ensures the random hash used for symbol generation is not yet determined when miners select transactions for inclusion. Since consensus transactions execute first in each block and set `State.RandomHashes[Context.CurrentHeight]`, the random hash will be available when the NFT contract executes but unknown during transaction selection. [6](#0-5) 

**Invariant Checks**:
- Ensure the requested height's random hash exists before using it
- Add assertion: `Assert(State.RandomHashes[height] != null, "Random hash not available for requested height")`

**Test Cases**:
1. Verify symbol generation produces different results across different blocks
2. Confirm same user gets different symbols when creating multiple NFT protocols in different blocks
3. Validate that symbol generation fails gracefully if random hash is unavailable
4. Test that miners cannot predict symbols before block production

### Proof of Concept

**Initial State**:
- Block height H-1 has been produced with random hash = `0xABCD...`
- User Alice submits transaction to create NFT protocol of type "Art"
- Miner Bob is producing block H

**Attack Steps**:

1. **Miner Observation**: Bob receives Alice's NFT creation transaction in the transaction pool
2. **Simulation**: Bob simulates the transaction locally:
   - Reads `State.RandomHashes[H-1]` = `0xABCD...` (publicly known)
   - Computes `randomHash = Hash(Hash(Alice.Address) + Hash(0xABCD...))`
   - Computes `symbolNumber = ConvertHashToInt64(randomHash, 1000, 10000)` (assuming 4-digit symbols)
   - Determines Alice would get symbol "AR1234"

3. **Exploitation Options**:
   - **Option A (Censorship)**: If "AR1234" is valuable, exclude Alice's transaction from block H
   - **Option B (Front-Running)**: If "AR1234" is valuable, Bob submits his own transaction first to claim "AR1234", then includes Alice's transaction which will get a different (less desirable) symbol
   - **Option C (Selective Inclusion)**: Only include transactions that generate undesirable symbols

**Expected Result**: Alice gets symbol "AR1234" if included in block H

**Actual Result**: 
- With censorship: Alice's transaction is delayed, she gets a different symbol in a future block
- With front-running: Bob gets "AR1234", Alice gets whatever symbol her transaction generates in the same block (different due to collision check) or next block
- Users cannot fairly obtain desirable symbols

**Success Condition**: Miner successfully obtains valuable symbol while denying it to legitimate user, with no on-chain evidence of manipulation

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-74)
```csharp
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L75-82)
```csharp
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
        long randomNumber;
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L117-122)
```csharp
    public override Hash GetRandomHash(Int64Value input)
    {
        Assert(input.Value > 1, "Invalid block height.");
        Assert(Context.CurrentHeight >= input.Value, "Block height not reached.");
        return State.RandomHashes[input.Value] ?? Hash.Empty;
    }
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockExecutingService.cs (L58-64)
```csharp
        var nonCancellable = nonCancellableTransactions.ToList();
        var cancellable = cancellableTransactions.ToList();
        var nonCancellableReturnSets =
            await _transactionExecutingService.ExecuteAsync(
                new TransactionExecutingDto { BlockHeader = blockHeader, Transactions = nonCancellable },
                CancellationToken.None);
        Logger.LogTrace("Executed non-cancellable txs");
```
