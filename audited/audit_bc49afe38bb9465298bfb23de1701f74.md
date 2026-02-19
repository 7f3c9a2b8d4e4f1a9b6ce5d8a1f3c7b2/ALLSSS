### Title
Consensus Transaction Signer Mismatch Enables Continuous Block Limit Bypass

### Summary
The continuous block limit mechanism can be bypassed through a pubkey mismatch between block validation and state update. Validation checks `LatestPubkeyToTinyBlocksCount.Pubkey` against `ExtraData.SenderPubkey` (block signer), but state updates use `Context.RecoverPublicKey()` (transaction signer). Two colluding miners can alternate signing consensus transactions while one produces all blocks, resetting the counter and bypassing the limit designed to prevent excessive consecutive block production.

### Finding Description

The root cause is a fundamental mismatch in pubkey sources between validation and state update phases:

**Validation Phase** uses `ExtraData.SenderPubkey` from the block header: [1](#0-0) 

This is validated against the stored pubkey: [2](#0-1) 

The `ExtraData.SenderPubkey` is confirmed to match `header.SignerPubkey`: [3](#0-2) 

**Execution Phase** uses transaction signer from `Context.RecoverPublicKey()`: [4](#0-3) 

State update logic uses this transaction-derived pubkey: [5](#0-4) 

**Missing Validation**: There is no check ensuring the transaction signer matches the block signer. The validation context is built here: [6](#0-5) 

The only transaction signer check verifies membership in the miner list, not equality with block signer: [7](#0-6) 

The validation provider also only checks the `SenderPubkey` (block signer) is in the miner list: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Violation**: The continuous block limit exists to prevent any single miner from dominating block production, as documented: [9](#0-8) 

Bypassing this protection enables:

1. **Centralization Risk**: One miner can produce unlimited consecutive blocks, undermining the decentralization guarantees of AEDPoS consensus
2. **Censorship**: Extended control over block production allows transaction censorship
3. **MEV Extraction**: Prolonged block production monopoly enables maximal extractable value across more blocks
4. **Reward Misallocation**: Unfair distribution of mining rewards to colluding parties
5. **Reorganization Risk**: Extended sequences from single producer increase chain instability

The state counter is reset when pubkeys differ: [10](#0-9) 

### Likelihood Explanation

**Highly Feasible** with realistic attacker capabilities:

1. **Reachable Entry Point**: Consensus transactions (`UpdateValue`, `NextRound`, `NextTerm`, `UpdateTinyBlockInformation`) are public methods invoked during normal block production [11](#0-10) 

2. **Feasible Preconditions**: Requires two miners in the active miner list willing to collude - realistic since miner coordination already occurs for legitimate consensus purposes

3. **Low Complexity**: Normal mining flow shows both block and transaction are signed by the same key: [12](#0-11) [13](#0-12) 

However, nothing prevents including a transaction signed by a different miner - all cryptographic checks pass as each signature is valid independently

4. **Economic Rationality**: Block production rewards and MEV opportunities provide strong economic incentives for exploitation

5. **Detection Difficulty**: The attack appears as normal mining from different miners when viewing individual components; only cross-referencing block signers with transaction signers reveals the manipulation

### Recommendation

**Add validation ensuring transaction signer matches block signer** in `ValidateBeforeExecution`:

```csharp
// After line 60 in AEDPoSContract_Validation.cs
// Add explicit check that transaction signer equals block signer
if (validationContext.SenderPubkey != Context.RecoverPublicKey().ToHex())
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = "Consensus transaction must be signed by block producer" 
    };
}
```

Alternatively, modify `PreCheck` to verify the recovered pubkey matches the expected block producer: [14](#0-13) 

Add after line 321:
```csharp
// Verify transaction signer matches block signer from header
if (TryToGetCurrentRoundInformation(out var validationRound) && 
    validationRound.RealTimeMinersInformation.ContainsKey(_processingBlockMinerPubkey))
{
    // Transaction signer must match the actual block producer
    // This ensures LatestPubkeyToTinyBlocksCount tracks the correct miner
}
```

**Test cases** should verify:
1. Block with mismatched block signer and transaction signer is rejected
2. Consecutive blocks from same miner with alternating transaction signers fail continuous block validation
3. Normal flow (matching signers) continues to work correctly

### Proof of Concept

**Initial State:**
- Miner A and Miner B are both in active miner list
- `State.LatestPubkeyToTinyBlocksCount = {Pubkey: "A", BlocksCount: 1}`
- Miner A wants to continue producing beyond the limit

**Attack Sequence:**

**Block N:**
1. Miner A signs block header (SignerPubkey = A)
2. Miner A includes consensus extra data with SenderPubkey = A
3. **Miner B signs the UpdateValue/TinyBlock transaction** (manipulation point)
4. Validation: `ContinuousBlocksValidationProvider` checks `"A" == "A" && 1 < 0`? False → Passes ✓
5. Execution: `_processingBlockMinerPubkey = "B"` (from transaction signature)
6. State update: Since `"A" != "B"`, counter resets to `{Pubkey: "B", BlocksCount: minersCount-1}`

**Block N+1:**
1. Miner A signs block header (SignerPubkey = A)
2. Miner A includes consensus extra data with SenderPubkey = A
3. **Miner A signs transaction** (or alternates back to B)
4. Validation: `ContinuousBlocksValidationProvider` checks `"B" == "A" && X < 0`? No (B ≠ A) → Passes ✓
5. Execution: `_processingBlockMinerPubkey = "A"`
6. State update: Since `"B" != "A"`, counter resets to `{Pubkey: "A", BlocksCount: minersCount-1}`

**Result:** Miner A produces unlimited consecutive blocks by alternating transaction signers, completely bypassing the continuous block limit enforcement. The validation always sees mismatched pubkeys and passes, while the state counter constantly resets instead of decrementing.

**Success Condition:** Miner A successfully produces more than `MaximumTinyBlocksCount` or `minersCountInTheory` consecutive blocks without triggering the continuous blocks validation failure that should occur when `BlocksCount < 0`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L17-17)
```csharp
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L35-37)
```csharp
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L16-19)
```csharp
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L32-32)
```csharp
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L350-363)
```csharp
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L130-183)
```csharp
    private TransactionList GenerateTransactionListByExtraData(AElfConsensusHeaderInformation consensusInformation,
        ByteString pubkey, ByteString randomNumber)
    {
        var round = consensusInformation.Round;
        var behaviour = consensusInformation.Behaviour;
        switch (behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                Context.LogDebug(() =>
                    $"Previous in value in extra data:{round.RealTimeMinersInformation[pubkey.ToHex()].PreviousInValue}");
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
                };
            case AElfConsensusBehaviour.TinyBlock:
                var minerInRound = round.RealTimeMinersInformation[pubkey.ToHex()];
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateTinyBlockInformation),
                            new TinyBlockInput
                            {
                                ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
                                ProducedBlocks = minerInRound.ProducedBlocks,
                                RoundId = round.RoundIdForValidation,
                                RandomNumber = randomNumber
                            })
                    }
                };
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
            default:
                return new TransactionList();
        }
    }
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L103-118)
```csharp
        var address = Address.FromPublicKey(await _accountService.GetPublicKeyAsync());
        var systemTransactions = await _systemTransactionGenerationService.GenerateSystemTransactionsAsync(address,
            previousBlockHeight, previousBlockHash);

        foreach (var transaction in systemTransactions) await SignAsync(transaction);

        await _blockchainService.AddTransactionsAsync(systemTransactions);

        return systemTransactions;
    }

    private async Task SignAsync(Transaction notSignerTransaction)
    {
        var signature = await _accountService.SignAsync(notSignerTransaction.GetHash().ToByteArray());
        notSignerTransaction.Signature = ByteString.CopyFrom(signature);
    }
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L132-140)
```csharp
        block.Header.SignerPubkey = ByteString.CopyFrom(await _accountService.GetPublicKeyAsync());
        return block;
    }

    private async Task SignBlockAsync(Block block)
    {
        var signature = await _accountService.SignAsync(block.GetHash().ToByteArray());
        block.Header.Signature = ByteString.CopyFrom(signature);
    }
```
