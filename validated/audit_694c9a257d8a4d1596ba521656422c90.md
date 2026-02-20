# Audit Report

## Title
Secret Sharing Revealed In Values Lost Due to Missing State Persistence in NextRound Flow

## Summary
The `RevealSharedInValues` function computes revealed in values from secret shares during off-chain NextRound block generation, but these values are set on a local `currentRound` variable that is never persisted to contract state. When `SupplyCurrentRoundInformation` executes on-chain during the NextRound transaction, it cannot access these revealed values, causing the secret sharing recovery mechanism to fail and fall back to predictable deterministic values.

## Finding Description

The vulnerability exists in the NextRound consensus flow where secret sharing is designed to recover in values for miners who failed to mine. The issue spans two execution phases:

**Off-Chain Phase (Block Generation):**

When a miner generates a NextRound block, `GetConsensusExtraDataForNextRound` creates the next round by calling `GenerateNextRoundInformation`, which constructs new `MinerInRound` objects copying only basic fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots) without PreviousInValue. [1](#0-0) 

The code then calls `RevealSharedInValues(currentRound, pubkey)` which uses Shamir secret sharing to decode other miners' in values and sets them on the local `currentRound` object. [2](#0-1) [3](#0-2) 

However, the function returns `nextRound` (which lacks these revealed values), and the modified `currentRound` is discarded without persistence. [4](#0-3) 

**On-Chain Phase (Block Execution):**

When the NextRound transaction executes, it first calls `SupplyCurrentRoundInformation()` to fill missing miner data. [5](#0-4) 

This function reads `currentRound` from state and attempts to access `PreviousInValue` for miners who didn't mine, with a comment explicitly stating this field should contain "previous in value recovered by other miners". [6](#0-5) 

Since the revealed values were never persisted, this field is null, forcing the system to fall back to deterministic fake values computed from the miner's public key. [7](#0-6) 

## Impact Explanation

This vulnerability completely breaks the secret sharing mechanism, which is a critical security feature of AEDPoS consensus designed to prevent miners from withholding their in values. When miners withhold in values, it breaks the random beacon and enables manipulation of consensus outcomes.

The impact is high severity because:
- **Complete security mechanism failure**: The secret sharing recovery that should prevent in value withholding becomes non-functional
- **Random beacon degradation**: Falls back to predictable deterministic values that undermine randomness properties
- **Consensus manipulation**: Allows malicious miners to withhold in values without consequence
- **Silent failure**: No errors are thrown, making the issue difficult to detect and allowing it to persist unnoticed

## Likelihood Explanation

This is not an attack scenario requiring malicious actions—it is a logic bug that occurs automatically during normal consensus operations.

The likelihood is HIGH because:
- **Automatic trigger**: Occurs at every NextRound transition, which is a regular consensus operation
- **No preconditions**: Requires no special setup or attacker actions
- **High frequency**: NextRound happens at every round transition during normal chain operation
- **Silent execution**: The failure produces no errors or warnings, making it appear as normal operation

## Recommendation

The revealed values computed by `RevealSharedInValues` must be persisted or transferred to the on-chain execution context. Possible fixes:

**Option 1**: Persist `currentRound` to state after calling `RevealSharedInValues`:
- After line 189 in `AEDPoSContract_GetConsensusBlockExtraData.cs`, call `TryToUpdateRoundInformation(currentRound)` to persist the revealed values

**Option 2**: Include revealed values in trigger information:
- Modify `AEDPoSTriggerInformationProvider.cs` to populate `RevealedInValues` for NextRound behavior (currently only done for UpdateValue)
- Use `UpdateLatestSecretPieces` mechanism to apply these values during on-chain processing

**Option 3**: Copy PreviousInValue in `GenerateNextRoundInformation`:
- Modify `Round_Generation.cs` to copy `PreviousInValue` when creating new `MinerInRound` objects, ensuring revealed values from `currentRound` are preserved in `nextRound`

## Proof of Concept

The vulnerability can be demonstrated by tracing the NextRound flow with secret sharing enabled:

1. Enable secret sharing via configuration
2. Have miners perform normal consensus operations to populate encrypted/decrypted pieces
3. Trigger a NextRound transition where some miners didn't mine
4. Observe that `RevealSharedInValues` computes revealed values during off-chain header generation
5. Observe that these values are absent when `SupplyCurrentRoundInformation` executes on-chain
6. Verify fallback to deterministic `HashHelper.ComputeFrom(miner)` values instead of recovered secret shared values

The test would verify that `PreviousInValue` in the current round state does not contain the values computed by `RevealSharedInValues` during NextRound generation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L198-203)
```csharp
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L52-52)
```csharp
            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L163-163)
```csharp
        SupplyCurrentRoundInformation();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-193)
```csharp
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L203-209)
```csharp
            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
```
