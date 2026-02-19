# Audit Report

## Title
Unvalidated ActualMiningTimes in RecoverFromTinyBlock Enables Term Change Manipulation and Consensus Corruption

## Summary
The AEDPoS consensus system fails to validate that miner-provided `ActualMiningTime` values match the actual block time (`Context.CurrentBlockTime`) when processing TinyBlock consensus information. Since `ActualMiningTimes` is excluded from round hash verification but used in critical consensus decisions including term change detection, malicious miners can provide arbitrary timestamps to manipulate consensus timing and disrupt governance processes.

## Finding Description

The vulnerability exists in the TinyBlock processing flow where miner-provided timestamps are accepted without validation:

**Root Cause:** The `RecoverFromTinyBlock()` function unconditionally adds provided timestamps to the round state without any validation. [1](#0-0) 

Similarly, `ProcessTinyBlock()` persists the provided timestamp directly to blockchain state without comparing it to `Context.CurrentBlockTime`. [2](#0-1) 

**Why Existing Protections Fail:**

1. **Hash Validation Bypass:** The round integrity verification explicitly clears `ActualMiningTimes` before computing hashes, allowing manipulated timestamps to bypass integrity checks. [3](#0-2) 

2. **Validation Uses Corrupted Data:** During `ValidateBeforeExecution`, the system calls `RecoverFromTinyBlock` BEFORE running validation providers, meaning validators check against already-corrupted state. [4](#0-3) 

The recovered `baseRound` with fake timestamps is then passed to validators: [5](#0-4) 

3. **Time Slot Validation Compromised:** The `TimeSlotValidationProvider` retrieves the latest actual mining time from the already-recovered (corrupted) round data. [6](#0-5) 

**Attack Path:**
A malicious miner producing a TinyBlock can modify the `ActualMiningTimes` in the consensus header after generation but before block signing. The block signature proves the miner signed the block but doesn't validate timestamp accuracy. Since consensus extra data only requires `SenderPubkey` to match `SignerPubkey`, the modified data passes validation.

## Impact Explanation

**Critical Consensus Corruption:**

1. **Term Change Manipulation:** The `NeedToChangeTerm()` function uses `ActualMiningTimes.Last()` to determine when term transitions should occur. [7](#0-6) 

Attackers can:
- **Delay term changes** by providing past timestamps, extending their mining power and delaying election updates and treasury releases
- **Advance term changes** by providing future timestamps, triggering premature elections and disrupting governance timing

2. **Time Slot Validation Bypass:** Miners can provide timestamps within their allocated time slot even when the actual block time has exceeded it, effectively extending their mining windows.

3. **Consensus Schedule Corruption:** The corrupted timestamps affect future consensus calculations and block production schedules.

**Affected Parties:** All blockchain participants experience consensus instability, governance processes are disrupted with mistimed elections and treasury releases, and miners gain unfair advantages through extended time slots.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current miner list (untrusted actors in AElf's threat model)
- Must produce TinyBlocks (normal miner operation)
- Must control their node software (standard for block producers)

**Attack Complexity: LOW**

The attack requires only modifying the node software to alter the `ActualMiningTimes` field in the consensus header data between generation and block signing. No cryptographic barriers exist since:
- Block producers control their node software completely
- The signature proves block authorship, not data accuracy
- ActualMiningTimes is excluded from hash verification
- No timestamp validation compares provided values against `Context.CurrentBlockTime`

**Feasibility: HIGH** - The attack is technically straightforward for any miner willing to run modified node software. Detection is difficult since observers only see the final persisted timestamps without reference to actual block times.

## Recommendation

Add validation to ensure provided `ActualMiningTime` values match or are reasonably close to `Context.CurrentBlockTime`:

**In ProcessTinyBlock:**
```csharp
private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // ADDED: Validate ActualMiningTime matches current block time
    var timeDifference = (Context.CurrentBlockTime - tinyBlockInput.ActualMiningTime).Seconds;
    Assert(Math.Abs(timeDifference) <= 60, 
        $"ActualMiningTime must match CurrentBlockTime. Difference: {timeDifference}s");
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
    // ... rest of function
}
```

**Alternative:** Eliminate the vulnerability entirely by having `ProcessTinyBlock` use `Context.CurrentBlockTime` directly instead of accepting it as input:
```csharp
minerInRound.ActualMiningTimes.Add(Context.CurrentBlockTime);
```

This removes the ability for miners to provide arbitrary timestamps while maintaining accurate mining time records.

## Proof of Concept

A proof of concept would require:

1. Setting up an AElf test network with AEDPoS consensus
2. Deploying a modified miner node that intercepts `GetConsensusExtraData` responses
3. Modifying the `ActualMiningTimes` field in the returned `Round` object to an arbitrary timestamp
4. Producing a TinyBlock with the modified consensus data
5. Observing that the block is accepted and the fake timestamp is persisted to state
6. Calling `GetCurrentRoundInformation` to verify the corrupted `ActualMiningTimes` values
7. Demonstrating term change timing manipulation by observing when `NeedToChangeTerm` returns true with fake vs. real timestamps

The test would validate that no assertion or validation rejects blocks with manipulated `ActualMiningTime` values, confirming the absence of timestamp verification against `Context.CurrentBlockTime`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L44-44)
```csharp
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L304-304)
```csharp
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L193-193)
```csharp
            checkableMinerInRound.ActualMiningTimes.Clear();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L218-223)
```csharp
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L49-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-59)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L41-41)
```csharp
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
```
