### Title
Malicious Miner Can Manipulate ConfirmedIrreversibleBlockRoundNumber in NextRound to Force Severe Status DoS

### Summary
A malicious miner can directly manipulate the `ConfirmedIrreversibleBlockRoundNumber` field when calling `NextRound`, artificially inflating the gap between `currentRoundNumber` and `libRoundNumber`. This forces the blockchain into Severe status, reducing maximum block production to 1 per miner and effectively causing a denial-of-service attack on the consensus system.

### Finding Description

The vulnerability exists in the consensus round transition validation logic. When a miner calls `NextRound` to advance to the next consensus round, the system does not validate that the `ConfirmedIrreversibleBlockRoundNumber` field in the provided `NextRoundInput` is accurate. [1](#0-0) 

The validation providers for NextRound behavior only include `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`, but critically **exclude** `LibInformationValidationProvider`. This means there is no check to ensure that `ConfirmedIrreversibleBlockRoundNumber` does not decrease or remain incorrectly low. [2](#0-1) 

The `ProcessNextRound` method directly converts the untrusted `NextRoundInput` to a `Round` object and stores it in state without validation of the LIB fields. [3](#0-2) 

The manipulated round information is then used by `GetMaximumBlocksCount()` to determine blockchain mining status: [4](#0-3) 

The `BlockchainMiningStatusEvaluator` uses these values to calculate status, and triggers Severe status when the gap is large enough: [5](#0-4) 

When Severe status is triggered, the maximum blocks count is reduced to 1: [6](#0-5) 

### Impact Explanation

This vulnerability enables a **critical denial-of-service attack** on the blockchain consensus system:

1. **Operational Impact:** Maximum block production is reduced from the normal limit (e.g., 8) to just 1 block per miner time slot, severely throttling blockchain throughput by up to 87.5%.

2. **Consensus Integrity:** The attack creates a false perception that the blockchain is in distress with stalled irreversible block confirmation, when in reality the LIB may be progressing normally.

3. **Affected Parties:** All blockchain users experience dramatically reduced transaction processing capacity. The entire network's ability to process transactions is crippled.

4. **Attack Persistence:** The attacker can repeat this manipulation in subsequent rounds to maintain the DoS condition indefinitely.

5. **Severity Justification:** This is a HIGH severity vulnerability because a single malicious miner can unilaterally degrade the entire blockchain's performance without requiring collusion or significant resources.

### Likelihood Explanation

The attack is **highly likely** to be exploitable:

**Attacker Capabilities:**
- Attacker must be one of the active miners in the consensus round (checked by `PreCheck`) [7](#0-6) 

**Attack Complexity:** 
- Very low complexity: The attacker simply generates a valid `NextRoundInput` using standard methods, modifies the `ConfirmedIrreversibleBlockRoundNumber` field to an artificially low value (e.g., `currentRoundNumber - 8`), and calls the public `NextRound` method. [8](#0-7) 

**Feasibility Conditions:**
- No special preconditions required beyond being a miner
- No need for collusion with other miners
- Can be executed at any time during normal consensus operation

**Detection Constraints:**
- The attack is difficult to distinguish from legitimate network issues since Severe status is designed to trigger when consensus genuinely degrades
- No on-chain mechanism exists to verify that the provided `ConfirmedIrreversibleBlockRoundNumber` matches reality

**Economic Rationality:**
- Attack cost is negligible (just one transaction)
- Potential motivations include: griefing competitors, manipulating transaction fees during congestion, disrupting network operations, or creating arbitrage opportunities during reduced blockchain capacity

### Recommendation

**Immediate Fix:**
Add `LibInformationValidationProvider` to the validation pipeline for NextRound behavior: [1](#0-0) 

Modify the switch case to include:
```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

**Invariant Check:**
The `LibInformationValidationProvider` will ensure that: [9](#0-8) 

This validates that `ConfirmedIrreversibleBlockRoundNumber` in the provided round is not less than the base round's value, preventing malicious manipulation.

**Additional Safeguard:**
Consider adding a sanity check that the gap between `currentRoundNumber` and `ConfirmedIrreversibleBlockRoundNumber` cannot exceed a reasonable threshold (e.g., 3 rounds) under normal conditions.

**Test Cases:**
1. Test that NextRound with decreased `ConfirmedIrreversibleBlockRoundNumber` is rejected
2. Test that NextRound with stale `ConfirmedIrreversibleBlockRoundNumber` is rejected  
3. Test that legitimate NextRound with properly propagated LIB values succeeds
4. Test that system correctly enters Severe status only when LIB genuinely stalls

### Proof of Concept

**Initial State:**
- Blockchain is operating normally with current round number 100
- `ConfirmedIrreversibleBlockRoundNumber` is 99 (properly advanced)
- Attacker is a miner in round 100

**Attack Steps:**

1. **Attacker generates NextRoundInput for round 101** using standard `GenerateNextRoundInformation`: [10](#0-9) 

2. **Attacker modifies the input** before calling NextRound:
   - Set `ConfirmedIrreversibleBlockRoundNumber` = 92 (artificially low)
   - Keep `RoundNumber` = 101
   - Gap = 101 - 92 = 9 (exceeds threshold of 8)

3. **Attacker calls NextRound** with manipulated input: [8](#0-7) 

4. **Validation passes** because LibInformationValidationProvider is not included: [1](#0-0) 

5. **Manipulated round is stored** in state: [3](#0-2) 

**Expected Result:** NextRound should be rejected due to invalid LIB information

**Actual Result:** 
- NextRound succeeds
- Round 101 now has `ConfirmedIrreversibleBlockRoundNumber` = 92
- `GetMaximumBlocksCount()` detects gap of 9 >= 8
- System enters Severe status
- Maximum blocks reduced to 1
- Blockchain throughput crippled

**Success Condition:** The attack succeeds when `State.IsPreviousBlockInSevereStatus.Value` becomes true and subsequent calls to `GetMaximumBlocksCount()` return 1, confirmed by the `IrreversibleBlockHeightUnacceptable` event being fired.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L24-28)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-66)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```
