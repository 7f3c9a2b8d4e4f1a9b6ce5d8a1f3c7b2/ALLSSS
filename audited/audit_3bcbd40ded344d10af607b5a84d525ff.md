### Title
Missing IsMinerListJustChanged Validation Allows Arbitrary Miner List Installation During Term Transitions

### Summary
The `ValidationForNextTerm()` function fails to verify that the `IsMinerListJustChanged` flag is set to true during term transitions, and does not validate that the provided miner list matches election results from the Election contract. This allows a malicious current miner to bypass the election mechanism by submitting a `NextTerm` transaction with an arbitrary miner list that will be installed for the new term.

### Finding Description

The validation logic for term transitions is implemented in `ValidationForNextTerm()` which only validates that the term number and round number increment by 1: [1](#0-0) 

**Root Cause**: The validation does not check:
1. Whether `IsMinerListJustChanged` is set to true (which should always be true for term transitions per the design)
2. Whether the miner list in the input matches the election results from `GetVictories()`

**Why Protections Fail**:

The `Round` protobuf message includes an `is_miner_list_just_changed` field specifically to indicate miner list changes: [2](#0-1) 

When generating a legitimate first round of a new term, this flag is always set to true: [3](#0-2) 

The legitimate term transition flow calls `TryToGetVictories()` to obtain the elected miner list from the Election contract: [4](#0-3) 

However, during execution in `ProcessNextTerm()`, the miner list is extracted **directly from the input** without any verification against election results: [5](#0-4) 

The `SetMinerList()` function only checks if the miner list for that term already exists, not whether it matches election results: [6](#0-5) 

### Impact Explanation

**Complete Subversion of Election Mechanism**: A malicious miner can install an arbitrary set of miners for the new term, completely bypassing the election voting process that determines miner selection. This breaks the fundamental consensus invariant that miners must be elected through the Election contract.

**Affected Parties**: All network participants are affected as the consensus mechanism's integrity is compromised. Legitimate elected candidates are denied their mining rights, while arbitrary addresses chosen by the attacker gain block production authority and associated rewards.

**Severity Justification**: This is a **HIGH severity** vulnerability because:
- It subverts the core election mechanism
- It violates the "miner schedule integrity" critical invariant
- The attacker gains complete control over the next term's miner set
- Mining rewards are redirected to attacker-controlled addresses
- The attack has lasting effects (entire term duration)

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be a current or previous miner (verified by `PreCheck()`): [7](#0-6) 

**Attack Complexity**: LOW - The attack is straightforward:
1. Wait for the appropriate time when `NeedToChangeTerm()` returns true
2. Construct a `NextTermInput` with correct term/round numbers and arbitrary miner list
3. Submit via the public `NextTerm()` method
4. The validation only checks term/round number increments and passes
5. The arbitrary miner list is installed

**Feasibility Conditions**: 
- Timing must align with term transition (predictable based on blockchain age and period seconds)
- No competing honest `NextTerm` transaction must be included first in the same block
- The `SetMinerList()` check only prevents duplicate miner list updates for the same term number

**Detection Constraints**: The lack of validation means there are no built-in detection mechanisms. The attack would only be discovered post-facto when the wrong miners are producing blocks.

**Probability**: MEDIUM-HIGH - Any current miner can execute this attack during each term transition window, making it a realistic threat.

### Recommendation

**Add IsMinerListJustChanged Validation**: Modify `ValidationForNextTerm()` to verify the flag is set:
```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Verify term number increments
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // NEW: Verify IsMinerListJustChanged is true for term transitions
    if (!extraData.Round.IsMinerListJustChanged)
        return new ValidationResult { Message = "IsMinerListJustChanged must be true for term transitions." };
    
    return new ValidationResult { Success = true };
}
```

**Add Miner List Verification**: In `ProcessNextTerm()`, verify the provided miner list matches election results:
```csharp
// Before calling SetMinerList, verify against election results
if (State.IsMainChain.Value && TryToGetVictories(out var victories))
{
    var providedMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    var electedMiners = victories.Pubkeys.Select(p => p.ToHex()).OrderBy(k => k).ToList();
    Assert(providedMiners.SequenceEqual(electedMiners), "Miner list does not match election results.");
}
```

**Test Cases**: Add regression tests that attempt to:
1. Submit `NextTerm` with `IsMinerListJustChanged = false`
2. Submit `NextTerm` with miner list different from `GetVictories()` results
3. Both should fail validation

### Proof of Concept

**Initial State**:
- Current term number: N
- Current round number: R
- Time has reached term transition point (blockchain age triggers `NeedToChangeTerm()`)
- Attacker is a current miner with public key ATTACKER_KEY
- Legitimate election winners: [MINER_A, MINER_B, MINER_C]

**Attack Steps**:
1. Attacker calls `GetCurrentRoundInformation()` to obtain current round R
2. Attacker crafts malicious `NextTermInput`:
   ```
   NextTermInput {
     TermNumber: N + 1,
     RoundNumber: R + 1,
     RealTimeMinersInformation: {
       ATTACKER_KEY: {...},
       ATTACKER_FRIEND_1: {...},
       ATTACKER_FRIEND_2: {...}
     },
     IsMinerListJustChanged: false  // or true, doesn't matter - not validated
   }
   ```
3. Attacker submits transaction calling `NextTerm(maliciousInput)`
4. Validation in `ValidateBeforeExecution()` passes (only checks term/round numbers)
5. Execution proceeds to `ProcessNextTerm()`
6. Miner list extracted from input: [ATTACKER_KEY, ATTACKER_FRIEND_1, ATTACKER_FRIEND_2]
7. `SetMinerList()` is called with attacker's list
8. State updated: `State.MinerListMap[N+1] = [ATTACKER_KEY, ATTACKER_FRIEND_1, ATTACKER_FRIEND_2]`

**Expected Result**: Only elected miners [MINER_A, MINER_B, MINER_C] should be installed for term N+1

**Actual Result**: Attacker's arbitrary miner list [ATTACKER_KEY, ATTACKER_FRIEND_1, ATTACKER_FRIEND_2] is installed and will produce blocks for the entire next term

**Success Condition**: Call `GetMinerList(termNumber: N+1)` and observe it returns the attacker's list instead of election results

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** protobuf/aedpos_contract.proto (L260-261)
```text
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```
