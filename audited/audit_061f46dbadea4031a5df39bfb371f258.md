### Title
Evil Miners Can Produce Blocks During Transition Round Due to Missing Banned Status Validation

### Summary
The `MiningPermissionValidationProvider` only verifies that a miner's public key exists in `RealTimeMinersInformation.Keys`, without checking if the miner has been marked as evil/banned in the Election Contract's `BannedPubkeyMap`. This allows miners who have been detected as evil (due to excessive missed time slots) to continue producing blocks for an entire additional round after detection, undermining the punishment mechanism and delaying their replacement with legitimate alternative candidates.

### Finding Description

The vulnerability exists in the `ValidateHeaderInformation` method which implements the comment's stated approach of "simply check keys of RealTimeMinersInformation should be enough": [1](#0-0) 

This validation is insufficient because there's a one-round timing gap in the evil miner detection and replacement flow:

**Detection Timing:** When transitioning from round N to N+1, evil miners are detected in `ProcessNextRound` using `TryToDetectEvilMiners`: [2](#0-1) 

This detection checks if miners have missed too many time slots: [3](#0-2) 

**Replacement Timing:** However, the replacement of evil miners happens BEFORE the next round is generated, using `GetMinerReplacementInformation`: [4](#0-3) 

**Critical Gap:** The `GetMinerReplacementInformation` method only identifies miners who are ALREADY in `BannedPubkeyMap`: [5](#0-4) 

**Execution Flow:**
1. Round N: Miner misses excessive time slots
2. Generate Round N+1: `GetMinerReplacementInformation` does NOT find the miner (not yet in `BannedPubkeyMap`)
3. Execute `ProcessNextRound`: `TryToDetectEvilMiners` detects the miner and marks them in `BannedPubkeyMap`
4. Round N+1: Evil miner remains in `RealTimeMinersInformation` and passes `MiningPermissionValidationProvider` validation
5. Round N+2: `GetMinerReplacementInformation` finally sees the miner in `BannedPubkeyMap` and replaces them

The AEDPoS contract has access to the Election Contract to check banned status: [6](#0-5) 

But this reference is not utilized in the validation logic.

### Impact Explanation

**Direct Consensus Integrity Impact:**
- Evil miners continue producing blocks for an entire round after being detected as malicious
- They continue receiving block rewards and mining fees during this transition round
- The punishment mechanism intended to penalize bad behavior is undermined
- Legitimate replacement candidates are delayed by one full round (potentially hundreds of blocks)

**Quantified Damage:**
- One additional round of block production by a detected evil miner
- Full round's worth of mining rewards allocated to punished miner
- Extended consensus disruption window
- Delayed activation of replacement miners who should be producing blocks

**Affected Parties:**
- The blockchain network suffers from continued operation by malicious nodes
- Legitimate alternative candidates lose one round of mining opportunities and rewards
- Token holders and users experience degraded network reliability

### Likelihood Explanation

**Attack Complexity:** None required - this is a design flaw that occurs naturally through the normal consensus flow.

**Attacker Capabilities:** No special capabilities needed. Any miner who exceeds the `TolerableMissedTimeSlotsCount` threshold automatically triggers this scenario.

**Feasibility Conditions:** 
- Occurs automatically during normal consensus operations
- No special permissions or state manipulation required
- Happens every time the evil miner detection mechanism triggers

**Execution Practicality:**
- Entry point is the standard block validation flow before execution
- No complex preconditions or race conditions to exploit
- Simply requires a miner to miss time slots, which can happen due to network issues, intentional disruption, or hardware failure

**Detection Constraints:** The system DOES detect the evil miner but fails to immediately prevent them from continuing to produce blocks.

**Probability:** HIGH - This will occur in every case where a miner is marked as evil due to missed time slots, which is a core punishment mechanism of the consensus system.

### Recommendation

**Immediate Fix:** Modify `MiningPermissionValidationProvider` to add a check against the Election Contract's `BannedPubkeyMap`:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    
    // Existing check
    if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
    {
        validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
        return validationResult;
    }

    // NEW: Check if miner is banned
    // Access via State.ElectionContract reference available in AEDPoS contract
    var isBanned = State.ElectionContract.IsPubkeyBanned.Call(
        new StringValue { Value = validationContext.SenderPubkey }
    ).Value;
    
    if (isBanned)
    {
        validationResult.Message = $"Sender {validationContext.SenderPubkey} is banned from mining.";
        return validationResult;
    }

    validationResult.Success = true;
    return validationResult;
}
```

**Additional Requirements:**
1. Add `IsPubkeyBanned` view method to Election Contract if not already present
2. Update `ConsensusValidationContext` to include Election Contract reference if needed
3. Add integration test verifying evil miners cannot produce blocks immediately after detection

**Invariant to Enforce:** Banned miners must be prevented from producing blocks in ALL rounds following their detection, with zero-round delay.

### Proof of Concept

**Initial State:**
- Round N is active with 17 miners
- Miner A has missed 14+ time slots (exceeds `TolerableMissedTimeSlotsCount`)
- Miner A is still in Round N's `RealTimeMinersInformation`

**Transaction Steps:**

1. **Generate Round N+1 Header:**
   - Miner B (extra block producer) calls consensus to generate Round N+1
   - `GetConsensusExtraDataForNextRound` is called [7](#0-6) 
   - `GenerateNextRoundInformation` calls `GetMinerReplacementInformation`
   - Miner A is NOT in `BannedPubkeyMap` yet, so NOT replaced in Round N+1 generation

2. **Execute ProcessNextRound:**
   - `TryToDetectEvilMiners` identifies Miner A
   - `UpdateCandidateInformation` is called with `IsEvilNode=true`
   - Miner A is added to `BannedPubkeyMap`
   - Round N+1 is stored with Miner A still in `RealTimeMinersInformation`

3. **Miner A Produces Block in Round N+1:**
   - Miner A attempts to produce their assigned block in Round N+1
   - Block validation calls `ValidateBeforeExecution` [8](#0-7) 
   - `MiningPermissionValidationProvider.ValidateHeaderInformation` is invoked
   - Check passes: Miner A exists in `baseRound.RealTimeMinersInformation.Keys`
   - No check against `BannedPubkeyMap`
   - **Block is accepted and executed**

**Expected Result:** Miner A should be rejected from producing blocks immediately after detection.

**Actual Result:** Miner A successfully produces blocks throughout Round N+1, continuing to earn rewards and participate in consensus despite being marked as evil.

**Success Condition:** When Round N+2 begins, `GetMinerReplacementInformation` finally sees Miner A in `BannedPubkeyMap` and replaces them - but only after an entire round of continued malicious participation.

### Notes

The comment stating "Simply check keys of RealTimeMinersInformation should be enough" is demonstrably insufficient. While `RealTimeMinersInformation` tracks which miners are scheduled for the current round, it does not reflect real-time punishment status. The one-round delay between detection and removal creates an exploitable window where banned miners retain full mining privileges, directly contradicting the consensus system's security model.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-342)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-404)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ContractsReferences.cs (L14-14)
```csharp
    internal ElectionContractContainer.ElectionContractReferenceState ElectionContract { get; set; }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-20)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```
