# Audit Report

## Title
Missing Miner List Validation in NextRound Transitions Allows Consensus Disruption via Inflated Miner Count

## Summary
The NextRound consensus validation logic fails to verify that the provided next round's miner list matches the current round's authorized miners. This allows a malicious miner to inject fake entries into `RealTimeMinersInformation`, causing an inflated miner count that disrupts consensus order assignments, time slot allocations, and potentially dilutes mining rewards.

## Finding Description

**Root Cause - Missing Miner List Validation:**

The vulnerability exists in the NextRound validation flow. When validating a NextRound block, the system only checks internal consistency of the provided round structure but never validates that the miner set is legitimate. [1](#0-0) 

This validator only verifies that miners with `FinalOrderOfNextRound > 0` equals miners with `OutValue != null`. For a freshly generated next round, all miners (both legitimate and any injected fake ones) have these fields as null/0, so the check passes as `0 == 0`. [2](#0-1) 

This validator only checks that all `InValue` fields are null in the next round, which fake miners would also satisfy.

**Critical Gap:** Neither validator compares the provided round's miner list against the current round's authorized miners stored in `BaseRound`. [3](#0-2) 

The validation context has access to both `BaseRound` (trusted current state) and `ProvidedRound` (from block header), but no validator performs miner set membership verification.

**Exploitation Path:**

1. A malicious miner's turn to produce the NextRound transition block
2. The miner generates legitimate next round via contract method: [4](#0-3) 

3. Before including in the block, the miner modifies `nextRound.RealTimeMinersInformation` to add fake `MinerInRound` entries with default values

4. Validation passes all checks: [5](#0-4) 

5. The corrupted round is stored to state: [6](#0-5) 

6. When the next round is generated from this corrupted round, fake miners are carried forward: [7](#0-6) 

7. Fake miners get assigned time slots and orders: [8](#0-7) 

8. The inflated miner count corrupts consensus calculations: [9](#0-8) 

## Impact Explanation

**Consensus Integrity Breach:**
The inflated `minersCount` directly affects the deterministic order assignment algorithm. The modulus operation `GetAbsModulus(sigNum, minersCount) + 1` produces different results with an inflated count, causing legitimate miners to receive incorrect order assignments.

**Operational Disruption:**
Fake miners are assigned time slots but cannot produce blocks, creating persistent gaps in the block production schedule. Each fake miner represents a missed time slot that delays network progress.

**Persistent Corruption:**
The `GenerateNextRoundInformation` method propagates all miners from the current round to the next round. Once injected, fake miners persist through subsequent rounds until a NextTerm transition occurs (which rebuilds the miner list from election results).

**Economic Impact:**
If mining rewards or other economic distributions are calculated based on miner count, fake entries dilute the rewards that should go to legitimate miners.

**Severity:** High - A single malicious miner can disrupt consensus for all validators, degrade block production reliability, and potentially manipulate reward distributions.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a current miner (moderate barrier - requires election/authorization)
- Must be producing the NextRound transition block (periodic opportunity - happens every round)
- Must modify node software to inject fake miners (low technical complexity)

**Attack Feasibility:**
The attack is straightforward - simply add entries to the `RealTimeMinersInformation` dictionary with default field values before including the round in the block header. No complex state manipulation or timing coordination required.

**Detection Difficulty:**
The corrupted state appears valid to the validation logic. Fake miners manifest as missed time slots, which could be mistaken for network issues rather than an attack.

**Probability:** High if any current miner is malicious, as the validation gap makes the attack trivial to execute and difficult to detect.

## Recommendation

Add a miner list membership validation in the NextRound validators to ensure the provided round only contains authorized miners from the current round:

```csharp
// In NextRoundMiningOrderValidationProvider or a new validator
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var baseRound = validationContext.BaseRound;
    var providedRound = validationContext.ProvidedRound;
    
    // Verify all miners in provided round exist in base round
    foreach (var minerPubkey in providedRound.RealTimeMinersInformation.Keys)
    {
        if (!baseRound.RealTimeMinersInformation.ContainsKey(minerPubkey))
        {
            validationResult.Message = $"Unauthorized miner {minerPubkey} in next round.";
            return validationResult;
        }
    }
    
    // Verify miner counts match (no miners removed or added)
    if (providedRound.RealTimeMinersInformation.Count != baseRound.RealTimeMinersInformation.Count)
    {
        validationResult.Message = "Miner count mismatch between rounds.";
        return validationResult;
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

This validation should be added to the validator list for NextRound behavior in `ValidateBeforeExecution`.

## Proof of Concept

Note: A complete proof of concept would require modifying the node software to inject fake miners during block production, which is outside the smart contract testing scope. However, the validation gap can be demonstrated by:

1. Deploy test chain with N legitimate miners
2. Manually construct a NextRoundInput with N+M miners (including fake entries)
3. Call ProcessConsensusInformation with this input
4. Observe that validation passes despite the inflated miner count
5. Verify subsequent rounds carry forward the fake miners via GetCurrentRoundInformation
6. Confirm ApplyNormalConsensusData uses the inflated count in calculations

The vulnerability is confirmed by code inspection showing no miner list validation exists in any NextRound validator, allowing arbitrary miners to be included in the next round structure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L32-34)
```csharp
        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L19-27)
```csharp
    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L16-18)
```csharp
        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-55)
```csharp
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
