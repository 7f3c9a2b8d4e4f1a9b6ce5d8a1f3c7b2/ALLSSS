# Audit Report

## Title
Time Slot Validation Allows Malicious Round Crafting with Biased Mining Intervals

## Summary
The `CheckRoundTimeSlots()` validation function uses an overly permissive 100% tolerance check that allows mining intervals to range from 0 to 2× the base interval. A malicious extra block producer can exploit this by crafting Round data with manipulated time slots that pass validation but disrupt consensus through either DoS attacks (impossibly short intervals) or severe performance degradation (excessively long intervals).

## Finding Description

The AEDPoS consensus system fails to properly validate Round time slot integrity during NextRound transitions, breaking the security guarantee that all miners receive equal time slots for block production.

**Root Cause - Permissive Tolerance Check:**

The time slot validation uses a 100% tolerance that accepts any interval within 0 to 2× the base interval: [1](#0-0) 

This tolerance check allows `Math.Abs(miningInterval - baseMiningInterval) ≤ baseMiningInterval`, which mathematically permits intervals from 0ms to 2×baseMiningInterval. The validation is invoked during consensus header validation: [2](#0-1) 

**Missing Protection - No Round Regeneration Check:**

When processing NextRound transactions, the contract directly converts and stores the input Round without verifying it matches what the contract would legitimately generate: [3](#0-2) 

The Round is stored directly to state: [4](#0-3) 

**Mining Interval Calculation Dependency:**

The mining interval used throughout consensus operations is calculated from the first two miners' ExpectedMiningTime values: [5](#0-4) 

**Ineffective After-Execution Validation:**

The after-execution validation compares the header Round hash with the state Round hash, but since the malicious Round was already stored to state during execution, they are identical: [6](#0-5) 

**No Minimum/Maximum Bounds:**

The contract constants define various parameters but no bounds on mining intervals: [7](#0-6) 

**Attack Execution Path:**

1. Extra block producer generates consensus data through GetConsensusExtraDataForNextRound: [8](#0-7) 

2. Attacker modifies Round.RealTimeMinersInformation[*].ExpectedMiningTime values before including in block header

3. Modified Round passes CheckRoundTimeSlots validation (within 0-2× tolerance)

4. ProcessNextRound stores malicious Round to state

5. ValidateConsensusAfterExecution passes because it compares identical data

## Impact Explanation

The manipulated mining interval directly impacts consensus operations through GetMiningInterval(), which affects:

**Time Slot Validation:** [9](#0-8) 

**Tiny Block Production Limits:** [10](#0-9) 

**Attack Scenarios:**

1. **DoS Attack (Impossibly Short Intervals):** Setting first two miners 1ms apart creates baseMiningInterval=1ms. This makes TinyBlockSlotInterval = 1ms/8 = 0.125ms and DefaultBlockMiningLimit = 0.075ms, physically impossible for miners to meet, halting consensus.

2. **Consensus Slowdown (Excessively Long Intervals):** Setting first two miners 8000ms+ apart allows intervals up to 16000ms, with TinyBlockSlotInterval = 1000ms and DefaultBlockMiningLimit = 600ms, drastically reducing network throughput.

**Affected Parties:**
- All network participants experience consensus disruption
- Honest miners unable to produce blocks lose rewards
- Users face transaction delays or complete service outage

**Severity:** HIGH - A single malicious miner can compromise consensus integrity for an entire round, causing network-wide DoS or severe performance degradation.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a miner in the current miner list
- Must become the extra block producer for a round

The extra block producer rotates pseudo-randomly based on signatures: [11](#0-10) 

**Attack Complexity:**
LOW - The attacker simply modifies ExpectedMiningTime values in the Round data structure before including it in the block header. Legitimate round generation shows equal spacing: [12](#0-11) 

The attacker deviates from this pattern while staying within the loose validation tolerance.

**Trigger Conditions:**
NextRound behavior is triggered when miners need to terminate the current round: [13](#0-12) 

**Detection/Operational Constraints:**
- No cryptographic binding between legitimate Round generation and block production
- Validation only checks mathematical constraints, not semantic correctness of time slots
- Difficult to detect without regenerating and comparing the expected Round

**Probability:** MEDIUM-HIGH - Given the rotating nature of extra block producers, any compromised miner will eventually have opportunity to exploit this vulnerability. The attack is repeatable every time they become the extra block producer.

## Recommendation

Implement strict Round validation during NextRound processing:

1. **Add Round Regeneration Check:** In ProcessNextRound, regenerate the expected Round using GenerateNextRoundInformation and compare against the provided Round:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var providedRound = input.ToRound();
    
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // Regenerate expected Round and validate
    GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var expectedRound);
    
    // Compare critical fields
    Assert(providedRound.RoundNumber == expectedRound.RoundNumber, "Invalid round number");
    
    // Validate time slots match expected values
    foreach (var miner in expectedRound.RealTimeMinersInformation.Keys)
    {
        Assert(providedRound.RealTimeMinersInformation.ContainsKey(miner), "Missing miner information");
        Assert(
            providedRound.RealTimeMinersInformation[miner].ExpectedMiningTime == 
            expectedRound.RealTimeMinersInformation[miner].ExpectedMiningTime,
            "Manipulated mining time slot detected");
    }
    
    // Continue with existing logic
    RecordMinedMinerListOfCurrentRound();
    // ...
}
```

2. **Add Mining Interval Bounds:** Define minimum and maximum mining interval constants in AEDPoSContractConstants:

```csharp
public const int MinimumMiningInterval = 1000; // 1 second minimum
public const int MaximumMiningInterval = 5000; // 5 seconds maximum
```

And enforce these in CheckRoundTimeSlots:

```csharp
if (baseMiningInterval < AEDPoSContractConstants.MinimumMiningInterval || 
    baseMiningInterval > AEDPoSContractConstants.MaximumMiningInterval)
    return new ValidationResult { Message = "Mining interval out of acceptable bounds." };
```

3. **Tighten Tolerance Check:** Reduce the tolerance from 100% to a more reasonable value like 10%:

```csharp
if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval.Div(10))
    return new ValidationResult { Message = "Time slots are too different." };
```

## Proof of Concept

The following test demonstrates the vulnerability by crafting a malicious Round with 1ms intervals that passes validation:

```csharp
[Fact]
public async Task MaliciousRound_WithManipulatedTimeSlots_PassesValidation()
{
    // Setup: Initialize consensus with normal miners
    var miners = await InitializeConsensusAsync();
    var maliciousMiner = miners[0]; // First miner becomes extra block producer
    
    // Attacker becomes extra block producer for current round
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Generate legitimate next round
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(maliciousMiner.PublicKey),
        Behaviour = AElfConsensusBehaviour.NextRound
    };
    
    var consensusExtraData = await AEDPoSContractStub.GetConsensusExtraData.CallAsync(
        new BytesValue { Value = triggerInfo.ToByteString() });
    
    var headerInfo = new AElfConsensusHeaderInformation();
    headerInfo.MergeFrom(consensusExtraData.Value);
    var nextRound = headerInfo.Round;
    
    // ATTACK: Manipulate time slots to create 1ms intervals
    var startTime = currentRound.GetRoundStartTime();
    var orderedMiners = nextRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    
    for (int i = 0; i < orderedMiners.Count; i++)
    {
        // Set 1ms intervals between miners (DoS attack scenario)
        orderedMiners[i].ExpectedMiningTime = startTime.AddMilliseconds(i);
    }
    
    // Create malicious NextRoundInput
    var maliciousInput = NextRoundInput.Create(nextRound, GenerateRandomProof());
    
    // Attempt to execute malicious NextRound transaction
    var result = await AEDPoSContractStub.NextRound.SendAsync(maliciousInput);
    
    // VULNERABILITY: Transaction succeeds despite manipulated time slots
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify malicious Round was stored to state
    var storedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    storedRound.RoundNumber.ShouldBe(nextRound.RoundNumber);
    
    // Verify GetMiningInterval returns manipulated value (1ms)
    storedRound.GetMiningInterval().ShouldBe(1);
    
    // This breaks consensus: TinyBlockSlotInterval = 1/8 = 0.125ms (impossible)
    var tinyBlockInterval = storedRound.GetMiningInterval() / 8;
    tinyBlockInterval.ShouldBeLessThan(1); // Less than 1ms - physically impossible
}
```

This test proves that a malicious extra block producer can successfully inject a Round with 1ms intervals that passes all validation checks, storing the manipulated data to state and breaking consensus integrity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-54)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L44-45)
```csharp
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L87-101)
```csharp
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L1-16)
```csharp
namespace AElf.Contracts.Consensus.AEDPoS;

// ReSharper disable once InconsistentNaming
public static class AEDPoSContractConstants
{
    public const int MaximumTinyBlocksCount = 8;
    public const long InitialMiningRewardPerBlock = 12500000;
    public const long TimeToReduceMiningRewardByHalf = 126144000; // 60 * 60 * 24 * 365 * 4
    public const int SupposedMinersCount = 17;
    public const int KeepRounds = 40960;
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
    public const string SideChainShareProfitsTokenSymbol = "SHARE";
    public const string PayTxFeeSymbolListName = "SymbolListToPayTxFee";
    public const string PayRentalSymbolListName = "SymbolListToPayRental";
    public const string SecretSharingEnabledConfigurationKey = "SecretSharingEnabled";
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-177)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L37-49)
```csharp
        protected int MiningInterval => CurrentRound.GetMiningInterval();

        /// <summary>
        ///     Producing time of every (tiny) block at most.
        /// </summary>
        private int TinyBlockSlotInterval => MiningInterval.Div(TinyBlocksCount);

        protected int MinersCount => CurrentRound.RealTimeMinersInformation.Count;

        /// <summary>
        ///     Give 3/5 of producing time for mining by default.
        /// </summary>
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-82)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
```
