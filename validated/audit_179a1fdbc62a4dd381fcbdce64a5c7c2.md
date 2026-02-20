# Audit Report

## Title
NextRound Mining Order Validation Checks Wrong Round Allowing Order Manipulation

## Summary
The `NextRoundMiningOrderValidationProvider` validates mining order data from the wrong round (ProvidedRound instead of BaseRound), causing validation to always pass with meaningless 0==0 checks. This allows miners to arbitrarily manipulate `Order` field assignments in the next round, breaking the consensus fairness mechanism where mining order should be deterministically derived from cryptographic signature randomness.

## Finding Description
The AEDPoS consensus mechanism ensures fair mining order through cryptographic randomness. When miners produce blocks via `UpdateValue`, their signatures determine `FinalOrderOfNextRound`, which should dictate their position in the next round's mining schedule. [1](#0-0) 

However, the validation logic for NextRound behavior contains a critical flaw. The `NextRoundMiningOrderValidationProvider` validates using `ProvidedRound` (the submitted next round data): [2](#0-1) 

The ProvidedRound comes from `GenerateNextRoundInformation`, which creates fresh `MinerInRound` objects containing only basic fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots): [3](#0-2) 

Since these newly generated objects do NOT include `FinalOrderOfNextRound` or `OutValue` (which only exist in the current round's state), the validation check becomes `0 == 0`, which always passes. The validation should check `BaseRound` (current round from state) where miners who produced blocks have both fields properly set. [4](#0-3) 

Critically, the `Order` field itself is never validated against `FinalOrderOfNextRound`. The NextRoundInput is directly converted and added to state without verifying Order assignments match cryptographic signature-derived values: [5](#0-4) 

The only other NextRound validation (`RoundTerminateValidationProvider`) checks round number increment and null InValues, not Order correctness: [6](#0-5) 

The `Order` field directly determines `ExpectedMiningTime` in the mining schedule, giving early positions significant advantages.

**Attack Execution:**
1. Miner obtains legitimate next round data via `GetConsensusExtraData` [7](#0-6) 
2. Modifies Order values in RealTimeMinersInformation before creating NextRoundInput
3. Submits modified NextRoundInput via public NextRound method [8](#0-7) 
4. Validation passes (checks meaningless fields in wrong round)
5. Modified Order values committed to state via ProcessNextRound [9](#0-8) 

## Impact Explanation
**Consensus Integrity Violation**: This vulnerability breaks the fundamental fairness mechanism of AEDPoS consensus. The protocol design ensures miners earn their next round position deterministically through signature randomness. An attacker can instead:

1. Assign favorable early positions (Order=1,2,3) to themselves or colluding parties
2. Push legitimate high-performing miners to disadvantaged later positions  
3. Manipulate the entire mining schedule for the next round

**Secondary Effects:**
- Mining order affects block production timing and opportunities
- Early positions have advantage in producing blocks before others
- Order influences extra block producer selection for subsequent rounds (calculated from first miner's signature)
- Rewards and transaction fee collection opportunities are distributed unfairly

**Affected Parties**: All miners in the consensus system, as the manipulated schedule affects when each miner can produce blocks and their expected rewards.

## Likelihood Explanation
**Attacker Capabilities**: Any miner can execute this attack. The PreCheck only validates miner list membership, not specific authorization for NextRound transitions. [10](#0-9)  While extra block producers typically call NextRound, any miner has access.

**Attack Complexity**: Very low. The attacker:
1. Calls GetConsensusExtraData to obtain legitimately generated next round data
2. Modifies Order field values in the RealTimeMinersInformation dictionary  
3. Submits the modified NextRoundInput to the public NextRound method

**Feasibility**: Extremely high. The validation flaw is structural - it checks fields that are always 0/null by design in the next round. There is no secondary validation of Order assignments. The attack works every time.

**Detection Difficulty**: Hard to detect without off-chain monitoring that recomputes expected Order assignments and compares with submitted values. The manipulated round appears structurally valid (correct round number, null InValues, proper miner count).

**Economic Rationality**: Highly rational for any miner seeking competitive advantage. Better mining positions translate directly to more block production opportunities and rewards.

## Recommendation
Fix the validation logic to check the correct round data and validate Order assignments:

1. **Fix NextRoundMiningOrderValidationProvider** to check BaseRound instead of ProvidedRound:
   - Change validation to check `validationContext.BaseRound` for FinalOrderOfNextRound and OutValue
   - This ensures the check validates current round state where these fields are properly set

2. **Add Order correctness validation**:
   - Add validation that verifies each miner's Order in ProvidedRound matches their FinalOrderOfNextRound from BaseRound
   - Iterate through miners and ensure: `ProvidedRound.RealTimeMinersInformation[pubkey].Order == BaseRound.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound`

3. **Strengthen PreCheck authorization**:
   - Consider restricting NextRound calls to specifically the extra block producer, not just any miner

## Proof of Concept
A proof of concept would demonstrate:
1. Calling `GetConsensusExtraData` to obtain legitimate next round data
2. Modifying the Order field in RealTimeMinersInformation (e.g., swapping Order=1 and Order=5)
3. Creating NextRoundInput with modified data
4. Calling `NextRound(modifiedInput)` 
5. Verifying validation passes despite incorrect Order values
6. Confirming modified Order values are stored in state
7. Observing that ExpectedMiningTime is calculated from manipulated Order, affecting the mining schedule

The vulnerability is confirmed by code inspection showing the validation checks ProvidedRound (which lacks the necessary fields) rather than BaseRound (which contains proper FinalOrderOfNextRound and OutValue data from miners' cryptographic signatures).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-21)
```csharp
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-34)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

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

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
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
