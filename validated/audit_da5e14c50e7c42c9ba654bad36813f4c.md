# Audit Report

## Title
NextTerm Validation Bypasses Election Results Allowing Unauthorized Miner List Manipulation

## Summary
The NextTerm validation logic in the AEDPoS consensus contract fails to verify that the provided miner list matches election winners from `ElectionContract.GetVictories`. This allows a malicious block producer to inject an arbitrary miner list during term transitions, completely bypassing the democratic election mechanism that is fundamental to the consensus security model.

## Finding Description

The vulnerability exists because the validation path and execution path for NextTerm transitions are disconnected from the election system's verification.

**Honest Path vs Attack Path:**

The honest implementation generates NextTerm data by calling `GenerateFirstRoundOfNextTerm`, which retrieves election winners via `TryToGetVictories` from the Election Contract: [1](#0-0) [2](#0-1) 

However, the validation performed by `ValidationForNextTerm` only verifies that term and round numbers increment correctly, without any check that the miner list is legitimate: [3](#0-2) 

The validation infrastructure for NextTerm behavior only adds `RoundTerminateValidationProvider`, which performs no miner list validation: [4](#0-3) 

During execution, `ProcessNextTerm` blindly extracts the miner list from the provided input and sets it as official without validation: [5](#0-4) 

The `SetMinerList` method only checks if a miner list has already been set for that term, not whether the miners are legitimate election winners: [6](#0-5) 

**TOCTOU Vulnerability in Post-Execution Validation:**

The post-execution validation in `ValidateConsensusAfterExecution` retrieves `currentRound` from state AFTER `ProcessNextTerm` has already written the malicious miner list, creating a Time-of-Check-Time-of-Use vulnerability: [7](#0-6) 

Since the comparison happens after state corruption, the hashes match and validation passes.

**Mining Permission Check is Insufficient:**

The `MiningPermissionValidationProvider` validates that the sender is in the CURRENT term's miner list, not that the NEXT term's miner list is valid: [8](#0-7) 

## Impact Explanation

This vulnerability has **CRITICAL** impact because it breaks the fundamental security assumption of the AEDPoS consensus mechanism: that miners must be democratically elected by token holders.

**Consensus Integrity Violation:** The blockchain's security model depends on elected, accountable miners. Breaking this assumption compromises all consensus guarantees including finality, censorship resistance, and liveness.

**Permanent Governance Capture:** Current miners can maintain indefinite control by repeatedly injecting themselves into future terms, making token holder voting meaningless.

**Centralization Risk:** A small group of colluding miners can permanently capture the network without being subject to democratic accountability or rotation.

**Chain-wide Impact:** All network participants are affected since consensus integrity is the foundation of the entire system's security and trustworthiness.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **Low Privilege Barrier:** Any miner in the current term can execute this attack when producing a NextTerm block. No special keys or permissions beyond normal block production are required.

2. **Regular Attack Windows:** Term transitions occur periodically (every term), providing multiple opportunities for exploitation.

3. **Low Technical Complexity:** The attack only requires a miner to run modified node software that creates a `NextTermInput` with arbitrary miners in `RealTimeMinersInformation` instead of using election results.

4. **No Detection Mechanism:** There is no validation check that would detect or prevent a miner list that doesn't match election results. The protocol accepts any miner list that increments term numbers correctly.

5. **High Economic Motivation:** Miners facing election loss have strong incentives (mining rewards, transaction fees, network control) to retain their positions.

6. **Protocol-Level Vulnerability:** This is not about compromising external systems - the protocol validation rules themselves are insufficient to enforce the election invariant.

## Recommendation

Add validation in `ValidationForNextTerm` to verify the miner list against election results:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Verify term number increments
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // NEW: Verify miner list matches election results
    if (State.IsMainChain.Value)
    {
        var victories = State.ElectionContract.GetVictories.Call(new Empty());
        var providedMiners = extraData.Round.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var electedMiners = victories.Value.Select(v => v.ToHex()).OrderBy(k => k).ToList();
        
        if (!providedMiners.SequenceEqual(electedMiners))
            return new ValidationResult { Message = "Miner list does not match election results." };
    }
    
    return new ValidationResult { Success = true };
}
```

Additionally, fix the TOCTOU vulnerability by comparing against the round from the input/header rather than state:

```csharp
public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
{
    var headerInformation = new AElfConsensusHeaderInformation();
    headerInformation.MergeFrom(input.Value);
    
    // Use State.RoundBeforeLatestExecution instead of current state
    var roundBeforeExecution = State.RoundBeforeLatestExecution.Value;
    
    // Validate against pre-execution state, not post-execution state
    // ... rest of validation logic
}
```

## Proof of Concept

A complete PoC would require setting up an AElf testnet with:
1. An election with specific winners [F, G, H, I, J]
2. Current term miners [A, B, C, D, E] where A is malicious
3. Miner A modifies their node to create NextTermInput with [A, B, C, D, E] instead of election winners
4. Observe that the NextTerm block is accepted and term continues with [A, B, C, D, E]

The validation code can be traced through the files cited above to confirm no election result validation exists in the NextTerm path.

## Notes

This vulnerability represents a fundamental gap in consensus validation logic where the protocol fails to enforce a critical invariant. The honest implementation correctly uses election results, but the validation layer doesn't enforce this constraint, allowing malicious miners to bypass elections entirely. This is distinct from requiring compromised keys or breaking cryptography - it's a protocol-level validation gap that enables governance capture.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-242)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-190)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-127)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
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
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```
