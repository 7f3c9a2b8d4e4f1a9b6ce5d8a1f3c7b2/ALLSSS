# Audit Report

## Title
Missing Period Expiration Validation Allows Premature Term Changes

## Summary
The AEDPoS consensus validation logic contains a critical gap where term change conditions are checked during command generation but not re-validated during block validation. A malicious miner can bypass the 2/3+1 Byzantine fault tolerance requirement by providing `NextTerm` behavior in trigger information, forcing premature term changes without proper consensus.

## Finding Description

The AEDPoS consensus mechanism exhibits a dangerous separation between advisory command generation and enforcement validation, creating an exploitable validation gap.

**Command Generation (Advisory):**

During command generation, `MainChainConsensusBehaviourProvider` correctly determines whether to transition terms by calling `NeedToChangeTerm()`: [1](#0-0) 

The `NeedToChangeTerm()` method properly validates that at least 2/3+1 miners (`MinersCountOfConsent`) have mined blocks in the new term period based on period expiration: [2](#0-1) 

Where `MinersCountOfConsent` correctly calculates the 2/3+1 threshold: [3](#0-2) 

**Validation Phase (Enforcement Gap):**

However, when validating blocks, the validation logic does NOT re-check these consensus conditions. For `NextTerm` behavior, the validation only adds `RoundTerminateValidationProvider`: [4](#0-3) 

This provider only validates structural correctness (term number incremented, round number incremented), but does NOT verify `NeedToChangeTerm()` conditions: [5](#0-4) 

**Attack Execution:**

The trigger information containing the behavior field is provided as INPUT to `GetConsensusExtraData`: [6](#0-5) 

A malicious miner controlling their node software can:
1. Call `GetConsensusCommand` (which recommends `NextRound`)
2. Construct `AElfConsensusTriggerInformation` with `Behaviour = NextTerm` 
3. Call `GetConsensusExtraData` with the malicious trigger information
4. Produce a block that forces term transition
5. Block passes validation since structural checks succeed

## Impact Explanation

This vulnerability has **CRITICAL** impact with multiple severe consequences:

**1. Consensus Integrity Violation:** The fundamental 2/3+1 Byzantine fault tolerance guarantee is completely bypassed. A single miner can unilaterally force term changes, breaking the core safety property of AEDPoS consensus.

**2. Premature Treasury Releases:** Term changes unconditionally trigger treasury fund releases, causing incorrect financial distributions: [7](#0-6) 

**3. Manipulated Election Snapshots:** Election snapshots are captured with incomplete miner performance data, corrupting the governance state used for future miner selection: [8](#0-7) 

**4. Reward Misallocation:** Mining rewards are calculated and donated based on premature round data: [9](#0-8) 

**5. Governance Disruption:** Miner list updates occur prematurely, cascading into voting power distribution and future consensus participation integrity.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Prerequisites:**
- Must be an active miner in current round (normal operational requirement)
- No additional economic stake or privileges required

**Attack Complexity:** 
- LOW - Attacker modifies their node software to override behavior in trigger information
- No complex timing or coordination needed
- Single transaction execution

**Detection Difficulty:**
- Attack appears as legitimate consensus state transition
- All validation checks pass
- No obvious on-chain indicators

**Verification:** The codebase search confirms `NeedToChangeTerm` is ONLY invoked during command generation, never during validation, making this vulnerability definitively exploitable by any active miner.

## Recommendation

Add validation to re-check `NeedToChangeTerm()` conditions during the block validation phase. Specifically, modify `RoundTerminateValidationProvider.ValidationForNextTerm()` to validate:

1. Period has expired based on blockchain start timestamp
2. At least 2/3+1 miners have mined in the new term period
3. Current time justifies the term transition

The validation should mirror the logic in `MainChainConsensusBehaviourProvider` to ensure enforcement matches the advisory conditions. This closes the gap between command generation (advisory) and validation (enforcement).

## Proof of Concept

The vulnerability is proven by code inspection showing:

1. `NeedToChangeTerm()` exists and checks 2/3+1 consensus + period expiration
2. This check occurs ONLY in `MainChainConsensusBehaviourProvider` (command generation)  
3. `RoundTerminateValidationProvider` does NOT call `NeedToChangeTerm()` during validation
4. Trigger information is miner-controlled input to `GetConsensusExtraData`
5. A malicious miner can provide `Behaviour = NextTerm` regardless of actual conditions
6. Block validation will pass structural checks without verifying consensus requirements
7. `ProcessNextTerm` executes treasury releases, election snapshots, and reward distributions

The attack requires only modifying node software to inject `NextTerm` behavior in trigger information, which is within any miner's capability as they control their own node infrastructure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L13-27)
```csharp
    private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);

        Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");

        TryToGetCurrentRoundInformation(out var currentRound);

        var publicKeyBytes = triggerInformation.Pubkey;
        var pubkey = publicKeyBytes.ToHex();

        var information = new AElfConsensusHeaderInformation();
        switch (triggerInformation.Behaviour)
        {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```
