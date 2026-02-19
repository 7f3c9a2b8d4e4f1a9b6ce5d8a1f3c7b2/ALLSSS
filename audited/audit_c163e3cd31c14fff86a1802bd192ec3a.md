# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Takeover via Malicious NextTermInput Injection

## Summary
The `NextTerm` method in the AEDPoS consensus contract accepts arbitrary miner lists from `NextTermInput` without validating them against the Election contract's `GetVictories` results. Any current or previous round miner can submit a malicious `NextTermInput` containing an arbitrary miner list, completely hijacking the consensus mechanism and bypassing the democratic election process.

## Finding Description

The AEDPoS consensus contract's `NextTerm` method is a public entry point that processes term transitions. [1](#0-0) 

The method delegates to `ProcessConsensusInformation`, which performs authorization via `PreCheck()`. However, this check only verifies that the sender is in the current OR previous round's miner list - it does not validate the content of the input. [2](#0-1) 

The validation for `NextTerm` behavior only adds `RoundTerminateValidationProvider`, which validates that term and round numbers increment by 1 and that InValues are null. [3](#0-2) 

Examining the actual validation logic confirms it NEVER checks the miner list: [4](#0-3) 

The vulnerable execution path in `ProcessNextTerm` directly extracts the miner list from the unvalidated input and sets it as the new miner list without any comparison to Election contract results: [5](#0-4) 

In contrast, the legitimate method `GenerateFirstRoundOfNextTerm` properly retrieves election winners by calling the Election contract's `GetVictories` method: [6](#0-5)  and [7](#0-6) 

The code contains a comment referencing a `ConstrainedAEDPoSTransactionValidationProvider` that should prevent malicious consensus transactions at the transaction pool level, but this provider does not exist in the codebase (verified via grep search showing only one comment reference, no implementation).

The `EnsureTransactionOnlyExecutedOnceInOneBlock` check only prevents duplicate execution within the same block, not malicious input: [8](#0-7) 

## Impact Explanation

**Complete Consensus Takeover:**
- An attacker who is (or was) a legitimate miner gains absolute control over block production by injecting an arbitrary miner list containing only attacker-controlled addresses
- All legitimate validators can be permanently excluded from consensus participation
- The entire Election contract voting mechanism becomes meaningless as its results are bypassed
- Subsequent blocks and all consensus decisions are controlled by the attacker

**Financial Impact:**
- Direct control over mining reward distribution through the `DonateMiningReward` flow [9](#0-8) 
- Authority over treasury releases tied to term transitions [10](#0-9) 
- Complete control over which transactions get included in blocks, enabling censorship or transaction ordering attacks

**Governance Integrity:**
- Violates the core protocol invariant that miners must be elected through democratic voting
- Attackers can maintain indefinite control by repeatedly calling `NextTerm` with their own miner list for subsequent terms
- Cross-chain security is compromised if sidechains rely on the mainchain miner set for security assumptions

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a current or previous round miner (achievable through legitimate election in one term, or by compromising a single miner's private key)
- Must have ability to submit transactions or produce blocks (inherent capability of being a miner)

**Attack Complexity:**
LOW - The attacker simply needs to:
1. Craft a `NextTermInput` with `TermNumber = currentTerm + 1`, `RoundNumber = currentRound + 1`
2. Populate `RealTimeMinersInformation` with only attacker-controlled miner addresses
3. Set all `InValue` fields to null (required by validation)
4. Submit transaction calling `NextTerm(maliciousInput)` or include it when producing their assigned block

**Feasibility:**
HIGH - No cryptographic challenges, race conditions, or complex state manipulation required. The attack succeeds if:
- The attacker produces the block during the term transition window, OR
- The attacker's transaction gets included first by another miner who is unaware of the attack

**Detection Difficulty:**
The malicious miner list will appear valid in contract state. Off-chain monitoring must actively compare the actual miner list with Election contract's `GetVictories` results to detect the attack. The `TakeSnapshot` call doesn't validate this. [11](#0-10) 

**Overall Probability:**
HIGH - Once any miner becomes malicious or is compromised, the attack is trivial to execute and causes permanent protocol damage requiring manual intervention or a hard fork to recover.

## Recommendation

Add validation in `ProcessNextTerm` to verify the miner list matches Election contract results:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // ADDED: Validate miner list against Election contract
    if (State.IsMainChain.Value && State.ElectionContract.Value != null)
    {
        var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
        var expectedMiners = new HashSet<string>(
            expectedVictories.Value.Select(pk => pk.ToHex()));
        var providedMiners = new HashSet<string>(
            nextRound.RealTimeMinersInformation.Keys);
        
        Assert(
            expectedMiners.SetEquals(providedMiners),
            "Miner list in NextTermInput does not match Election contract winners.");
    }
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of existing code
}
```

Additionally, implement the referenced `ConstrainedAEDPoSTransactionValidationProvider` at the transaction pool level to provide defense-in-depth.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanHijackConsensus_Test()
{
    // Setup: Initialize consensus with legitimate miners
    var initialMiners = await InitializeConsensusWithMiners(3);
    var maliciousMiner = initialMiners[0];
    
    // Attacker is currently a valid miner
    var currentTerm = await GetCurrentTermNumber();
    var currentRound = await GetCurrentRoundNumber();
    
    // Craft malicious NextTermInput with only attacker-controlled miners
    var maliciousInput = new NextTermInput
    {
        TermNumber = currentTerm + 1,
        RoundNumber = currentRound + 1,
        RealTimeMinersInformation = 
        {
            // Only attacker's address, excluding all legitimate miners
            { maliciousMiner.PublicKey.ToHex(), new MinerInRound { /* ... */ } }
        },
        // InValues must be null to pass validation
        RandomNumber = GenerateRandomNumber(maliciousMiner)
    };
    
    // Execute attack
    var result = await maliciousMiner.ExecuteConsensusTransaction(
        nameof(AEDPoSContract.NextTerm), 
        maliciousInput);
    
    // Verify attack succeeded
    result.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // VULNERABLE: Miner list is now controlled by attacker
    var newMinerList = await GetCurrentMinerList();
    newMinerList.Pubkeys.Count.ShouldBe(1);
    newMinerList.Pubkeys[0].ToHex().ShouldBe(maliciousMiner.PublicKey.ToHex());
    
    // Legitimate miners from Election contract are bypassed
    var electionWinners = await GetElectionVictories();
    electionWinners.Value.Count.ShouldBe(3); // Election says 3 miners
    // But consensus only has 1 - the attacker!
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-232)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-280)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```
