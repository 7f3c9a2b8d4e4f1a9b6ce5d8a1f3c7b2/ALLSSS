# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Manipulation

## Summary
The `NextTerm` validation logic fails to verify that the proposed miner list matches election results from the Election Contract. A malicious current miner can directly call the `NextTerm` RPC method with an arbitrary miner list, bypassing the intended election-based consensus mechanism and achieving complete control over the next term's block production.

## Finding Description

The AEDPoS consensus contract exposes `NextTerm` as a public RPC method [1](#0-0)  that accepts a `NextTermInput` containing the full miner list for the next term. The validation for NextTerm transitions only applies the `RoundTerminateValidationProvider` [2](#0-1) , which exclusively validates structural correctness [3](#0-2) : round number increment, term number increment, and null InValues. 

**The Critical Gap:** No validation verifies that the miner list in the input matches the actual election winners from the Election Contract.

The honest execution path shows the intended design: `GenerateFirstRoundOfNextTerm` retrieves election winners via `TryToGetVictories` [4](#0-3) , which calls the Election Contract [5](#0-4) . However, since `NextTerm` is a public method, attackers can bypass this honest path entirely.

**Exploitation Mechanism:** When `ProcessNextTerm` executes, it directly extracts the miner list from the input [6](#0-5)  and permanently stores it [7](#0-6) . The only access control is `PreCheck()`, which merely verifies the sender is a current or previous miner [8](#0-7)  without validating the proposed miner list content.

**Attack Execution:**
1. Malicious current miner crafts a `NextTermInput` with arbitrary miners in `RealTimeMinersInformation`
2. Sets `RoundNumber = current + 1`, `TermNumber = current + 1`, and `InValues = null` (to pass structural validation)
3. Directly calls the public `NextTerm` method [9](#0-8) 
4. Validation passes since only structure is checked
5. Fraudulent miner list is stored and becomes authoritative for the entire next term

## Impact Explanation

**Complete Consensus Compromise:** The attacker achieves total control over block production for the entire next term (duration determined by `PeriodSeconds` configuration, typically weeks or months). Legitimately elected miners are excluded from consensus participation and lose all associated mining rewards.

**Democratic Nullification:** The Election Contract's purpose is completely subverted. Token holders' votes become meaningless as the election results are ignored. The decentralized governance model that should determine miner selection is bypassed.

**Economic Impact:** All mining rewards for the compromised term are redirected to unauthorized miners. The attacker controls transaction inclusion/exclusion, enabling censorship attacks, state manipulation, or complete chain halt.

**Historical Corruption:** Election snapshots record the fraudulent miner list [10](#0-9) , corrupting the historical consensus record. Recovery requires emergency governance intervention or potentially a chain fork.

**Network Security:** The attacker controls which transactions are processed, enabling sophisticated attacks including selective censorship of governance proposals, targeted DoS of specific users, and manipulation of time-sensitive contracts.

## Likelihood Explanation

**Low Attack Barriers:** Any current miner can execute this attack. The prerequisite (being a current miner) is achievable through legitimate election in a prior term. No special privileges, cryptographic attacks, or timing manipulation are required.

**Trivial Execution:** The attack requires only crafting a `NextTermInput` with correct structural fields (round/term number increments by 1, null InValues) and arbitrary miner list. This is straightforward data structure manipulation with no complex coordination.

**Guaranteed Success:** Validation checks are deterministic and do not query the Election Contract. If the attacker is producing a block during term transition, the transaction will pass validation with certainty. There are no randomness factors, external dependencies, or race conditions that could cause failure.

**Detection Difficulty:** The malicious transaction appears structurally valid and passes all implemented validation checks. Without external monitoring of election results versus actual miner lists, detection is challenging.

**High Practical Feasibility:** The extra block producer for term transition has guaranteed opportunity to include their malicious NextTerm transaction. No off-chain infrastructure beyond normal mining capabilities is required.

## Recommendation

Add miner list verification to the validation logic. The fix should be implemented in `RoundTerminateValidationProvider.ValidationForNextTerm`:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Is next term number correct?
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // NEW: Verify miner list matches election results (for main chain)
    if (State.IsMainChain.Value)
    {
        var electionWinners = State.ElectionContract.GetVictories.Call(new Empty());
        var proposedMiners = extraData.Round.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var electedMiners = electionWinners.Pubkeys.Select(p => p.ToHex()).OrderBy(k => k).ToList();
        
        if (proposedMiners.Count != electedMiners.Count || 
            !proposedMiners.SequenceEqual(electedMiners))
        {
            return new ValidationResult 
            { 
                Message = "Proposed miner list does not match election results." 
            };
        }
    }
    
    return new ValidationResult { Success = true };
}
```

Alternatively, implement the check in `ProcessNextTerm` before storing the miner list to ensure defense in depth.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanInjectArbitraryMinerList()
{
    // Setup: Initialize chain with legitimate miners from election
    await InitializeConsensusContract();
    var legitimateMiners = await GetElectionWinners();
    
    // Current miner (attacker) is part of current term
    var attackerKeyPair = legitimateMiners[0];
    
    // Attacker crafts malicious NextTermInput with only themselves as miner
    var maliciousMiners = new Dictionary<string, MinerInRound>
    {
        {
            attackerKeyPair.PublicKey.ToHex(),
            new MinerInRound
            {
                Pubkey = attackerKeyPair.PublicKey.ToHex(),
                Order = 1,
                IsExtraBlockProducer = true,
                ExpectedMiningTime = TimestampHelper.GetUtcNow().AddSeconds(4000)
            }
        }
    };
    
    var currentRound = await GetCurrentRound();
    var maliciousInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber + 1,
        RealTimeMinersInformation = { maliciousMiners },
        RandomNumber = ByteString.CopyFrom(new byte[32]) // Valid random number
    };
    
    // Execute attack: Attacker calls NextTerm directly
    var result = await AEDPoSContractStub.NextTerm.SendAsync(maliciousInput);
    
    // Verify: Malicious miner list is now authoritative
    var newTermMiners = await GetMinerList(currentRound.TermNumber + 1);
    
    // VULNERABILITY: Only attacker is in miner list, legitimate election winners excluded
    Assert.Single(newTermMiners.Pubkeys);
    Assert.Equal(attackerKeyPair.PublicKey, newTermMiners.Pubkeys[0]);
    
    // Legitimate election winners are NOT in the miner list despite winning the election
    var electionWinners = await GetElectionWinners();
    Assert.True(electionWinners.Count > 1); // Multiple winners from election
    Assert.False(newTermMiners.Pubkeys.Count == electionWinners.Count); // But only 1 in actual miner list
}
```

### Citations

**File:** protobuf/aedpos_contract.proto (L38-38)
```text
    rpc NextTerm (NextTermInput) returns (google.protobuf.Empty) {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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
