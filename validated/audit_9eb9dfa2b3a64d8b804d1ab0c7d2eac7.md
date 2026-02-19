# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Manipulation

## Summary
The `ValidationForNextTerm()` function fails to verify that the proposed miner list matches actual election results from the Election Contract. A malicious block producer in the current term can propose a `NextTerm` transaction with an arbitrary miner list during their extra block time slot, bypassing consensus integrity checks and achieving complete control over the next term's consensus.

## Finding Description

The AEDPoS consensus contract has a critical validation gap when processing NextTerm transitions. The validation logic only verifies structural correctness (round/term number increments, null InValues) but completely omits verification of the most critical component - the miner list itself.

**Validation Gap:**
When a NextTerm transaction is validated, only the `RoundTerminateValidationProvider` is applied. [1](#0-0)  This validator only checks that round and term numbers increment correctly and that InValues are null. [2](#0-1) 

**Missing Election Verification:**
In the honest path, `GenerateFirstRoundOfNextTerm()` correctly retrieves election winners via `TryToGetVictories()`, which calls the Election Contract to get legitimately elected miners. [3](#0-2)  The `TryToGetVictories()` method specifically queries election results. [4](#0-3) 

**Exploitation Mechanism:**
Once validation passes, `ProcessNextTerm()` directly extracts the miner list from the input and stores it in state without any verification against election results. [5](#0-4)  The miner list is permanently stored for the term. [6](#0-5) 

**Insufficient Access Control:**
The `PreCheck()` function only verifies that the sender is in the current or previous miner list, but does not validate the content of the proposed new miner list. [7](#0-6) 

**Attack Flow:**
1. A malicious miner in the current term waits for their extra block time slot
2. Instead of using the honest `GenerateFirstRoundOfNextTerm()`, they craft a malicious `NextTermInput` with arbitrary miners
3. They set correct round/term numbers and null InValues to pass validation
4. The malicious miner list includes only themselves or colluding nodes
5. Validation passes as no election result check exists
6. The fraudulent miner list is stored and becomes authoritative for the entire next term

## Impact Explanation

**Critical Consensus Compromise:**
- The attacker achieves complete control over consensus for the entire next term (potentially weeks/months based on `PeriodSeconds` configuration)
- Legitimately elected miners are excluded from block production and lose all associated rewards
- The democratic election mechanism is completely nullified - token holders' votes become meaningless
- Network security is compromised as the attacker controls which transactions are included/excluded

**Quantified Damage:**
- All mining rewards for the compromised term flow to unauthorized miners
- The attacker can censor specific transactions, manipulate contract states, or halt chain progress
- Election snapshots record the fraudulent miner list, corrupting historical consensus records [8](#0-7) 
- Recovery requires emergency governance intervention or potentially a chain fork

**Affected Parties:**
- Legitimately elected miners lose block production rights and income
- Token holders who voted have their democratic participation nullified  
- dApp users face potential censorship or service unavailability
- The entire AElf network's security and decentralization guarantees are violated

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a miner in the current term (achievable through prior legitimate election)
- No special privileges required beyond being a current block producer
- Attack executes during the extra block time slot, which is part of normal consensus flow

**Attack Complexity:**
- Very low - attacker simply crafts a `NextTermInput` with their desired miner list
- Setting correct round/term numbers is trivial (just increment by 1)
- Setting InValues to null is trivial
- No cryptographic attacks, timing manipulation, or race conditions required

**Execution Certainty:**
- Validation is guaranteed to pass as demonstrated by code analysis
- No randomness or external dependencies that could cause failure
- Single transaction execution - no multi-step coordination needed
- Detection is difficult as the transaction appears structurally valid

**Practical Feasibility:**
- Any miner who becomes malicious can execute this attack
- The extra block producer for term transition has guaranteed opportunity
- No off-chain coordination or infrastructure beyond normal mining required

**Overall Probability:** High - The attack is straightforward, requires minimal sophistication, and has guaranteed success if the attacker is the designated extra block producer during term transition.

## Recommendation

Add miner list validation to `ValidationForNextTerm()` or `ProcessNextTerm()`:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Existing term number check
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // NEW: Validate miner list against election results
    if (State.IsMainChain.Value)
    {
        var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
        var proposedMiners = extraData.Round.RealTimeMinersInformation.Keys.Select(k => 
            ByteStringHelper.FromHexString(k)).ToHashSet();
        
        if (!expectedVictories.Value.ToHashSet().SetEquals(proposedMiners))
            return new ValidationResult { Message = "Proposed miner list does not match election results." };
    }
    
    return new ValidationResult { Success = true };
}
```

This ensures that only legitimately elected miners can be included in the next term, preserving the integrity of the election-based consensus mechanism.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanManipulateNextTermMinerList()
{
    // Setup: Current term with miners A, B, C
    // Election results show winners should be D, E, F for next term
    
    // Malicious miner A crafts NextTermInput with arbitrary list (only A)
    var maliciousNextTermInput = new NextTermInput
    {
        Round = CreateRoundWithOnlyMinerA(), // Only includes attacker
        RandomNumber = GenerateValidRandomNumber()
    };
    
    // Set correct round/term numbers to pass validation
    maliciousNextTermInput.Round.RoundNumber = currentRound + 1;
    maliciousNextTermInput.Round.TermNumber = currentTerm + 1;
    
    // Set all InValues to null to pass validation
    foreach (var miner in maliciousNextTermInput.Round.RealTimeMinersInformation)
        miner.Value.InValue = null;
    
    // Execute during extra block time slot
    var result = await ConsensusStub.NextTerm.SendAsync(maliciousNextTermInput);
    
    // Validation passes - no election check exists
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify malicious miner list was stored
    var storedMinerList = await ConsensusStub.GetCurrentMinerList.CallAsync(new Empty());
    storedMinerList.Pubkeys.Count.ShouldBe(1); // Only attacker
    storedMinerList.Pubkeys[0].ShouldBe(attackerPubkey); // Not election winners D, E, F
    
    // Election results were bypassed - legitimately elected miners excluded
    var electionWinners = await ElectionStub.GetVictories.CallAsync(new Empty());
    electionWinners.Value.ShouldNotContain(attackerPubkey); // Attacker wasn't elected
}
```

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-242)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
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
