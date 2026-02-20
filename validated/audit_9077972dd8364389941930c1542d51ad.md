# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Takeover Through Arbitrary Miner Selection

## Summary
The `NextTerm` consensus transaction processing lacks validation that the miner list in `NextTermInput` matches election results from `GetVictories`. A malicious current miner can submit a crafted `NextTermInput` with an arbitrary miner list that passes validation (which only checks term/round number increments), allowing them to bypass the election mechanism and seize permanent control of consensus by excluding legitimately elected miners.

## Finding Description

The vulnerability exists in the validation and processing flow for term transitions in the AEDPoS consensus contract.

**Insufficient Validation:**

The `ValidationForNextTerm` method only validates term and round number increments but does not verify the miner list against election results. [1](#0-0) 

When `NextTerm` consensus transactions are validated via `ValidateConsensusBeforeExecution`, only the `RoundTerminateValidationProvider` is added for NextTerm behavior. [2](#0-1) 

**Unverified Miner List Acceptance:**

The `ProcessNextTerm` method extracts the miner list directly from the input's `RealTimeMinersInformation.Keys` and sets it via `SetMinerList` without any verification against election results. [3](#0-2) 

The `SetMinerList` function only checks if the term's miner list hasn't been set previously, performing no validation against election results. [4](#0-3) 

**Contrast with Legitimate Flow:**

The legitimate term generation process calls `GenerateFirstRoundOfNextTerm`, which queries election results via `TryToGetVictories` to obtain the correct miner list from the Election contract. [5](#0-4) 

The `TryToGetVictories` method retrieves the elected miners from the Election contract. [6](#0-5) 

However, this election verification only occurs when generating consensus data through `GetConsensusExtraDataForNextTerm`, not during validation of submitted `NextTermInput`. [7](#0-6) 

**Why Existing Protections Fail:**

The `PreCheck` permission verification only confirms the sender is in the current or previous miner list, which a malicious miner already satisfies. [8](#0-7) 

The `NextTerm` method is publicly callable with any crafted input structure. [9](#0-8) 

## Impact Explanation

**Severity: Critical - Complete Consensus Takeover**

A successful exploit achieves:

1. **Consensus Control**: The attacker can construct a miner list containing only themselves or colluding parties, gaining permanent control over all future block production
2. **Election Bypass**: Completely circumvents the democratic election mechanism where token holders vote for miners, rendering all voting meaningless
3. **Governance Manipulation**: Controls future governance by monopolizing block production and proposal submission
4. **Transaction Censorship**: Can selectively exclude transactions or manipulate block contents without competing miners
5. **Economic Disruption**: Monopolizes mining rewards that should be distributed based on election results

This breaks the fundamental security invariant that "miner lists for each term must correspond to election results" and destroys the integrity of the consensus mechanism. All token holders who voted, legitimately elected candidates, DApps, and users are affected.

## Likelihood Explanation

**High Likelihood - Simple Exploitation**

**Attacker Prerequisites:**
- Must be a current miner (obtainable through legitimate election initially)
- Ability to produce blocks and submit transactions
- No special cryptographic knowledge or computational resources required

**Attack Steps:**
1. Wait until term change conditions are met (normal consensus operation)
2. Craft a `NextTermInput` with correct term/round numbers but a malicious miner list
3. When scheduled to produce the term-changing block, include this malicious transaction
4. Validation passes (only checks numeric increments)
5. Malicious miner list is accepted and stored as the new consensus

**Exploitation Feasibility:**
- Single transaction required during the attacker's normal block production turn
- No race conditions or timing complexities  
- Deterministic validation checks easily satisfied
- Detection difficult as transaction appears structurally valid

The risk/reward ratio heavily favors attack execution: minimal cost (one transaction fee) versus massive benefit (permanent consensus control and reward monopolization).

## Recommendation

Add miner list validation in the `ValidationForNextTerm` method or `ValidateBeforeExecution` flow for NextTerm behavior. The validation should:

1. Query the Election contract's `GetVictories` to retrieve the legitimate elected miner list
2. Compare the miner list in the submitted `NextTermInput.RealTimeMinersInformation.Keys` against the election results
3. Reject the transaction if the lists don't match (allowing only for legitimate miner replacements tracked by the Election contract)

Alternative fix: Add validation in `ProcessNextTerm` before calling `SetMinerList` to verify against election results, similar to how `GenerateFirstRoundOfNextTerm` retrieves and uses the correct miner list.

## Proof of Concept

The vulnerability can be exploited through the following sequence:

1. Attacker is elected as a legitimate miner in the current term
2. When the term is about to end, instead of using the honest `GetConsensusExtraDataForNextTerm` flow that queries election results, the attacker crafts a custom `NextTermInput`:
   - Sets `TermNumber` to current term + 1 (passes validation)
   - Sets `RoundNumber` to current round + 1 (passes validation)
   - Sets `RealTimeMinersInformation` to only contain their own public key (bypasses elections)
3. During their scheduled block production time when term change should occur, they submit this malicious `NextTerm` transaction
4. The transaction passes all validations (PreCheck verifies they're a current miner, RoundTerminateValidationProvider only checks numbers)
5. `ProcessNextTerm` executes and calls `SetMinerList` with the attacker's malicious list
6. The attacker is now the sole miner for all future terms, having bypassed the election mechanism entirely

**Notes:**
- This vulnerability fundamentally breaks the AEDPoS consensus security model by allowing miners to self-appoint rather than being elected by token holders
- The issue exists because validation is split between data generation (which queries elections) and data validation (which does not), creating a gap that malicious miners can exploit
- Once exploited, recovery would be extremely difficult as the attacker controls all future block production and can censor any remediation attempts

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-210)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
```
