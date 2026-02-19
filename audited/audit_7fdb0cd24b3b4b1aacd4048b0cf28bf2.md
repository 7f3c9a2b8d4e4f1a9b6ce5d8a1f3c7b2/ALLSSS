# Audit Report

## Title
First-Time Miners Can Claim Welcome Rewards Through Pubkey Replacement

## Summary
A first-time miner can replace their public key during their first term and the replacement pubkey will incorrectly receive welcome rewards at term end. This occurs because the replacement pubkey inherits `LatestMinedTerm = 0` from the original pubkey, causing it to be misidentified as a new miner and added as a beneficiary for welcome rewards.

## Finding Description

The vulnerability exists in the interaction between three contract functions across the Election, Consensus, and Treasury contracts:

**Step 1: Pubkey Replacement During First Term**

When a miner calls `ReplaceCandidatePubkey` during their first term, the Election contract notifies the Consensus contract via `RecordCandidateReplacement`. [1](#0-0) 

The Consensus contract updates the current round to replace the old pubkey with the new pubkey in `RealTimeMinersInformation` and persists this change to storage. [2](#0-1) 

**Step 2: Treasury Transfer Without Validation**

The Consensus contract then notifies the Treasury contract by calling `RecordMinerReplacement`. Critically, it never sets the `IsOldPubkeyEvil` field, which defaults to `false` in protobuf. [3](#0-2) 

The protobuf definition confirms `is_old_pubkey_evil` is a boolean field: [4](#0-3) 

The Treasury contract's `RecordMinerReplacement` function transfers the `LatestMinedTerm` value from the old pubkey to the new pubkey without validating whether the old pubkey has completed any mining terms. For a first-time miner, this means transferring `LatestMinedTerm = 0` to the replacement pubkey. [5](#0-4) 

**Step 3: Misidentification as New Miner**

At term end, the `Release` function retrieves `previousTermInformation` from the Consensus contract. [6](#0-5) 

The `GetPreviousTermInformation` method retrieves the last round of the term from storage, which now contains the replacement pubkey (not the original) because the round was updated during the replacement. [7](#0-6) 

The `Release` function identifies new miners by checking if `LatestMinedTerm[p] == 0`. The replacement pubkey passes this check and is incorrectly added to the `newElectedMiners` list. [8](#0-7) 

**Step 4: Welcome Reward Allocation**

`UpdateWelcomeRewardWeights` is called with the replacement pubkey in the `newElectedMiners` list and adds it as a beneficiary for welcome rewards with 1 share. [9](#0-8) 

**Step 5: State Update**

Finally, `UpdateStateAfterDistribution` updates `LatestMinedTerm` for the replacement pubkey, preventing it from claiming welcome rewards again in future terms. [10](#0-9) 

The Treasury contract's initialization explicitly identifies welcome rewards as one of three sub-schemes under "Mining Reward", confirming their purpose as incentives for new miners. [11](#0-10) 

## Impact Explanation

**Direct Financial Impact**: The replacement pubkey receives welcome rewards that should only be distributed to genuinely new miners. This misallocates treasury funds from the welcome reward pool, which has a configurable weight in the miner reward distribution (default 1/4 of miner rewards).

**Affected Parties**: 
- Legitimate new miners receive diluted welcome rewards as the fixed pool is shared with illegitimate recipients
- The protocol's economic incentive model is violated as welcome rewards are designed as a one-time bonus for new participation

**Severity Assessment**: HIGH - This directly misallocates treasury funds, can be systematically exploited by any first-time miner, and undermines the protocol's intended economic incentive structure for onboarding new miners.

## Likelihood Explanation

**Attack Feasibility**: Any first-time elected miner can exploit this vulnerability. The miner must have the authority to call `ReplaceCandidatePubkey`, which requires being the candidate admin. [12](#0-11) 

**Attack Complexity**: LOW - The exploit requires only:
1. Being elected as a miner for the first time (legitimate participation)
2. Calling `ReplaceCandidatePubkey` during the first term
3. No race conditions or timing constraints beyond staying within the first term

**Detection Difficulty**: The exploitation is indistinguishable from legitimate pubkey replacements for operational security reasons (e.g., key rotation).

**Probability**: HIGH - First-time miners regularly join the network, and the vulnerability can be triggered either intentionally for extra rewards or accidentally during legitimate key rotation.

## Recommendation

Add validation in `RecordMinerReplacement` to check if the old pubkey has completed at least one mining term before transferring `LatestMinedTerm`:

```csharp
public override Empty RecordMinerReplacement(RecordMinerReplacementInput input)
{
    Assert(
        Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
        "Only AEDPoS Contract can record miner replacement.");

    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    if (!input.IsOldPubkeyEvil)
    {
        var latestMinedTerm = State.LatestMinedTerm[input.OldPubkey];
        
        // Only transfer if the old pubkey has actually mined at least one complete term
        if (latestMinedTerm > 0)
        {
            State.LatestMinedTerm[input.NewPubkey] = latestMinedTerm;
        }
        // If latestMinedTerm == 0, the new pubkey starts fresh and will be eligible
        // for welcome rewards as a genuinely new miner in a future term
        
        State.LatestMinedTerm.Remove(input.OldPubkey);
    }
    else
    {
        var replaceCandidates = State.ReplaceCandidateMap[input.CurrentTermNumber] ?? new StringList();
        replaceCandidates.Value.Add(input.NewPubkey);
        State.ReplaceCandidateMap[input.CurrentTermNumber] = replaceCandidates;
    }

    State.IsReplacedEvilMiner[input.NewPubkey] = true;

    return new Empty();
}
```

This ensures that replacement pubkeys only inherit the mining history if the original pubkey has actually completed a mining term, preventing first-time miners from exploiting the replacement mechanism to claim welcome rewards.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Deploying a test scenario where a first-time miner is elected in Term N
2. Having the miner call `ReplaceCandidatePubkey` during Term N
3. Triggering term end and observing that `Release` adds the replacement pubkey to welcome reward beneficiaries
4. Verifying that the replacement pubkey receives welcome rewards despite not being a genuinely new miner

**Notes**

This vulnerability specifically affects first-time miners during their first term of mining. Once a miner completes their first term and `LatestMinedTerm` is updated to a non-zero value, subsequent replacements will correctly transfer the mining history and the replacement pubkey will not qualify for welcome rewards.

The issue stems from the Treasury contract's assumption that `LatestMinedTerm = 0` always indicates a genuinely new miner, without accounting for the case where a replacement pubkey inherits this value from an original pubkey that hasn't completed a term yet.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-181)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L140-146)
```csharp
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L149-154)
```csharp
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });
```

**File:** protobuf/treasury_contract.proto (L154-159)
```text
message RecordMinerReplacementInput {
    string old_pubkey = 1;
    string new_pubkey = 2;
    int64 current_term_number = 3;
    bool is_old_pubkey_evil = 4;
}
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L28-34)
```csharp
///     (Mining Reward for Miners) - 3
///     (Subsidy for Candidates / Backups) - 1
///     (Welfare for Electors / Voters / Citizens) - 1
///     3 sub profit schemes for Mining Rewards:
///     (Basic Rewards) - 4
///     (Welcome Rewards) - 1
///     (Flexible Rewards) - 1
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L136-139)
```csharp
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L155-156)
```csharp
        maybeNewElectedMiners = maybeNewElectedMiners
            .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p)).ToList();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L583-588)
```csharp
        if (!input.IsOldPubkeyEvil)
        {
            var latestMinedTerm = State.LatestMinedTerm[input.OldPubkey];
            State.LatestMinedTerm[input.NewPubkey] = latestMinedTerm;
            State.LatestMinedTerm.Remove(input.OldPubkey);
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L766-769)
```csharp
    private void UpdateStateAfterDistribution(Round previousTermInformation, List<string> currentMinerList)
    {
        foreach (var miner in currentMinerList) State.LatestMinedTerm[miner] = previousTermInformation.TermNumber;
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L864-879)
```csharp
        if (newElectedMiners.Any())
        {
            Context.LogDebug(() => "Welcome reward will go to new miners.");
            var newBeneficiaries = new AddBeneficiariesInput
            {
                SchemeId = State.VotesWeightRewardHash.Value,
                EndPeriod = previousTermInformation.TermNumber.Add(1)
            };
            foreach (var minerAddress in newElectedMiners.Select(GetProfitsReceiver))
                newBeneficiaries.BeneficiaryShares.Add(new BeneficiaryShare
                {
                    Beneficiary = minerAddress,
                    Shares = 1
                });

            if (newBeneficiaries.BeneficiaryShares.Any()) State.ProfitContract.AddBeneficiaries.Send(newBeneficiaries);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L440-456)
```csharp
    public override Round GetPreviousTermInformation(Int64Value input)
    {
        var lastRoundNumber = State.FirstRoundNumberOfEachTerm[input.Value.Add(1)].Sub(1);
        var round = State.Rounds[lastRoundNumber];
        if (round == null || round.RoundId == 0) return new Round();
        var result = new Round
        {
            TermNumber = input.Value
        };
        foreach (var minerInRound in round.RealTimeMinersInformation)
            result.RealTimeMinersInformation[minerInRound.Key] = new MinerInRound
            {
                Pubkey = minerInRound.Value.Pubkey,
                ProducedBlocks = minerInRound.Value.ProducedBlocks
            };

        return result;
```
