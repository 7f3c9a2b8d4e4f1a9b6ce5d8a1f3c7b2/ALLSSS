# Audit Report

## Title
Duplicate Welcome Rewards via Pubkey Replacement During Non-Mining Periods

## Summary
A state synchronization vulnerability between the AEDPoS consensus contract and the Treasury contract allows miners to receive welcome rewards multiple times. When a candidate replaces their public key while not actively mining, the Treasury contract is not notified, leaving the new pubkey with `LatestMinedTerm == 0`, causing it to be incorrectly identified as a "new" miner eligible for welcome rewards.

## Finding Description

The vulnerability stems from a conditional notification pattern in the cross-contract interaction between Election, AEDPoS, and Treasury contracts that breaks state synchronization.

**Root Cause:**

When the Election contract processes a pubkey replacement via `ReplaceCandidatePubkey`, it unconditionally notifies the AEDPoS consensus contract regardless of whether the old pubkey is currently mining. [1](#0-0) 

However, the AEDPoS contract's `RecordCandidateReplacement` method contains a critical conditional check that only proceeds with state updates and Treasury notification when the old pubkey exists in the current round's miner list. [2](#0-1) 

When this condition fails (old pubkey not in current round), the method returns early without calling Treasury's `RecordMinerReplacement`. [3](#0-2) 

This breaks state synchronization because the Treasury contract relies on being notified to transfer the `LatestMinedTerm` value from the old pubkey to the new pubkey. [4](#0-3)  The `LatestMinedTerm` mapping tracks each miner's latest term to distinguish veteran miners from new ones. [5](#0-4) 

**New Miner Detection:**

During reward distribution in the `Release` method, the Treasury contract identifies new miners by checking if their `LatestMinedTerm` equals 0 and they're not in the initial miner list. [6](#0-5) 

**Welcome Reward Distribution:**

New miners identified by this check receive welcome rewards through the `UpdateWelcomeRewardWeights` method, which adds them as beneficiaries to the `VotesWeightRewardHash` profit scheme with 1 share each. [7](#0-6) 

**Why Existing Protections Fail:**

The Election contract's `ReplaceCandidatePubkey` method only validates that the old pubkey is a candidate or initial miner and that neither pubkey is banned, plus permission checks for the candidate admin. [8](#0-7)  It does not validate whether the replacement should occur based on current mining status.

The old pubkey is banned to prevent reuse, [9](#0-8)  but this doesn't prevent the new pubkey from being treated as new by the Treasury contract because the `LatestMinedTerm` state transfer never occurs when the notification is skipped.

**Attack Path:**

1. Attacker registers as candidate with `pubkey_A`, gets elected, receives welcome rewards (legitimate first-time)
2. After mining one or more terms, `LatestMinedTerm[pubkey_A]` is set to a non-zero value
3. Attacker waits until `pubkey_A` is NOT elected in a future term (not in current round's miner list)
4. Attacker calls `ReplaceCandidatePubkey(pubkey_A, pubkey_B)` as the candidate admin
5. AEDPoS's `RecordCandidateReplacement` checks if `pubkey_A` is in current round, finds it's not, and returns early
6. Treasury's `RecordMinerReplacement` is never called
7. Result: `LatestMinedTerm[pubkey_A]` retains its value, but `LatestMinedTerm[pubkey_B]` remains at default value 0
8. Attacker gets `pubkey_B` elected in a subsequent term
9. Treasury's `Release` method identifies `pubkey_B` as a new miner because `LatestMinedTerm[pubkey_B] == 0`
10. Welcome rewards are granted again to the same entity through a different pubkey

## Impact Explanation

This vulnerability has significant economic impact on the AElf blockchain's reward distribution system:

**Direct Financial Impact:**
- Attackers can claim welcome rewards from the `VotesWeightRewardHash` profit scheme multiple times by exploiting the state synchronization gap
- Each duplicate claim grants beneficiary shares in the welcome reward pool for an entire term
- The welcome reward pool is funded according to `MinerRewardWeightSetting.WelcomeRewardWeight` proportions from the overall miner reward allocation

**Affected Parties:**
- Legitimate new miners receive diluted welcome rewards when attackers claim duplicate shares from the fixed-size welcome reward pool
- The Treasury's economic model is violated, breaking the intended "one-time welcome incentive" design principle
- Overall blockchain tokenomics and economic security are compromised when reward mechanisms can be gamed

**Severity Justification - HIGH:**

1. Direct economic impact through misallocation of protocol rewards
2. Repeatable attack - a single attacker can exploit this multiple times with different pubkey replacements
3. Low barrier to entry - requires only standard candidate admin privileges, no special access
4. Minimal cost - only transaction fees for pubkey replacement operation
5. Breaks fundamental protocol invariant that welcome rewards should be one-time incentives for genuinely new miners

## Likelihood Explanation

The likelihood of this vulnerability being exploited is HIGH based on several factors:

**Attacker Prerequisites:**
- Must be a registered candidate with access to the candidate admin address (standard requirement)
- Must have previously been elected and received welcome rewards as a miner
- Must not be currently in the active miner list during the replacement operation
- Must be able to get the new pubkey elected in a future term (requires same voting support as original election)

**Attack Feasibility:**

The conditions for exploitation occur naturally in the blockchain's operation:
- Election cycles occur regularly (every 7 days based on standard term duration)
- Candidates naturally rotate in and out of the active miner set based on voting dynamics and the limited number of miner slots
- Pubkey replacement is a legitimate administrative operation designed for key rotation and security management
- The attack leaves minimal forensic trail since pubkey replacement is an expected normal operation

**Detection Difficulty:**

- The exploitation pattern is difficult to distinguish from legitimate pubkey rotation for security purposes
- No on-chain validation prevents this specific sequence of operations
- Multiple independent candidates could discover and exploit this vulnerability without coordination
- The gap between replacement and reward claiming can span multiple terms, further obscuring the attack

**Overall Probability: HIGH** - All preconditions naturally occur during normal blockchain operation, and the attack requires only standard candidate privileges available to any elected miner.

## Recommendation

Implement unconditional state transfer for miner replacements to maintain synchronization between contracts:

**Solution 1: Remove Conditional Treasury Notification (Recommended)**

Modify `AEDPoSContract.RecordCandidateReplacement` to always notify the Treasury contract regardless of whether the old pubkey is in the current round: [3](#0-2) 

Change the logic to:
1. Keep the current round update logic as conditional (only when miner is active)
2. Move the Treasury notification outside the conditional block so it always executes
3. This ensures `LatestMinedTerm` state is always transferred from old to new pubkey

**Solution 2: Add Treasury-Side Validation**

Add a fallback mechanism in the Treasury contract to verify miner replacement history independently by consulting the Election contract's replacement maps when identifying new miners.

**Solution 3: Track Replacements in Release Path**

Modify `TreasuryContract.Release` to query the Election contract for replacement information and treat replaced pubkeys as veterans rather than new miners, even if `LatestMinedTerm` is 0.

The first solution is preferred as it maintains the intended architecture where AEDPoS coordinates state synchronization between contracts.

## Proof of Concept

A proof of concept test would demonstrate:

1. Deploy and initialize Election, AEDPoS, and Treasury contracts
2. Register candidate with `pubkey_A` and simulate election to miner status
3. Execute one term where `pubkey_A` mines blocks (establishing `LatestMinedTerm[pubkey_A] > 0`)
4. Simulate term change where `pubkey_A` is NOT elected (removed from miner list)
5. Call `ReplaceCandidatePubkey(pubkey_A, pubkey_B)` as candidate admin during this non-mining term
6. Verify that `LatestMinedTerm[pubkey_B]` remains 0 (state transfer did not occur)
7. Simulate election where `pubkey_B` becomes a miner in a subsequent term
8. Execute `Release` for that term and verify `pubkey_B` is identified as a new miner
9. Confirm welcome reward beneficiary shares are granted to `pubkey_B`
10. Verify the same entity received welcome rewards twice through different pubkeys

The test would validate that the state synchronization gap allows the `LatestMinedTerm` tracking to fail, enabling duplicate welcome reward claims.

## Notes

This vulnerability represents a genuine flaw in the cross-contract state synchronization design. The conditional notification pattern in `RecordCandidateReplacement` creates an edge case where legitimate administrative operations (pubkey replacement during non-mining periods) inadvertently reset the new miner tracking state. The fix requires ensuring that state transfers between contracts occur unconditionally for all replacement operations, regardless of current mining status.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L175-181)
```csharp
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L246-246)
```csharp
        State.BannedPubkeyMap[input.OldPubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContractState.cs (L45-48)
```csharp
    /// <summary>
    ///     Pubkey -> Latest Mined Term Number.
    /// </summary>
    public MappedState<string, long> LatestMinedTerm { get; set; }
```
