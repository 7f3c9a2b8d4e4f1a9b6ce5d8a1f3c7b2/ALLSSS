# Audit Report

## Title
Duplicate Welcome Rewards via Pubkey Replacement During Non-Mining Periods

## Summary
A state synchronization vulnerability between the AEDPoS consensus contract and the Treasury contract allows miners to receive welcome rewards multiple times. When a candidate replaces their public key while not actively mining, the Treasury contract is not notified, leaving the new pubkey with `LatestMinedTerm == 0`, causing it to be incorrectly identified as a "new" miner eligible for welcome rewards.

## Finding Description

The vulnerability exists in the cross-contract interaction between Election, AEDPoS, and Treasury contracts.

**Root Cause:**

The AEDPoS contract's `RecordCandidateReplacement` method contains a conditional check that only notifies the Treasury contract when the old pubkey is currently an active miner in the current round: [1](#0-0) 

When this condition fails (old pubkey not in current round), the method returns early without calling Treasury's `RecordMinerReplacement`: [2](#0-1) 

This breaks state synchronization. The Treasury contract's `LatestMinedTerm` mapping tracks each miner's latest term, but when `RecordMinerReplacement` is not called, this state is never updated for the new pubkey: [3](#0-2) 

**Detection of New Miners:**

During reward distribution in the `Release` method, miners are identified as "new" if their `LatestMinedTerm` equals 0 and they're not in the initial miner list: [4](#0-3) 

**Welcome Reward Distribution:**

New miners identified by this check receive welcome rewards through the `UpdateWelcomeRewardWeights` method, which adds them as beneficiaries to the `VotesWeightRewardHash` profit scheme: [5](#0-4) 

Specifically, lines 864-879 add new miners as beneficiaries with 1 share each in the welcome reward distribution.

**Why Protections Fail:**

The Election contract's `ReplaceCandidatePubkey` method processes the replacement regardless of current mining status, only checking that the old pubkey is a candidate or initial miner and verifying admin permissions: [6](#0-5) 

The old pubkey is banned to prevent reuse: [7](#0-6) 

However, this doesn't prevent the new pubkey from being treated as new by the Treasury contract because the `LatestMinedTerm` state transfer never occurs.

**Attack Path:**

1. Attacker registers as candidate with `pubkey_A`, gets elected, receives welcome rewards (legitimate)
2. After mining, `LatestMinedTerm[pubkey_A] = term_number`
3. When `pubkey_A` is NOT elected in a future term (not in current round)
4. Attacker calls `ReplaceCandidatePubkey(pubkey_A, pubkey_B)`
5. AEDPoS returns early because `pubkey_A` not in current round
6. Treasury's `RecordMinerReplacement` is never called
7. Result: `LatestMinedTerm[pubkey_A]` remains set, but `LatestMinedTerm[pubkey_B] = 0`
8. Attacker gets `pubkey_B` elected in a subsequent term
9. Treasury's `Release` method identifies `pubkey_B` as a new miner
10. Welcome rewards granted again to the same entity

## Impact Explanation

**Direct Financial Impact:**
- Attackers can receive welcome rewards from the `VotesWeightRewardHash` profit scheme multiple times, draining funds intended for genuine new miners
- Each duplicate welcome reward grants beneficiary shares in the welcome reward distribution for an entire term
- The welcome reward pool is funded by the Treasury's mining reward allocation (weighted by `MinerRewardWeightSetting.WelcomeRewardWeight`)

**Affected Parties:**
- Legitimate new miners receive reduced welcome rewards due to pool dilution when attackers claim duplicate shares
- The Treasury's reward distribution becomes unfair, violating the intended "one-time welcome incentive" design principle
- The overall economic model and tokenomics of the blockchain are compromised

**Severity Justification:**

This is HIGH severity because:
1. It directly misallocates economic rewards designed for new miner onboarding
2. The attack is repeatable - a single attacker can exploit this multiple times with different pubkeys
3. It requires no special privileges beyond normal candidate admin rights
4. The cost is minimal (just transaction fees for pubkey replacement)
5. It breaks a fundamental protocol invariant (one-time welcome rewards)

## Likelihood Explanation

**Attacker Capabilities:**
- Must be a registered candidate with candidate admin address
- Must have previously received welcome rewards as a miner
- Must not be currently in the active miner list during replacement
- Must be able to get the new pubkey elected in a future term

**Attack Complexity:**

The attack is straightforward:
1. Register as candidate, get elected, receive welcome rewards (legitimate)
2. Mine for several terms to establish mining history
3. When not elected in a term, call `ReplaceCandidatePubkey` with a new pubkey
4. Get the new pubkey elected in a future term
5. Receive welcome rewards again for the "new" pubkey

**Feasibility:**
- Elections happen regularly (every 7 days based on term duration)
- Candidates frequently rotate in/out of the active miner set based on voting dynamics
- Pubkey replacement is a legitimate operation for key rotation/security
- The attack leaves minimal audit trail since replacement is a normal operation

**Detection Difficulty:**
- The exploitation is difficult to distinguish from legitimate pubkey rotation
- No on-chain validation prevents this pattern
- Multiple candidates could independently discover and exploit this

**Probability: HIGH** - The conditions naturally occur during normal blockchain operation, and the attack requires only standard candidate privileges.

## Recommendation

Fix the state synchronization issue by ensuring Treasury is always notified of pubkey replacements, regardless of current mining status:

**Option 1: Remove the early return condition**

Modify `RecordCandidateReplacement` in AEDPoSContract.cs to always notify Treasury:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");

    bool isInCurrentRound = false;
    if (TryToGetCurrentRoundInformation(out var currentRound) &&
        currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey))
    {
        // If this candidate is current miner, update current round information
        isInCurrentRound = true;
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
    }

    // Always notify Treasury Contract to update replacement information
    State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
    {
        OldPubkey = input.OldPubkey,
        NewPubkey = input.NewPubkey,
        CurrentTermNumber = State.CurrentTermNumber.Value
    });

    return new Empty();
}
```

**Option 2: Add validation in Treasury's Release method**

Add a check to prevent welcome rewards if the pubkey has a replacement history indicating it's not genuinely new. This would require tracking replacement chains in Treasury state.

**Recommended approach:** Option 1 is cleaner as it ensures state consistency across contracts at the point of replacement, rather than trying to detect abuse later during reward distribution.

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateWelcomeRewards_ViaReplacementDuringNonMining_Test()
{
    // Setup: Initialize contracts and create initial miners
    await InitializeContracts();
    
    // Step 1: Register attacker as candidate with pubkey_A
    var attackerPubkeyA = "attacker_pubkey_A";
    var attackerAdmin = Accounts[1].Address;
    await RegisterCandidate(attackerPubkeyA, attackerAdmin);
    
    // Step 2: Get pubkey_A elected and receive welcome rewards
    await VoteForCandidate(attackerPubkeyA, 10000);
    await NextTerm(); // Attacker gets elected
    
    // Verify welcome rewards received
    var welcomeRewardsA = await GetWelcomeRewards(attackerPubkeyA);
    Assert.True(welcomeRewardsA > 0);
    
    // Step 3: Mine for a few terms
    await NextTerm();
    await NextTerm();
    
    // Step 4: Ensure pubkey_A is NOT in current mining round
    await RemoveVotes(attackerPubkeyA); // Drop out of active miner set
    await NextTerm();
    
    var currentMiners = await GetCurrentMiners();
    Assert.DoesNotContain(attackerPubkeyA, currentMiners);
    
    // Step 5: Replace pubkey_A with pubkey_B while not mining
    var attackerPubkeyB = "attacker_pubkey_B";
    await ReplaceCandidatePubkey(attackerPubkeyA, attackerPubkeyB, attackerAdmin);
    
    // Verify Treasury was NOT notified (LatestMinedTerm[pubkey_B] == 0)
    var latestMinedTermB = await GetLatestMinedTerm(attackerPubkeyB);
    Assert.Equal(0, latestMinedTermB);
    
    // Step 6: Get pubkey_B elected
    await VoteForCandidate(attackerPubkeyB, 10000);
    await NextTerm();
    
    // Step 7: Verify duplicate welcome rewards received
    var welcomeRewardsB = await GetWelcomeRewards(attackerPubkeyB);
    Assert.True(welcomeRewardsB > 0);
    
    // VULNERABILITY CONFIRMED: Same entity received welcome rewards twice
    Assert.True(welcomeRewardsA > 0 && welcomeRewardsB > 0);
}
```

**Notes:**
- The vulnerability is confirmed through code analysis showing the exact state synchronization gap
- The attack requires only standard candidate operations during natural mining rotations
- Multiple miners could exploit this independently, amplifying the economic impact
- The fix is straightforward: ensure Treasury is always notified of pubkey replacements

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L136-137)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContractState.cs (L45-48)
```csharp
    /// <summary>
    ///     Pubkey -> Latest Mined Term Number.
    /// </summary>
    public MappedState<string, long> LatestMinedTerm { get; set; }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L155-156)
```csharp
        maybeNewElectedMiners = maybeNewElectedMiners
            .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p)).ToList();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L848-891)
```csharp
    private void UpdateWelcomeRewardWeights(Round previousTermInformation, List<string> newElectedMiners)
    {
        var previousMinerAddresses =
            GetAddressesFromCandidatePubkeys(previousTermInformation.RealTimeMinersInformation.Keys);
        var possibleWelcomeBeneficiaries = new RemoveBeneficiariesInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Beneficiaries = { previousMinerAddresses }
        };
        State.ProfitContract.RemoveBeneficiaries.Send(possibleWelcomeBeneficiaries);
        State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            SubSchemeId = State.BasicRewardHash.Value
        });

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
        }
        else
        {
            Context.LogDebug(() => "Welcome reward will go to Basic Reward.");
            State.ProfitContract.AddSubScheme.Send(new AddSubSchemeInput
            {
                SchemeId = State.VotesWeightRewardHash.Value,
                SubSchemeId = State.BasicRewardHash.Value,
                SubSchemeShares = 1
            });
        }
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L246-246)
```csharp
        State.BannedPubkeyMap[input.OldPubkey] = true;
```
