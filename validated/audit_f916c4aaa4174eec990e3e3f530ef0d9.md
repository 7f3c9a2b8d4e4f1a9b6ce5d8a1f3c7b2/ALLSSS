# Audit Report

## Title
Initial Miners Can Bypass Election Announcement Check via ReplaceCandidatePubkey to Gain Backup Subsidy

## Summary
The `ReplaceCandidatePubkey` method in the Election contract fails to validate whether the new pubkey is an initial miner, allowing a bypass of the restriction that prevents initial miners from announcing election. This enables an attacker to register an initial miner pubkey in the backup subsidy profit scheme, receiving candidate subsidies in addition to their role as initial miners.

## Finding Description

The Election contract enforces a critical invariant: initial miners (bootstrap nodes from chain genesis) cannot announce election to prevent them from participating in the candidate subsidy distribution. This is enforced in the `AnnounceElection` method with an explicit check: [1](#0-0) 

However, the `ReplaceCandidatePubkey` method contains insufficient validation. When replacing a candidate's pubkey, the method only validates that the new pubkey is not already a candidate: [2](#0-1) 

The method **does not check** whether the new pubkey exists in the `InitialMiners` list.

The exploit flow:
1. Attacker announces election with a regular pubkey (not an initial miner), passing the initial miner check
2. Regular pubkey is added to `Candidates` list and potentially to `DataCentersRankingList` with subsidy registration: [3](#0-2) 

3. Attacker calls `ReplaceCandidatePubkey` with old=regular pubkey, new=initial miner pubkey
4. The method removes the old pubkey from `Candidates` and adds the initial miner pubkey: [4](#0-3) 

5. If in the data center ranking list, subsidy beneficiary is transferred from old to new pubkey: [5](#0-4) 

6. The `InitialMiners` list update block only executes if the OLD pubkey was in `InitialMiners`: [6](#0-5) 

7. Since the old pubkey (regular candidate) is NOT in `InitialMiners`, this block is skipped and `InitialMiners` remains unchanged

**Result**: The initial miner pubkey now exists in both `Candidates` and `InitialMiners` lists simultaneously, with backup subsidy beneficiary registration active.

## Impact Explanation

This vulnerability enables **reward misallocation** within the Treasury profit distribution system. Initial miners are intentionally excluded from the candidate subsidy system, as evidenced by the explicit check preventing them from announcing election and their use as fallback miners when insufficient candidates exist: [7](#0-6) 

By exploiting this vulnerability, an initial miner can:
1. Remain in the `InitialMiners` list (serving as a backup miner)
2. Be registered as a beneficiary in the `BackupSubsidy` profit scheme via: [8](#0-7) 

3. Receive backup subsidy distributions (5% of Treasury distributions) intended only for regular candidates

This dilutes the subsidy share of legitimate candidates and misallocates treasury resources contrary to the protocol's economic design.

## Likelihood Explanation

**Execution Path**: The exploit requires only two public method calls with realistic preconditions:
1. `AnnounceElection` with a regular pubkey (requires token lock, but recoverable)
2. `ReplaceCandidatePubkey` as the candidate admin

**Feasibility**: 
- Initial miner pubkeys are public information from chain initialization: [9](#0-8) 

- Any user can announce election and become a candidate admin
- The validation checks in `ReplaceCandidatePubkey` all pass incorrectly because no initial miner check exists

**Economic Incentive**: The attacker gains continuous backup subsidy rewards (5% of treasury distributions) across multiple terms with only the temporary cost of locked tokens for election announcement, making the exploit highly profitable.

## Recommendation

Add a validation check in the `ReplaceCandidatePubkey` method to ensure the new pubkey is not an initial miner:

```csharp
public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
{
    Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
        "Pubkey is in already banned.");

    // Permission check.
    Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

    var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
    var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));

    // Add validation to prevent initial miners from becoming candidates
    Assert(!State.InitialMiners.Value.Value.Contains(newPubkeyBytes),
        "Initial miner cannot become a candidate.");

    // Record the replacement.
    PerformReplacement(input.OldPubkey, input.NewPubkey);
    
    // ... rest of the method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_InitialMinerBypass_Test()
{
    // Step 1: Get an initial miner pubkey from genesis
    var initialMiners = await ElectionContractStub.GetInitialMiners.CallAsync(new Empty());
    var initialMinerPubkey = initialMiners.Value.First().ToHex();
    
    // Step 2: Announce election with a regular pubkey (not initial miner)
    var regularKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = ValidationDataCenterKeyPairs.Last();
    var candidateAdminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
    await AnnounceElectionAsync(regularKeyPair, candidateAdminAddress);
    
    // Verify regular candidate is in candidates list
    var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidates.Value.ShouldContain(ByteString.CopyFrom(regularKeyPair.PublicKey));
    
    // Step 3: Replace regular pubkey with initial miner pubkey
    var candidateAdminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, candidateAdmin);
    await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = regularKeyPair.PublicKey.ToHex(),
        NewPubkey = initialMinerPubkey
    });
    
    // Step 4: Verify exploit success - initial miner is now in Candidates
    var candidatesAfter = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    var initialMinerBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(initialMinerPubkey));
    candidatesAfter.Value.ShouldContain(initialMinerBytes);
    
    // Step 5: Verify initial miner is still in InitialMiners list
    var initialMinersAfter = await ElectionContractStub.GetInitialMiners.CallAsync(new Empty());
    initialMinersAfter.Value.ShouldContain(initialMinerBytes);
    
    // Vulnerability confirmed: Initial miner pubkey exists in both lists
    // This allows receiving BackupSubsidy rewards while remaining as fallback miner
}
```

## Notes

This vulnerability violates the fundamental design principle that initial miners should be excluded from the democratic election and candidate subsidy system. The flaw exists because the `ReplaceCandidatePubkey` method assumes that if you're replacing TO an initial miner pubkey, the old pubkey must ALSO be an initial miner. This assumption is violated when the old pubkey is a regular candidate, allowing the invariant to be bypassed.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L112-116)
```csharp
        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L149-150)
```csharp
        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L34-38)
```csharp
        State.InitialMiners.Value = new PubkeyList
        {
            // ReSharper disable once ConvertClosureToMethodGroup
            Value = { input.MinerList.Select(m => ByteStringHelper.FromHexString(m)) }
        };
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L191-191)
```csharp
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L192-196)
```csharp
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L199-218)
```csharp
        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L220-226)
```csharp
        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L67-69)
```csharp
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L781-795)
```csharp
    private void AddBeneficiary(string candidatePubkey, Address profitsReceiver = null)
    {
        var beneficiaryAddress = GetBeneficiaryAddress(candidatePubkey, profitsReceiver);
        var subsidyId = GenerateSubsidyId(candidatePubkey, beneficiaryAddress);
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.SubsidyHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = beneficiaryAddress,
                Shares = 1,
            },
            ProfitDetailId = subsidyId
        });
    }
```
