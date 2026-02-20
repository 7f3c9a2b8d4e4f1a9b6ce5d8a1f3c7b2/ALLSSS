# Audit Report

## Title
Vote Contract Option Capacity Exhaustion Enables Election System DoS

## Summary
The Vote contract enforces a hard limit of 64 options per voting item. An attacker can exhaust this capacity by announcing election with 64 different keypairs, permanently blocking all subsequent legitimate candidates from joining the election. The attack costs 6.4M ELF but is fully refundable, and governance has no mechanism to forcibly remove malicious options without attacker cooperation.

## Finding Description

The vulnerability stems from an architectural mismatch between the Election contract's candidate management and the Vote contract's option capacity constraints.

**Attack Vector:**

The Vote contract enforces a maximum of 64 options per voting item [1](#0-0) , with this limit checked during option addition [2](#0-1) .

When a candidate calls `AnnounceElection`, the Election contract adds them as an option to the miner election voting item [3](#0-2) [4](#0-3) .

The duplicate check only prevents the same public key from announcing twice [5](#0-4) , meaning an attacker can use 64 different keypairs (trivially generated) to fill all slots.

**Critical Gap - Why Governance Cannot Mitigate:**

1. **QuitElection requires admin permission**: Only the candidate admin (controlled by attacker) can voluntarily free slots [6](#0-5) .

2. **RemoveEvilNode does NOT remove Vote options**: When governance removes an evil node, it updates internal Election state but critically fails to call `RemoveOption` on the Vote contract [7](#0-6) . The method removes candidates from internal state and bans the pubkey [8](#0-7) , but never calls `VoteContract.RemoveOption`. Compare this to QuitElection, which properly calls RemoveOption [9](#0-8) .

3. **RemoveOption access control**: Only the voting item sponsor (the Election contract itself) can modify options [10](#0-9) , preventing direct governance intervention.

4. **ReplaceCandidatePubkey is option-neutral**: This method removes the old key and adds the new key atomically [11](#0-10) , maintaining the same option count.

**Economic Analysis:**

Each candidate must lock 100,000 ELF [12](#0-11) , totaling 6.4M ELF for 64 candidates. However, this deposit is fully refundable when the attacker calls QuitElection [13](#0-12) , making the attack cost-neutral except for transaction fees.

## Impact Explanation

**Severity: High**

This vulnerability enables a permanent denial-of-service attack on the election system with the following consequences:

1. **Consensus Stagnation**: No new candidates can announce election, preventing the AElf network from onboarding new miners or replacing underperforming ones. This directly impacts consensus security and decentralization.

2. **Governance Capture**: The election system is fundamental to AElf's governance model. Blocking new candidate entry effectively freezes the validator set, concentrating power among existing miners.

3. **Irreversible Without Attacker Cooperation**: The architectural gap means governance cannot forcibly remove malicious Vote options. Recovery requires the attacker to voluntarily call QuitElection on all 64 candidates.

4. **Zero Net Cost Attack**: While requiring 6.4M ELF in capital, the attack has zero net cost since deposits are fully refundable. An attacker can maintain the DoS indefinitely with no ongoing expense.

The impact is categorized as High rather than Critical because it does not result in direct fund loss or supply inflation, but it fundamentally breaks the election system's availability guarantees.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- 64 unique keypairs (trivially generated)
- Temporary access to 6.4M ELF (but maintains full custody)
- No special permissions required

**Attack Complexity:**
Low complexity - simply call `AnnounceElection` 64 times with different transaction signers. Each call succeeds because the duplicate check only prevents the same public key from announcing twice.

**Economic Feasibility:**
While 6.4M ELF is significant capital, the attack is fully recoverable, making it attractive for:
- Competitors seeking to disrupt the network
- Political actors attempting governance capture
- Malicious actors with temporary access to capital

**Detection vs. Remediation Gap:**
The attack is easily detectable (64 candidates from coordinated source), but detectability is irrelevant when governance has no remediation mechanism. The architectural flaw means even identified attacks cannot be mitigated without attacker cooperation.

## Recommendation

Modify `RemoveEvilNode` and `UpdateCandidateInformation` to synchronize with the Vote contract when removing evil candidates:

In `ElectionContract_Maintainence.cs`, add a call to `RemoveOption` when removing evil nodes:

```csharp
if (input.IsEvilNode)
{
    // ... existing code for banning and removing from internal state ...
    
    // Add this: Remove from Vote contract options
    var initialPubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
    var pubkeyByteString = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(initialPubkey));
    
    // Only remove option if not an initial miner
    if (!State.InitialMiners.Value.Value.Contains(pubkeyByteString))
    {
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = input.Pubkey
        });
    }
    
    // ... rest of existing code ...
}
```

Additionally, consider implementing a governance-controlled emergency mechanism to remove Vote options for confirmed malicious candidates.

## Proof of Concept

```csharp
[Fact]
public async Task VoteOptionExhaustion_BlocksLegitimateCandidate()
{
    // Setup: Initialize election system
    await InitializeElectionContract();
    
    // Attack: Announce 64 candidates with different keypairs
    for (int i = 0; i < 64; i++)
    {
        var attackerKeyPair = GenerateKeyPair();
        await AnnounceElectionWithKeyPair(attackerKeyPair, 100_000_00000000);
    }
    
    // Verify: Options limit reached
    var votingItem = await GetMinerElectionVotingItem();
    votingItem.Options.Count.ShouldBe(64);
    
    // Attempt: Legitimate candidate tries to announce
    var legitimateCandidate = GenerateKeyPair();
    var result = await AnnounceElectionWithKeyPair(legitimateCandidate, 100_000_00000000);
    
    // Assert: Transaction fails due to option limit
    result.Status.ShouldBe(TransactionResultStatus.Failed);
    result.Error.ShouldContain("can't greater than 64");
    
    // Governance attempts remediation: Remove one attacker as evil node
    await RemoveEvilNode(GetFirstAttackerPubkey());
    
    // Verify: Vote options NOT freed (bug confirmed)
    votingItem = await GetMinerElectionVotingItem();
    votingItem.Options.Count.ShouldBe(64); // Still at capacity!
    
    // Assert: Legitimate candidate still cannot join
    result = await AnnounceElectionWithKeyPair(legitimateCandidate, 100_000_00000000);
    result.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L5-5)
```csharp
    public const int MaximumOptionsCount = 64;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L285-286)
```csharp
        Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L305-306)
```csharp
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L110-110)
```csharp
        AddCandidateAsOption(pubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-157)
```csharp
        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L197-209)
```csharp
    private void AddCandidateAsOption(string publicKey)
    {
        if (State.VoteContract.Value == null)
            State.VoteContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName);

        // Add this candidate as an option for the the Voting Item.
        State.VoteContract.AddOption.Send(new AddOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = publicKey
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L236-236)
```csharp
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L239-249)
```csharp
        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L257-261)
```csharp
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-112)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
            var rankingList = State.DataCentersRankingList.Value;
            if (rankingList.DataCenters.ContainsKey(input.Pubkey))
            {
                rankingList.DataCenters[input.Pubkey] = 0;
                UpdateDataCenterAfterMemberVoteAmountChanged(rankingList, input.Pubkey, true);
                State.DataCentersRankingList.Value = rankingList;
            }

            Context.LogDebug(() => $"Marked {input.Pubkey.Substring(0, 10)} as an evil node.");
            Context.Fire(new EvilMinerDetected { Pubkey = input.Pubkey });
            State.CandidateInformationMap.Remove(input.Pubkey);
            var candidates = State.Candidates.Value;
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
            RemoveBeneficiary(input.Pubkey);
            return new Empty();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L308-317)
```csharp
            State.VoteContract.RemoveOption.Send(new RemoveOptionInput
            {
                VotingItemId = State.MinerElectionVotingItemId.Value,
                Option = oldPubkey
            });
            State.VoteContract.AddOption.Send(new AddOptionInput
            {
                VotingItemId = State.MinerElectionVotingItemId.Value,
                Option = newPubkey
            });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-351)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
