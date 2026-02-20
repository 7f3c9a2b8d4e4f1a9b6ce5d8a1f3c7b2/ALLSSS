# Audit Report

## Title
Unauthorized Candidate Admin Control via AnnounceElectionFor with Null Admin and Contract Caller

## Summary
The `AnnounceElectionFor` function allows any caller to announce any public key as an election candidate without the candidate's consent. When the `Admin` parameter is null, the function defaults the admin role to `Context.Sender`, enabling an attacker to deploy an immutable contract that permanently seizes administrative control over a victim's candidacy with no recourse except Parliament intervention.

## Finding Description

The Election contract provides two methods for announcing candidacy: `AnnounceElection` and `AnnounceElectionFor`. The regular `AnnounceElection` method verifies the caller owns the candidate's private key by using `Context.RecoverPublicKey()` [1](#0-0)  and requires an explicit admin address to be provided [2](#0-1) .

However, `AnnounceElectionFor` has two critical flaws:

**1. Missing Consent Verification**: Unlike `AnnounceElection`, this function accepts any public key string without signature validation [3](#0-2) , allowing anyone to announce anyone else as a candidate.

**2. Improper Admin Defaulting**: When `input.Admin` is null, the function defaults to `Context.Sender` as the admin [4](#0-3) . This admin is then stored in the state mappings [5](#0-4) .

**Attack Execution**:
1. Attacker deploys an immutable contract with no admin transfer or quit functions
2. Contract approves 100,000 ELF [6](#0-5)  to the Election contract
3. Contract calls `AnnounceElectionFor` with victim's pubkey and `Admin = null`
4. The contract address becomes the admin
5. Victim's pubkey is now permanently under contract control

**Why Victim Cannot Recover**:
- The private `AnnounceElection` method prevents duplicate announcements [7](#0-6) , so the victim cannot re-announce themselves
- `SetCandidateAdmin` requires the caller to be either the current admin or Parliament [8](#0-7) 
- `QuitElection` requires the caller to be the admin [9](#0-8) 
- `ReplaceCandidatePubkey` also requires the caller to be the admin [10](#0-9) 

If the attacker uses an immutable contract, the victim has no recourse except waiting for Parliament governance intervention.

## Impact Explanation

**Authorization Impact**: An attacker gains unauthorized administrative control over any victim's election candidacy. The victim loses the ability to manage their own participation in the election system.

**Operational Impact**:
- **DoS of Self-Announcement**: The victim cannot call `AnnounceElection` for their own public key due to the duplicate candidate check
- **Loss of Control**: The victim cannot quit the election or change the admin without being the current admin or having Parliament approval
- **Permanent Lock**: If executed via an immutable contract, the situation becomes permanent until Parliament intervenes

**Severity: Medium** - While there is no direct fund theft (the attacker's locked 100,000 ELF tokens are refundable when the contract quits [11](#0-10) ), the vulnerability has significant governance and operational impact requiring external governance intervention to resolve.

## Likelihood Explanation

**Attacker Capabilities**:
- Must deploy a smart contract (trivial on AElf)
- Must have 100,000 ELF to lock (modest requirement, fully refundable)
- Must approve tokens to the Election contract (standard operation)

**Attack Complexity**: Very Low
- Single transaction from the malicious contract
- No timing requirements or race conditions
- No complex state manipulation needed

**Feasibility Conditions**:
- Target pubkey must not already be an announced candidate
- Target must not be an initial miner [12](#0-11) 
- These conditions are easily satisfied for most addresses

**Economic Rationality**: High
- Attack cost: Only opportunity cost of locked tokens (100% refundable when contract quits)
- Impact: Permanent control over victim's candidacy
- Detection: Publicly visible on-chain but victim has no technical recourse

**Probability: High** - All preconditions are easily met and the attack is straightforward to execute with minimal cost.

## Recommendation

Add consent verification to `AnnounceElectionFor` by requiring either:

1. **Signature-based consent**: Require the candidate to sign the announcement transaction, similar to how `AnnounceElection` uses `Context.RecoverPublicKey()`
2. **Explicit admin requirement**: Remove the null-coalescing operator and require an explicit admin address to be provided in all cases
3. **Candidate self-authorization**: Add a two-step process where the candidate must first authorize a sponsor to announce on their behalf

Recommended fix for option 2:
```csharp
public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
{
    var pubkey = input.Pubkey;
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
    var address = Address.FromPublicKey(pubkeyBytes);
    AnnounceElection(pubkeyBytes);
    
    // Require explicit admin address
    Assert(input.Admin != null, "Admin address must be explicitly provided.");
    var admin = input.Admin;
    
    State.CandidateAdmins[pubkey] = admin;
    var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
    managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
    State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
    LockCandidateNativeToken();
    AddCandidateAsOption(pubkey);
    if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
    {
        State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
        RegisterCandidateToSubsidyProfitScheme(pubkey);
    }

    State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AnnounceElectionFor_UnauthorizedAdminControl_Attack()
{
    // Setup: Get a victim keypair that hasn't announced candidacy yet
    var victimKeyPair = SampleKeyPairs.KeyPairs[10];
    var attackerKeyPair = SampleKeyPairs.KeyPairs[11];
    
    // Attacker deploys contract or uses their address directly
    var attackerStub = GetElectionContractTester(attackerKeyPair);
    
    // Attacker announces election for victim with null admin (defaults to attacker's address)
    await attackerStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Pubkey = victimKeyPair.PublicKey.ToHex(),
        Admin = null // This will default to Context.Sender (attacker)
    });
    
    // Verify attacker controls the admin
    var admin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = victimKeyPair.PublicKey.ToHex() });
    admin.ShouldBe(Address.FromPublicKey(attackerKeyPair.PublicKey));
    
    // Victim cannot re-announce themselves
    var victimStub = GetElectionContractTester(victimKeyPair);
    var result = await victimStub.AnnounceElection.SendWithExceptionAsync(
        Address.FromPublicKey(victimKeyPair.PublicKey));
    result.TransactionResult.Error.ShouldContain("This public key already announced election");
    
    // Victim cannot quit election (requires admin permission)
    var quitResult = await victimStub.QuitElection.SendWithExceptionAsync(
        new StringValue { Value = victimKeyPair.PublicKey.ToHex() });
    quitResult.TransactionResult.Error.ShouldContain("Only admin can quit election");
    
    // Victim cannot change admin (requires being current admin or Parliament)
    var changeAdminResult = await victimStub.SetCandidateAdmin.SendWithExceptionAsync(
        new SetCandidateAdminInput
        {
            Pubkey = victimKeyPair.PublicKey.ToHex(),
            Admin = Address.FromPublicKey(victimKeyPair.PublicKey)
        });
    changeAdminResult.TransactionResult.Error.ShouldContain("No permission");
}
```

## Notes

This vulnerability represents a consent issue in the election system design. The `AnnounceElectionFor` method was likely intended to allow sponsors to help candidates announce their candidacy, but the lack of consent verification combined with the admin defaulting mechanism creates a griefing vector. The impact is limited to governance operations rather than direct financial loss, but it permanently locks victims out of election participation without Parliament intervention.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L27-40)
```csharp
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
            }
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L95-95)
```csharp
        var recoveredPublicKey = Context.RecoverPublicKey();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L101-101)
```csharp
        Assert(input.Value.Any(), "Admin is needed while announcing election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L123-124)
```csharp
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L127-127)
```csharp
        var admin = input.Admin ?? Context.Sender;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L128-131)
```csharp
        State.CandidateAdmins[pubkey] = admin;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L149-150)
```csharp
        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-157)
```csharp
        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L236-236)
```csharp
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L242-249)
```csharp
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```
