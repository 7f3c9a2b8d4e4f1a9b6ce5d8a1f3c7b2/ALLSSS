# Audit Report

## Title
Unauthorized Candidate Registration via Missing Permission Check in AnnounceElectionFor

## Summary
The `AnnounceElectionFor` function in the Election contract allows anyone to register arbitrary public keys as election candidates without the owner's consent. The caller becomes the admin of the registered candidate and can prevent the legitimate owner from participating in elections. Since the attacker can recover the locked tokens by calling `QuitElection`, the attack has zero net cost and enables repeated abuse.

## Finding Description

The `AnnounceElectionFor` function accepts an arbitrary public key parameter and registers it as a candidate without any authorization check to verify the caller has permission to do so. [1](#0-0) 

The function directly uses the input `pubkey` parameter and calls the internal `AnnounceElection` method, which only validates that the pubkey is not an initial miner, not already a current candidate, and not banned. [2](#0-1) 

Critically, the caller becomes the admin of the victim's public key if no admin is explicitly specified (the admin defaults to `Context.Sender`). [3](#0-2) 

This breaks the fundamental authorization model because:

1. **Unlike `AnnounceElection`**, which uses `Context.RecoverPublicKey()` to ensure only the key owner can register themselves, `AnnounceElectionFor` accepts any pubkey as a parameter without signature verification. [4](#0-3) 

2. **Only the admin can quit the election**, blocking the legitimate owner from managing their candidacy. [5](#0-4) 

3. **The victim cannot re-register** because the public key is already marked as a current candidate, and the internal validation prevents duplicate registration. [6](#0-5) 

4. **The attacker can recover the locked tokens** (100,000 ELF) by calling `QuitElection`, making the attack economically costless and repeatable. [7](#0-6) [8](#0-7) 

The test suite demonstrates that only the admin can quit the election, confirming that neither the original keypair nor any replacement can quit without admin authorization. [9](#0-8) 

## Impact Explanation

**Concrete Harm:**
1. **Unauthorized Governance Control**: An attacker gains admin authority over arbitrary candidates in the election system, controlling their participation in consensus miner selection through the AEDPoS mechanism.

2. **Denial of Service**: Legitimate node operators cannot register their own public keys once pre-registered by an attacker. The duplicate candidate check prevents re-registration, and only the attacker-controlled admin can quit to free the slot.

3. **Candidate List Manipulation**: An attacker can flood the voting options with controlled fake candidates, diluting legitimate votes and polluting the governance candidate pool.

4. **Zero Net Cost Attack**: The attacker recovers the 100,000 token lock by calling `QuitElection` as the admin, enabling repeated attacks against multiple victims with the same capital.

**Who is Affected:**
- Node operators whose public keys are registered without consent
- Voters who face a polluted candidate list with fake options
- The AEDPoS consensus mechanism which relies on legitimate candidate participation for miner selection

**Severity Justification:**
This is CRITICAL because it violates the fundamental authorization invariant that only a public key owner should control their candidate status. The Election contract is core to AEDPoS consensus governance, and unauthorized control over candidates directly impacts miner selection and network security.

## Likelihood Explanation

**Attacker Capabilities:**
- Requires 100,000 ELF tokens and approval to the Election contract (standard requirements for any candidate registration)
- Can obtain any public key from blockchain transaction data (all public keys are visible on-chain)
- No special privileges or trusted roles required

**Attack Complexity:**
The attack is trivial to execute with a single transaction call. The attacker simply calls `AnnounceElectionFor` with the target's public key, and either omits the `admin` parameter (defaulting to themselves) or explicitly sets themselves as admin.

**Feasibility Conditions:**
- Public method accessible to anyone meeting the standard token requirements
- No rate limiting or spam prevention mechanisms
- Economic cost is fully recoverable through `QuitElection`, enabling the attacker to cycle through announce-quit-announce to attack multiple victims with the same capital
- The attack is difficult to detect proactively since `AnnounceElectionFor` appears to be a legitimate sponsorship feature

**Probability:** HIGH - The vulnerability is easily exploitable with standard user capabilities, minimal cost, and no technical barriers.

## Recommendation

Add an authorization check to verify the caller has permission to register the specified public key. The most secure approach is to require a signature from the public key owner approving the sponsorship:

```csharp
public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
{
    var pubkey = input.Pubkey;
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
    var address = Address.FromPublicKey(pubkeyBytes);
    
    // CRITICAL FIX: Require authorization from the candidate
    // Option 1: Require the candidate to be the sender
    // Option 2: Require a signature from the candidate in the input
    // Option 3: Set admin to candidate's address by default, not sponsor's
    Assert(input.Admin != null && input.Admin == address, 
        "Admin must be explicitly set to the candidate's address for authorization.");
    
    AnnounceElection(pubkeyBytes);
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

Alternatively, require the `admin` parameter to always be the candidate's own address, and remove the default to `Context.Sender`.

## Proof of Concept

```csharp
[Fact]
public async Task AnnounceElectionFor_UnauthorizedRegistration_Attack()
{
    // Setup: Attacker and victim keypairs
    var attackerKeyPair = ValidationDataCenterKeyPairs.First();
    var victimKeyPair = ValidationDataCenterKeyPairs.Skip(1).First();
    
    var attackerStub = GetElectionContractTester(attackerKeyPair);
    var victimAddress = Address.FromPublicKey(victimKeyPair.PublicKey);
    
    // Step 1: Attacker registers victim's public key without permission
    // Attacker becomes admin by not specifying admin parameter (defaults to Context.Sender)
    await attackerStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Pubkey = victimKeyPair.PublicKey.ToHex()
        // No admin specified - defaults to attacker
    });
    
    // Step 2: Verify attacker is now admin
    var admin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = victimKeyPair.PublicKey.ToHex() });
    admin.ShouldBe(Address.FromPublicKey(attackerKeyPair.PublicKey));
    
    // Step 3: Victim cannot register themselves (already registered)
    var victimStub = GetElectionContractTester(victimKeyPair);
    var result = await victimStub.AnnounceElection.SendWithExceptionAsync(victimAddress);
    result.TransactionResult.Error.ShouldContain("This public key already announced election");
    
    // Step 4: Victim cannot quit (not the admin)
    var quitResult = await victimStub.QuitElection.SendAsync(
        new StringValue { Value = victimKeyPair.PublicKey.ToHex() });
    quitResult.TransactionResult.Error.ShouldContain("Only admin can quit election");
    
    // Step 5: Attacker can quit and recover tokens (zero net cost)
    await attackerStub.QuitElection.SendAsync(
        new StringValue { Value = victimKeyPair.PublicKey.ToHex() });
    
    // Attack complete: Victim is denied service, attacker recovers all funds
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-99)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-142)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
        var admin = input.Admin ?? Context.Sender;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L144-175)
```csharp
    private void AnnounceElection(byte[] pubkeyBytes)
    {
        var pubkey = pubkeyBytes.ToHex();
        var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);

        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");

        var candidateInformation = State.CandidateInformationMap[pubkey];

        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
        }
        else
        {
            Assert(!IsPubkeyBanned(pubkey), "This candidate already banned before.");
            State.CandidateInformationMap[pubkey] = new CandidateInformation
            {
                Pubkey = pubkey,
                AnnouncementTransactionId = Context.OriginTransactionId,
                IsCurrentCandidate = true
            };
        }

        State.Candidates.Value.Value.Add(pubkeyByteString);
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-236)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
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

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ReplaceCandidateTests.cs (L63-85)
```csharp
        // Two pubkeys cannot quit election.
        {
            var stub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(ElectionContractAddress,
                announceElectionKeyPair);
            var result = await stub.QuitElection.SendAsync(new StringValue { Value = newKeyPair.PublicKey.ToHex() });
            result.TransactionResult.Error.ShouldContain("Only admin can quit election.");
        }
        {
            var stub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(ElectionContractAddress,
                newKeyPair);
            var result = await stub.QuitElection.SendAsync(new StringValue { Value = newKeyPair.PublicKey.ToHex() });
            result.TransactionResult.Error.ShouldContain("Only admin can quit election.");
        }

        // Only admin can quit election.
        {
            await candidateAdminStub.QuitElection.SendAsync(new StringValue
            {
                Value = newKeyPair.PublicKey.ToHex()
            });
            var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
            candidates.Value.ShouldNotContain(ByteString.CopyFrom(newKeyPair.PublicKey));
        }
```
