# Audit Report

## Title
Unauthorized Candidate Registration via AnnounceElectionFor Allows Admin Privilege Hijacking

## Summary
The `AnnounceElectionFor` method in the Election contract allows any caller to register an arbitrary public key as an election candidate without verifying ownership or obtaining consent from the key holder. The attacker gains permanent admin control over the candidate, enabling them to quit elections, replace public keys, and control election participation. The legitimate public key owner cannot reclaim admin control without Parliament governance intervention.

## Finding Description

The vulnerability exists in the `AnnounceElectionFor` method which creates candidate entries without verifying that the caller owns or controls the specified public key. [1](#0-0) 

**Root Cause:**

Unlike the regular `AnnounceElection` method which uses `Context.RecoverPublicKey()` to cryptographically verify the caller's identity, the `AnnounceElectionFor` method accepts the public key as a string parameter without any ownership verification. [2](#0-1) 

The private `AnnounceElection` method creates a new entry in `CandidateInformationMap` for any pubkey that passes basic checks (not an initial miner, not already a candidate, not banned). [3](#0-2) 

Critically, it creates a new `CandidateInformation` entry without verifying the caller's authority over that pubkey. The attacker-specified admin is permanently set, and the legitimate owner cannot reclaim control because `SetCandidateAdmin` requires either the current admin's permission or Parliament governance intervention. [4](#0-3) 

**Why Protections Fail:**

The method only validates that the pubkey is not an initial miner, not already registered, and not banned. There is no check verifying that `Context.Sender` has any relationship to or authority over the specified public key.

## Impact Explanation

**Authorization & Governance Impact:**
- Attackers can register any public key as a candidate without the owner's knowledge or consent, violating the fundamental authorization invariant
- The attacker gains permanent admin control over the candidate, allowing them to:
  - Quit the election on the victim's behalf via `QuitElection` [5](#0-4) 
  
  - Replace the victim's public key via `ReplaceCandidatePubkey` [6](#0-5) 

**Operational Impact:**
- Attackers can disrupt validator operations by quitting elections at critical moments
- Legitimate validator node operators lose control over their participation in the election system
- Can be used to prevent specific validators from participating or to cause confusion by registering well-known public keys

**Who Is Affected:**
- Any public key holder whose key has not yet been registered as a candidate
- The election system's integrity and trust model
- Honest validators who may have their keys registered maliciously

**Severity Justification:**
HIGH severity because it breaks the core authorization model of the election system, allowing unauthorized parties to gain permanent administrative control over candidates and manipulate election participation.

## Likelihood Explanation

**Reachable Entry Point:**
`AnnounceElectionFor` is a public method directly callable by any user with no authorization restrictions. [7](#0-6) 

**Attacker Capabilities:**
- Attacker needs only sufficient native tokens to pay the registration fee of 100,000 ELF [8](#0-7) 

- No special permissions or trusted role access required
- Can specify any valid public key string as the target

**Attack Complexity:**
Single transaction with straightforward parameters. The attacker simply calls `AnnounceElectionFor` with the victim's public key and their own address as admin.

**Economic Rationality:**
- Cost: 100,000 ELF registration fee (tokens are locked, not lost, and returned upon quit) [9](#0-8) 

- Benefit: Full administrative control over a candidate, ability to disrupt elections, control over profit distribution
- Rational for attackers seeking to manipulate validator elections or disrupt specific validators

**Detection Constraints:**
The attack is immediately effective and difficult to reverse without Parliament governance action, making it a practical and severe threat.

## Recommendation

Add ownership verification to the `AnnounceElectionFor` method. Require either:

1. **Signature-based verification**: Require the candidate to sign a message authorizing the specific admin address, similar to how the regular `AnnounceElection` uses `Context.RecoverPublicKey()`

2. **Two-step process**: Allow `AnnounceElectionFor` to create a "pending" registration that requires the actual public key owner to confirm and accept the admin assignment

3. **Admin initialization constraint**: Only allow the public key owner to set the initial admin via `SetCandidateAdmin`, and prevent `AnnounceElectionFor` from setting an admin without explicit consent

The recommended fix would be to modify `AnnounceElectionFor` to require cryptographic proof of authorization from the pubkey owner, similar to the existing `AnnounceElection` pattern.

## Proof of Concept

```csharp
[Fact]
public async Task AnnounceElectionFor_UnauthorizedAdminHijacking_Test()
{
    // Victim's keypair (legitimate validator)
    var victimKeyPair = ValidationDataCenterKeyPairs[0];
    var victimPubkey = victimKeyPair.PublicKey.ToHex();
    
    // Attacker's keypair (malicious actor)
    var attackerKeyPair = ValidationDataCenterKeyPairs[1];
    var attackerAddress = Address.FromPublicKey(attackerKeyPair.PublicKey);
    
    // Attacker calls AnnounceElectionFor with victim's pubkey and attacker as admin
    var attackerStub = GetElectionContractTester(attackerKeyPair);
    await attackerStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Admin = attackerAddress,
        Pubkey = victimPubkey
    });
    
    // Verify attacker is now the admin
    var admin = await attackerStub.GetCandidateAdmin.CallAsync(new StringValue { Value = victimPubkey });
    admin.ShouldBe(attackerAddress);
    
    // Attacker can now quit the election on victim's behalf
    await attackerStub.QuitElection.SendAsync(new StringValue { Value = victimPubkey });
    
    // Verify candidate is no longer active
    var candidateInfo = await attackerStub.GetCandidateInformation.CallAsync(new StringValue { Value = victimPubkey });
    candidateInfo.IsCurrentCandidate.ShouldBeFalse();
    
    // Victim cannot reclaim control - SetCandidateAdmin requires current admin permission
    var victimStub = GetElectionContractTester(victimKeyPair);
    var result = await victimStub.SetCandidateAdmin.SendWithExceptionAsync(new SetCandidateAdminInput
    {
        Pubkey = victimPubkey,
        Admin = Address.FromPublicKey(victimKeyPair.PublicKey)
    });
    result.TransactionResult.Error.ShouldContain("No permission");
}
```

This test demonstrates that an attacker can register any public key as a candidate with themselves as admin, quit the election on the victim's behalf, and prevent the victim from reclaiming control.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L19-57)
```csharp
    public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

        // Permission check
        var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
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

        State.CandidateAdmins[pubkey] = input.Admin;

        var pubkeyByteString = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(pubkey));

        var newAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[input.Admin] ?? new PubkeyList();
        if (!newAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            newAdminManagedPubkeys.Value.Add(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[input.Admin] = newAdminManagedPubkeys;

        var oldAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender] ?? new PubkeyList();
        if (oldAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            oldAdminManagedPubkeys.Value.Remove(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[Context.Sender] = oldAdminManagedPubkeys;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-96)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);
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

**File:** protobuf/election_contract.proto (L38-39)
```text
    rpc AnnounceElectionFor (AnnounceElectionForInput) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
