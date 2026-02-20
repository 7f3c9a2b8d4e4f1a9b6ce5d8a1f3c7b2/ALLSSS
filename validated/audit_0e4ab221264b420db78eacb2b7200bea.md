# Audit Report

## Title
Sponsor Fund Misdirection in ReplaceCandidatePubkey Causes Loss of Locked Election Tokens

## Summary
The `ReplaceCandidatePubkey` function contains a critical flaw in sponsor tracking that results in permanent loss of 100,000 ELF tokens. When candidates announce via `AnnounceElection` (self-sponsored), the sponsor mapping is never initialized. Upon pubkey replacement and subsequent `QuitElection`, the locked funds are incorrectly sent to an address derived from the new pubkey instead of the original sponsor who deposited the funds.

## Finding Description

The vulnerability exists in the sponsor tracking mechanism across three contract methods, creating a fund misdirection scenario:

**Root Cause - Missing Sponsor Map Initialization:**

When candidates announce election via `AnnounceElection`, the implementation does not set the `CandidateSponsorMap` state variable [1](#0-0) . This contrasts with `AnnounceElectionFor`, which explicitly records the sponsor [2](#0-1) .

During `AnnounceElection`, tokens are locked from the transaction sender [3](#0-2) , but no sponsor tracking is established.

**Vulnerability - Blind Copy Operation:**

The `PerformReplacement` method performs an unchecked copy of the sponsor mapping [4](#0-3) . Since `CandidateSponsorMap[oldPubkey]` was never initialized, `CandidateSponsorMap[newPubkey]` becomes null.

Simultaneously, the candidate information (including the critical `AnnouncementTransactionId` that identifies the locked funds) is migrated to the new pubkey [5](#0-4) .

**Fund Misdirection - Wrong Recipient:**

During `QuitElection`, the refund logic uses a null-coalescing operator to determine the recipient [6](#0-5) . Since `CandidateSponsorMap[newPubkey]` is null, the funds default to `Address.FromPublicKey(newPubkey)` instead of the original sponsor at `Address.FromPublicKey(oldPubkey)`.

This violates the fundamental sponsor tracking invariant demonstrated in the test suite [7](#0-6)  and confirmed by the `GetSponsor` view method design [8](#0-7) .

## Impact Explanation

**Direct Financial Loss:**
The original sponsor loses exactly 100,000 ELF tokens [9](#0-8) , which are permanently misdirected to an address they do not control.

**Affected Users:**
- Self-sponsored candidates who announced via `AnnounceElection` and subsequently need key rotation due to security incidents
- The original sponsor (address derived from oldPubkey) loses access to their deposited funds
- The funds are sent to an address derived from the newPubkey, which the original sponsor typically does not control

**Broken Security Guarantee:**
The election deposit system's core invariant—that locked funds return to the original depositor—is violated. This breaks a fundamental trust assumption in the election mechanism.

## Likelihood Explanation

**Reachable Entry Points:**
All three methods are publicly accessible with realistic permission requirements:
- `AnnounceElection`: Available to any candidate
- `ReplaceCandidatePubkey`: Requires candidate admin permission [10](#0-9) 
- `QuitElection`: Requires candidate admin permission [11](#0-10) 

**Feasible Preconditions:**
1. Candidate announces via `AnnounceElection` (standard for self-managed candidates)
2. Candidate admin invokes `ReplaceCandidatePubkey` (legitimate operation for key compromise scenarios)
3. Eventually calls `QuitElection` to recover locked funds

**Probability:**
Medium likelihood - While pubkey replacement is not a routine operation, it is an intentional security feature for handling key compromise or loss scenarios. The existing test suite confirms this is expected functionality [12](#0-11) , though it does not verify the refund recipient address.

## Recommendation

Modify the `PerformReplacement` method to properly handle sponsor mapping when the original sponsor was not explicitly set:

```csharp
// In PerformReplacement method (ElectionContract_Maintainence.cs)
// Instead of blindly copying:
State.CandidateSponsorMap[newPubkey] = State.CandidateSponsorMap[oldPubkey];

// Use:
var originalSponsor = State.CandidateSponsorMap[oldPubkey];
if (originalSponsor == null)
{
    // If no explicit sponsor was set, the original pubkey's address is the sponsor
    originalSponsor = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(oldPubkey));
}
State.CandidateSponsorMap[newPubkey] = originalSponsor;
```

This ensures the sponsor mapping always points to the actual depositor, preserving the refund invariant across pubkey replacements.

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_SponsorRefund_Vulnerability_Test()
{
    // Step 1: Announce election with old keypair (self-sponsored via AnnounceElection)
    var oldKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = ValidationDataCenterKeyPairs.Last();
    var candidateAdminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
    
    var oldAddress = Address.FromPublicKey(oldKeyPair.PublicKey);
    var balanceBeforeAnnounce = await GetNativeTokenBalance(oldKeyPair.PublicKey);
    
    await AnnounceElectionAsync(oldKeyPair, candidateAdminAddress);
    
    var balanceAfterAnnounce = await GetNativeTokenBalance(oldKeyPair.PublicKey);
    // Verify 100k ELF was locked from old address
    balanceAfterAnnounce.ShouldBe(balanceBeforeAnnounce - ElectionContractConstants.LockTokenForElection);
    
    // Step 2: Replace pubkey
    var newKeyPair = ValidationDataCenterKeyPairs.Skip(1).First();
    var newAddress = Address.FromPublicKey(newKeyPair.PublicKey);
    
    var candidateAdminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, candidateAdmin);
    await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = oldKeyPair.PublicKey.ToHex(),
        NewPubkey = newKeyPair.PublicKey.ToHex()
    });
    
    // Step 3: Quit election with new pubkey
    var newBalanceBeforeQuit = await GetNativeTokenBalance(newKeyPair.PublicKey);
    var oldBalanceBeforeQuit = await GetNativeTokenBalance(oldKeyPair.PublicKey);
    
    await candidateAdminStub.QuitElection.SendAsync(new StringValue { Value = newKeyPair.PublicKey.ToHex() });
    
    var newBalanceAfterQuit = await GetNativeTokenBalance(newKeyPair.PublicKey);
    var oldBalanceAfterQuit = await GetNativeTokenBalance(oldKeyPair.PublicKey);
    
    // VULNERABILITY: Funds go to new address instead of old address
    // Expected: oldBalanceAfterQuit = oldBalanceBeforeQuit + 100k ELF
    // Actual: newBalanceAfterQuit = newBalanceBeforeQuit + 100k ELF
    newBalanceAfterQuit.ShouldBe(newBalanceBeforeQuit + ElectionContractConstants.LockTokenForElection);
    oldBalanceAfterQuit.ShouldBe(oldBalanceBeforeQuit); // Original sponsor gets nothing!
}
```

## Notes

This vulnerability specifically affects the `AnnounceElection` path (self-sponsored announcements) and does not impact `AnnounceElectionFor` scenarios where sponsor tracking is properly initialized. The issue represents a state management flaw where sponsor identity is lost during pubkey replacement, violating the deposit refund guarantee that is fundamental to the election security model.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-119)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;

        LockCandidateNativeToken();

        AddCandidateAsOption(pubkey);

        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L140-140)
```csharp
        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L177-195)
```csharp
    private void LockCandidateNativeToken()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Lock the token from sender for deposit of announce election
        var lockId = Context.OriginTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        var sponsorAddress = Context.Sender;
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = sponsorAddress,
            To = lockVirtualAddress,
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Lock for announcing election."
        });
    }
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L237-242)
```csharp
        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L320-321)
```csharp
        State.CandidateSponsorMap[newPubkey] = State.CandidateSponsorMap[oldPubkey];
        State.CandidateSponsorMap.Remove(oldPubkey);
```

**File:** test/AElf.Contracts.Election.Tests/BVT/SponsorTests.cs (L52-64)
```csharp
    public async Task ElectionContract_QuitElection_Sponsor_Test()
    {
        await ElectionContract_AnnounceElectionFor_State_Test();

        var candidatesKeyPair = ValidationDataCenterKeyPairs.First();
        var sponsorKeyPair = ValidationDataCenterKeyPairs.Last();
        var balanceBeforeAnnouncing = await GetNativeTokenBalance(sponsorKeyPair.PublicKey);

        await QuitElectionAsync(candidatesKeyPair);

        var balanceAfterAnnouncing = await GetNativeTokenBalance(sponsorKeyPair.PublicKey);
        balanceAfterAnnouncing.ShouldBe(balanceBeforeAnnouncing + ElectionContractConstants.LockTokenForElection);
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L421-425)
```csharp
    public override Address GetSponsor(StringValue input)
    {
        return State.CandidateSponsorMap[input.Value] ??
               Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ReplaceCandidateTests.cs (L14-86)
```csharp
    public async Task ElectionContract_ReplaceCandidatePubkey_Test()
    {
        var announceElectionKeyPair = ValidationDataCenterKeyPairs.First();
        var candidateAdmin = ValidationDataCenterKeyPairs.Last();
        var candidateAdminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
        await AnnounceElectionAsync(announceElectionKeyPair, candidateAdminAddress);

        // Check candidate admin
        {
            var admin = await ElectionContractStub.GetCandidateAdmin.CallAsync(new StringValue
                { Value = announceElectionKeyPair.PublicKey.ToHex() });
            admin.ShouldBe(candidateAdminAddress);
        }

        // Check candidates.
        {
            var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
            candidates.Value.ShouldContain(ByteString.CopyFrom(announceElectionKeyPair.PublicKey));
        }

        var candidateAdminStub =
            GetTester<ElectionContractImplContainer.ElectionContractImplStub>(ElectionContractAddress,
                candidateAdmin);
        var newKeyPair = ValidationDataCenterKeyPairs.Skip(1).First();
        await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
        {
            OldPubkey = announceElectionKeyPair.PublicKey.ToHex(),
            NewPubkey = newKeyPair.PublicKey.ToHex()
        });

        // Check candidates again.
        {
            var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
            candidates.Value.ShouldContain(ByteString.CopyFrom(newKeyPair.PublicKey));
            candidates.Value.ShouldNotContain(ByteString.CopyFrom(announceElectionKeyPair.PublicKey));
        }

        // Check candidate information
        {
            var oldCandidateInformation =
                await ElectionContractStub.GetCandidateInformation.CallAsync(new StringValue
                    { Value = announceElectionKeyPair.PublicKey.ToHex() });
            oldCandidateInformation.IsCurrentCandidate.ShouldBeFalse();
            var newPubkeyInformation =
                await ElectionContractStub.GetCandidateInformation.CallAsync(new StringValue
                    { Value = newKeyPair.PublicKey.ToHex() });
            newPubkeyInformation.IsCurrentCandidate.ShouldBeTrue();
        }

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
    }
```
