# Audit Report

## Title
Sponsor Fund Misdirection in ReplaceCandidatePubkey Causes Loss of Locked Election Tokens

## Summary
The `ReplaceCandidatePubkey` function blindly copies the sponsor mapping from old to new pubkey without validation. When a candidate announces via `AnnounceElection` (not `AnnounceElectionFor`), the sponsor map is never initialized. Upon replacement and subsequent `QuitElection`, the locked 100,000 tokens are sent to the address derived from the new pubkey instead of the original sponsor, resulting in permanent fund loss.

## Finding Description

The vulnerability exists in the sponsor tracking mechanism across three contract methods:

**Root Cause - Missing Sponsor Map Initialization:**
When candidates announce via `AnnounceElection`, the `CandidateSponsorMap` is never set [1](#0-0) , unlike `AnnounceElectionFor` which explicitly sets it [2](#0-1) .

**Vulnerability - Blind Copy Operation:**
During pubkey replacement, the `PerformReplacement` method blindly copies the sponsor mapping without validation [3](#0-2) . Since `CandidateSponsorMap[oldPubkey]` was never set, `CandidateSponsorMap[newPubkey]` becomes null. The candidate information, including the original `AnnouncementTransactionId` that identifies the locked funds, is transferred to the new pubkey [4](#0-3) .

**Fund Misdirection - Wrong Recipient:**
When `QuitElection` is called, the refund logic uses the null-coalescing operator to determine the recipient [5](#0-4) . Since `CandidateSponsorMap[newPubkey]` is null, funds default to `Address.FromPublicKey(newPubkey)` instead of the original sponsor at `Address.FromPublicKey(oldPubkey)`.

This violates the sponsor tracking invariant demonstrated in the existing test suite, where sponsors are guaranteed to receive refunds [6](#0-5) . The `GetSponsor` view method also confirms this design pattern [7](#0-6) .

## Impact Explanation

**Direct Financial Loss:**
The original sponsor loses exactly 100,000 ELF tokens (100,000 × 10^8 base units) [8](#0-7) .

**Affected Users:**
- Candidates who announced election via `AnnounceElection` (self-sponsored) and later need key rotation
- The funds are permanently misdirected to an address derived from the new pubkey, which is typically not controlled by the original sponsor

**Broken Security Guarantee:**
The sponsor tracking mechanism ensures locked funds return to the original depositor. This is a fundamental invariant of the election deposit system, as evidenced by the explicit sponsor tracking in `AnnounceElectionFor` and the refund logic in `QuitElection`.

## Likelihood Explanation

**Reachable Entry Points:**
All three methods are publicly accessible with realistic permission requirements:
- `AnnounceElection`: Available to any candidate
- `ReplaceCandidatePubkey`: Requires candidate admin permission [9](#0-8) 
- `QuitElection`: Requires candidate admin permission [10](#0-9) 

**Feasible Preconditions:**
1. Candidate announces via `AnnounceElection` (common for self-managed candidates or initial miners)
2. Candidate admin invokes `ReplaceCandidatePubkey` (legitimate key rotation scenario for key compromise/loss)
3. Eventually calls `QuitElection` to recover locked funds

**Probability:**
Medium - While pubkey replacement is not everyday operation, it is an intentional feature for handling security incidents. The test suite confirms this is expected functionality [11](#0-10) , though tests don't verify refund recipients after replacement.

## Recommendation

Add validation before copying the sponsor mapping in `PerformReplacement`:

```csharp
private void PerformReplacement(string oldPubkey, string newPubkey)
{
    // ... existing code ...
    
    // Fix: Ensure sponsor mapping is properly initialized before copying
    var oldSponsor = State.CandidateSponsorMap[oldPubkey];
    if (oldSponsor == null)
    {
        // If no explicit sponsor was set, the original pubkey address is the implicit sponsor
        oldSponsor = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(oldPubkey));
    }
    State.CandidateSponsorMap[newPubkey] = oldSponsor;
    State.CandidateSponsorMap.Remove(oldPubkey);
    
    // ... rest of existing code ...
}
```

This ensures that when a candidate self-announces via `AnnounceElection`, their original address is preserved as the sponsor even after pubkey replacement.

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_MisdirectsFunds_WhenAnnouncedViaAnnounceElection()
{
    // Setup: Candidate announces via AnnounceElection (not AnnounceElectionFor)
    var oldKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = ValidationDataCenterKeyPairs.Last();
    var candidateAdminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
    
    // Announce election (this does NOT set CandidateSponsorMap)
    await AnnounceElectionAsync(oldKeyPair, candidateAdminAddress);
    
    var oldPubkeyAddress = Address.FromPublicKey(oldKeyPair.PublicKey);
    var oldBalance = await GetNativeTokenBalance(oldKeyPair.PublicKey);
    
    // Replace pubkey
    var newKeyPair = ValidationDataCenterKeyPairs.Skip(1).First();
    var candidateAdminStub = GetElectionContractTester(candidateAdmin);
    await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = oldKeyPair.PublicKey.ToHex(),
        NewPubkey = newKeyPair.PublicKey.ToHex()
    });
    
    var newPubkeyAddress = Address.FromPublicKey(newKeyPair.PublicKey);
    var newPubkeyBalanceBefore = await GetNativeTokenBalance(newKeyPair.PublicKey);
    
    // Quit election - funds should go back to oldPubkeyAddress but go to newPubkeyAddress
    await candidateAdminStub.QuitElection.SendAsync(new StringValue 
    { 
        Value = newKeyPair.PublicKey.ToHex() 
    });
    
    var oldBalanceAfter = await GetNativeTokenBalance(oldKeyPair.PublicKey);
    var newPubkeyBalanceAfter = await GetNativeTokenBalance(newKeyPair.PublicKey);
    
    // VULNERABILITY: Original sponsor (oldPubkeyAddress) did not receive refund
    oldBalanceAfter.ShouldBe(oldBalance); // No change - funds lost!
    
    // VULNERABILITY: New pubkey address received the funds instead
    newPubkeyBalanceAfter.ShouldBe(newPubkeyBalanceBefore + ElectionContractConstants.LockTokenForElection);
}
```

## Notes

This vulnerability only affects candidates who announce via `AnnounceElection`. Candidates who use `AnnounceElectionFor` are not affected because the sponsor mapping is explicitly set. The issue demonstrates a gap between the two announcement methods where implicit sponsor tracking (self-sponsorship) is not preserved during pubkey replacement.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L237-243)
```csharp
        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }
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
