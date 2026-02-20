# Audit Report

## Title
Election Deposit Misrouted to Wrong Address After Pubkey Replacement in Self-Announce Scenario

## Summary
When a candidate self-announces via `AnnounceElection`, the sponsor is not recorded in `CandidateSponsorMap`. If the candidate's pubkey is subsequently replaced via `ReplaceCandidatePubkey`, the 100,000 token deposit is incorrectly refunded to the new pubkey's address instead of the original depositor's address when quitting election, resulting in permanent fund loss.

## Finding Description

The vulnerability stems from inconsistent sponsor tracking between two election announcement paths combined with a flawed fallback mechanism in the refund logic.

**Root Cause:**

When a candidate self-announces election, the `AnnounceElection` method locks 100,000 tokens from `Context.Sender` but does **not** record this payer in `CandidateSponsorMap`. [1](#0-0) 

In contrast, `AnnounceElectionFor` explicitly records the sponsor: [2](#0-1) 

Both methods lock the deposit from `Context.Sender`: [3](#0-2) 

When a pubkey is replaced, the sponsor mapping (including null values) is transferred from old to new pubkey: [4](#0-3) 

The critical flaw occurs in `QuitElection`, which refunds to `CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes)`, where `pubkeyBytes` is derived from the **current** pubkey (input parameter): [5](#0-4) 

After pubkey replacement, this fallback address points to the new pubkey's address, not the original depositor.

**Execution Path:**

1. Alice calls `AnnounceElection` with pubkey_A - 100,000 tokens locked from `Address.FromPublicKey(pubkey_A)`, but `CandidateSponsorMap[pubkey_A]` remains null
2. Admin calls `ReplaceCandidatePubkey(pubkey_A, pubkey_B)` - sponsor mapping transferred as null
3. Admin calls `QuitElection` with pubkey_B - refund goes to `Address.FromPublicKey(pubkey_B)` due to null sponsor
4. Original depositor at `Address.FromPublicKey(pubkey_A)` loses 100,000 tokens

The deposit amount is 100,000 tokens with 8 decimals: [6](#0-5) 

The `GetSponsor` view method confirms this fallback design: [7](#0-6) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes direct, irreversible financial loss:

1. **Fund Misdirection:** 100,000 tokens are permanently transferred to an unintended recipient
2. **Original Depositor Loss:** The address that paid the deposit cannot recover funds through contract mechanisms
3. **Unearned Gain:** The new pubkey's address receives tokens they never deposited
4. **Protocol Invariant Break:** The fundamental principle that deposits are refundable to the payer is violated

The HIGH severity is justified because:
- Causes immediate, quantifiable fund loss (100,000 tokens)
- Irreversible once the transfer occurs
- Breaks the deposit refund guarantee that users rely on
- The `AnnounceElectionFor` path correctly tracks sponsors, proving this functionality should work but is broken for self-announce cases

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability is exploitable through standard contract operations:

**Prerequisites:**
- Candidate uses `AnnounceElection` (self-announce) rather than `AnnounceElectionFor`
- Candidate admin performs pubkey replacement via `ReplaceCandidatePubkey`
- Admin quits election via `QuitElection`

**Attack Complexity: LOW**
- All three methods are public, documented contract operations
- No special privileges beyond normal candidate admin rights
- Simple linear execution with no timing dependencies

**Realistic Scenarios:**

1. **Admin Compromise:** Attacker gains control of admin credentials, replaces pubkey to attacker-controlled key, quits election and receives deposit
2. **Legitimate Key Rotation:** Candidate legitimately rotates to new pubkey after losing old private key, but deposit is lost to new address
3. **Insider Threat:** Malicious admin deliberately replaces pubkey to steal deposit

MEDIUM likelihood (not HIGH) because it requires the specific sequence of self-announce → pubkey replacement → quit, plus either admin compromise or malicious insider. However, pubkey replacement is a documented feature, making this a realistic attack vector.

## Recommendation

Record the sponsor in `AnnounceElection` to maintain consistency with `AnnounceElectionFor`:

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
    
    // FIX: Record the sponsor for self-announce
    State.CandidateSponsorMap[pubkey] = Context.Sender;
    
    AddCandidateAsOption(pubkey);
    
    if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
    {
        State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
        RegisterCandidateToSubsidyProfitScheme(pubkey);
    }
    
    return new Empty();
}
```

This ensures the original depositor is always tracked and receives the refund regardless of pubkey replacements.

## Proof of Concept

```csharp
[Fact]
public async Task Test_DepositMisroutedAfterPubkeyReplacement()
{
    // Setup: Initialize election contract and get candidate keypair
    var candidateKeyPair = SampleKeyPairs.KeyPairs[0];
    var candidatePubkey = candidateKeyPair.PublicKey.ToHex();
    var candidateAddress = Address.FromPublicKey(candidateKeyPair.PublicKey);
    
    var newKeyPair = SampleKeyPairs.KeyPairs[1];
    var newPubkey = newKeyPair.PublicKey.ToHex();
    var newAddress = Address.FromPublicKey(newKeyPair.PublicKey);
    
    // Step 1: Self-announce election (CandidateSponsorMap NOT set)
    var announceResult = await ElectionContractStub.AnnounceElection.SendAsync(candidateAddress);
    announceResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify deposit locked from candidate address
    var candidateBalanceBefore = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = candidateAddress,
        Symbol = "ELF"
    });
    
    // Step 2: Replace pubkey
    var replaceResult = await ElectionContractStub.ReplaceCandidatePubkey.SendAsync(
        new ReplaceCandidatePubkeyInput
        {
            OldPubkey = candidatePubkey,
            NewPubkey = newPubkey
        });
    replaceResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Quit election with new pubkey
    var quitResult = await ElectionContractStub.QuitElection.SendAsync(new StringValue { Value = newPubkey });
    quitResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Deposit went to NEW address instead of original depositor
    var newAddressBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = newAddress,
        Symbol = "ELF"
    });
    
    var candidateBalanceAfter = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = candidateAddress,
        Symbol = "ELF"
    });
    
    // Bug: New address received the 100,000 token deposit
    newAddressBalance.Balance.ShouldBe(100_000_00000000);
    
    // Original depositor did NOT receive refund
    candidateBalanceAfter.Balance.ShouldBe(candidateBalanceBefore.Balance - 100_000_00000000);
}
```

## Notes

This vulnerability highlights a critical inconsistency in the Election contract's deposit tracking mechanism. The existence of proper sponsor tracking in `AnnounceElectionFor` demonstrates that the contract developers understood the need to track original depositors, but failed to apply this same logic to the self-announce path. The pubkey replacement feature, while legitimate, exposes this oversight by allowing the refund address to diverge from the original depositor when combined with the null-sponsor fallback mechanism.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-249)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L320-321)
```csharp
        State.CandidateSponsorMap[newPubkey] = State.CandidateSponsorMap[oldPubkey];
        State.CandidateSponsorMap.Remove(oldPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L421-425)
```csharp
    public override Address GetSponsor(StringValue input)
    {
        return State.CandidateSponsorMap[input.Value] ??
               Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
    }
```
