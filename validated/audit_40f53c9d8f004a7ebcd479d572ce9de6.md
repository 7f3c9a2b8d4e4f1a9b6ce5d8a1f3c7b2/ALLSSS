# Audit Report

## Title
Unauthorized Candidate Registration Enables Preemptive DoS Attack on Election System

## Summary
The `AnnounceElectionFor()` function in the Election contract lacks authorization checks to verify that the caller owns or has permission to register a given public key as a candidate. An attacker can force-register arbitrary public keys by paying the lock deposit, permanently preventing legitimate owners from announcing their candidacy and requiring Parliament intervention to recover.

## Finding Description

The vulnerability exists in the `AnnounceElectionFor()` function which accepts any public key string as input without verifying the caller's ownership or authorization. [1](#0-0) 

The function directly calls the internal `AnnounceElection(byte[] pubkeyBytes)` method without any authorization check that verifies `Context.Sender` owns the private key corresponding to the provided public key. [2](#0-1) 

The internal method enforces that a public key can only be registered once as a current candidate through an assertion that prevents re-registration. [3](#0-2)  Once a public key is registered with `IsCurrentCandidate = true`, any subsequent registration attempt will fail with "This public key already announced election."

In contrast, the legitimate `AnnounceElection(Address input)` method properly verifies ownership by recovering the public key from the transaction signature using `Context.RecoverPublicKey()`, ensuring the caller actually owns the private key. [4](#0-3) 

The attacker sets themselves as the admin for the registered public key. If no admin is explicitly provided in the input, it defaults to `Context.Sender` (the attacker). [5](#0-4)  The admin field controls who can subsequently quit the election or modify admin rights.

Recovery mechanisms are blocked because `SetCandidateAdmin()` requires the caller to be either the current admin (the attacker) or Parliament default address. [6](#0-5)  Once an admin is set, the legitimate public key owner cannot override it without Parliament intervention.

**Attack Sequence:**
1. Attacker calls `AnnounceElectionFor({ Pubkey: "victim_public_key", Admin: attacker_address })` (or omits Admin to default to themselves)
2. Contract locks 100,000 tokens from attacker's balance [7](#0-6) 
3. Victim's public key is registered with attacker as admin
4. Internal check prevents victim from re-registering using either `AnnounceElection()` or `AnnounceElectionFor()`
5. Victim cannot participate in elections or receive mining rewards
6. Only Parliament can change the admin to allow victim to regain control

## Impact Explanation

**Governance Disruption**: An attacker can systematically prevent legitimate validators from participating in elections, effectively censoring candidates and centralizing power to attacker-controlled or pre-existing candidates only. This breaks the decentralized election mechanism that is fundamental to AElf's consensus.

**Candidate Lockout**: Legitimate public key owners lose the ability to register themselves for candidacy, blocking their eligibility for mining rewards, governance participation, and profit distribution from the subsidy scheme. [8](#0-7) 

**Requires Emergency Governance**: Recovery requires Parliament default organization to manually override admin controls for each affected public key, consuming governance bandwidth and delaying election processes.

**Quantified Damage**:
- Attack cost: 100,000 tokens per public key registered
- For typical blockchain with 17-21 miners, validation data center count would be 85-105 (5x multiplier) [9](#0-8) 
- Total attack cost for complete DoS: 8.5M - 10.5M tokens
- Attacker can potentially recover tokens later by quitting elections, reducing net cost

## Likelihood Explanation

**Attacker Capabilities Required**:
- Sufficient token balance to pay lock deposits (100,000 tokens per target)
- Knowledge of target public keys (publicly available for known validators on-chain)
- Ability to execute transactions faster than legitimate candidates (frontrunning potential)

**Attack Complexity**:
- **Low technical complexity**: Single contract call with target public key string
- **No special permissions**: Any account with sufficient token balance can execute
- **Automation feasible**: Can target multiple candidates in parallel transactions

**Economic Feasibility**:
- **Targeted attack** (10-20 key validators): 1M-2M tokens - highly feasible for motivated attacker
- **Complete DoS** (85-105 candidates): 8.5M-10.5M tokens - feasible for well-funded adversary or competitor
- **Reduced net cost**: Tokens can be recovered by calling `QuitElection()` later [10](#0-9) 
- **High-value scenarios**: Governance takeover, competitor elimination, or manipulation justify costs

**Detection/Prevention**:
- No on-chain detection mechanism exists before damage occurs
- Once executed, requires Parliament governance action to remediate
- Legitimate candidates may not realize they're locked out until attempting registration

## Recommendation

Add ownership verification to `AnnounceElectionFor()` by requiring either:

1. **Option A - Signature Verification**: Require a signature from the public key being registered to prove ownership.

2. **Option B - Explicit Authorization**: Only allow authorized addresses (Parliament/specific admin contracts) to call `AnnounceElectionFor()`.

3. **Option C - Remove Function**: If the intended use case doesn't require third-party registration, consider deprecating `AnnounceElectionFor()` and require all candidates to use `AnnounceElection()` which has proper ownership verification.

**Recommended Fix (Option A concept)**:
Add a signature verification parameter to prove the caller has authorization from the public key owner before allowing registration.

## Proof of Concept

```csharp
// Attacker transaction
var attackerAddress = /* attacker's address */;
var victimPubkey = "04abcd..."; // Known validator's public key

// Step 1: Attacker calls AnnounceElectionFor with victim's pubkey
electionContract.AnnounceElectionFor(new AnnounceElectionForInput {
    Pubkey = victimPubkey,
    Admin = attackerAddress  // Or omit to default to Context.Sender
});
// Result: 100,000 tokens locked from attacker, victim's pubkey registered with attacker as admin

// Step 2: Victim tries to register themselves
// This will FAIL because IsCurrentCandidate is already true
victimContract.AnnounceElection(adminAddress);
// Result: Transaction reverts with "This public key already announced election."

// Step 3: Victim tries to change admin
// This will FAIL because only current admin (attacker) or Parliament can change
victimContract.SetCandidateAdmin(new SetCandidateAdminInput {
    Pubkey = victimPubkey,
    Admin = victimAddress
});
// Result: Transaction reverts with "No permission."

// Step 4: Attacker can later recover tokens
attackerContract.QuitElection(new StringValue { Value = victimPubkey });
// Result: 100,000 tokens returned to attacker, victim still locked out until Parliament intervenes
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L156-157)
```csharp
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L211-218)
```csharp
    private void RegisterCandidateToSubsidyProfitScheme(string candidatePubkey)
    {
        if (State.ProfitContract.Value == null)
            State.ProfitContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

        AddBeneficiary(candidatePubkey);
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

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L406-409)
```csharp
    private int GetValidationDataCenterCount()
    {
        return GetMinersCount(new Empty()).Value.Mul(5);
    }
```
