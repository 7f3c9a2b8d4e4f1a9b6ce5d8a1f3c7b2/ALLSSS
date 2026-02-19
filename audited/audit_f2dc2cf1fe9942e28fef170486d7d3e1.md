### Title
Unauthorized Candidate Registration via AnnounceElectionFor Allows Admin Privilege Hijacking

### Summary
The `AnnounceElectionFor` method allows any caller to register an arbitrary public key as an election candidate without verifying ownership or obtaining consent from the key holder. The attacker can set themselves (or any address) as the admin, gaining permanent control over the candidate's election status, including the ability to quit elections, replace public keys, and control profit distribution. The legitimate public key owner cannot reclaim admin control without Parliament governance intervention.

### Finding Description

The vulnerability exists in the `AnnounceElectionFor` method [1](#0-0) , which creates candidate entries without verifying that the caller owns or controls the specified public key.

**Root Cause:**

Unlike the regular `AnnounceElection` method which uses `Context.RecoverPublicKey()` to cryptographically verify the caller's identity [2](#0-1) , the `AnnounceElectionFor` method accepts the public key as a string parameter without any ownership verification [3](#0-2) .

The private `AnnounceElection` method creates a new entry in `CandidateInformationMap` for any pubkey that passes basic checks (not an initial miner, not already a candidate, not banned) [4](#0-3) . Critically, at lines 163-171, it creates a new `CandidateInformation` entry without verifying the caller's authority over that pubkey.

The attacker-specified admin is permanently set [5](#0-4) , and the legitimate owner cannot reclaim control because `SetCandidateAdmin` requires either the current admin's permission or Parliament governance intervention [6](#0-5) .

**Why Protections Fail:**

The method only validates that the pubkey is not an initial miner, not already registered, and not banned [7](#0-6) . There is no check verifying that `Context.Sender` has any relationship to or authority over the specified public key.

### Impact Explanation

**Authorization & Governance Impact:**
- Attackers can register any public key as a candidate without the owner's knowledge or consent, violating the fundamental authorization invariant
- The attacker gains permanent admin control over the candidate, allowing them to:
  - Quit the election on the victim's behalf via `QuitElection` [8](#0-7) 
  - Replace the victim's public key via `ReplaceCandidatePubkey` [9](#0-8) 
  - Control profit receivers and reward distribution [10](#0-9) 

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

### Likelihood Explanation

**Reachable Entry Point:**
`AnnounceElectionFor` is a public method directly callable by any user [11](#0-10) .

**Attacker Capabilities:**
- Attacker needs only sufficient native tokens to pay the registration fee (`ElectionContractConstants.LockTokenForElection`) [12](#0-11) 
- No special permissions or trusted role access required
- Can specify any valid public key string as the target

**Attack Complexity:**
Single transaction with straightforward parameters. The attacker simply calls `AnnounceElectionFor` with the victim's public key and their own address as admin.

**Economic Rationality:**
- Cost: Registration fee (tokens are locked, not lost, and returned upon quit)
- Benefit: Full administrative control over a candidate, ability to disrupt elections, control over profit distribution
- Rational for attackers seeking to manipulate validator elections or disrupt specific validators

**Detection Constraints:**
The attack is immediately effective and difficult to reverse without Parliament governance action, making it a practical and severe threat.

### Recommendation

**Immediate Fix:**
Add public key ownership verification to `AnnounceElectionFor`:

1. Require the pubkey owner to provide explicit consent through a signature verification mechanism, or
2. Restrict `AnnounceElectionFor` to only work with a pre-approved whitelist/registry, or  
3. Allow the legitimate pubkey owner to override the admin setting if `State.CandidateAdmins[pubkey]` was set by someone other than the pubkey owner

**Specific Code Changes:**
In the `AnnounceElectionFor` method [1](#0-0) , add a check before calling the private `AnnounceElection`:

```csharp
// Verify that either:
// 1. The caller is the pubkey owner, OR
// 2. A valid signature from the pubkey owner is provided in the input
Assert(Context.Sender == Address.FromPublicKey(pubkeyBytes) || 
       VerifyPubkeyOwnerConsent(input), 
       "Pubkey owner consent required.");
```

**Alternative Fix:**
Modify `SetCandidateAdmin` to allow the legitimate pubkey owner to reclaim admin control even if an admin was already set by a third party [13](#0-12) , adding a special case:

```csharp
if (State.CandidateAdmins[pubkey] == null || 
    Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)))
{
    // Pubkey owner can always set/reclaim admin
}
```

**Test Cases:**
1. Verify that `AnnounceElectionFor` with an unauthorized pubkey fails
2. Verify that only the pubkey owner can initially register themselves via this method
3. Verify that the pubkey owner can reclaim admin control if set by a third party

### Proof of Concept

**Initial State:**
- Victim has a valid public key `VICTIM_PUBKEY` (e.g., from a known validator)
- Victim has never called `AnnounceElection` or `AnnounceElectionFor`
- `State.CandidateInformationMap[VICTIM_PUBKEY]` is null
- `State.CandidateAdmins[VICTIM_PUBKEY]` is null
- Attacker has sufficient tokens to pay registration fee

**Attack Steps:**

1. **Attacker registers victim's pubkey:**
   ```
   Transaction: AnnounceElectionFor({
     pubkey: VICTIM_PUBKEY,
     admin: ATTACKER_ADDRESS
   })
   Sender: ATTACKER_ADDRESS
   ```

2. **Verify malicious registration:**
   - `State.CandidateInformationMap[VICTIM_PUBKEY]` now contains `CandidateInformation` with `IsCurrentCandidate = true` [14](#0-13) 
   - `State.CandidateAdmins[VICTIM_PUBKEY] == ATTACKER_ADDRESS` [15](#0-14) 
   - Victim's pubkey is added to candidate list and voting options

3. **Attacker exercises admin control:**
   ```
   Transaction: QuitElection(VICTIM_PUBKEY)
   Sender: ATTACKER_ADDRESS
   Result: SUCCESS (admin permission check passes)
   ``` [16](#0-15) 

4. **Victim attempts to reclaim control:**
   ```
   Transaction: SetCandidateAdmin({
     pubkey: VICTIM_PUBKEY,
     admin: VICTIM_ADDRESS
   })
   Sender: VICTIM_ADDRESS (derived from VICTIM_PUBKEY)
   Result: FAIL - "No permission" error
   ```
   The victim cannot reclaim control because `State.CandidateAdmins[VICTIM_PUBKEY]` is already set to `ATTACKER_ADDRESS`, and only the current admin can change it [17](#0-16) .

**Expected vs Actual Result:**
- **Expected:** Only the legitimate owner of a public key should be able to register it as a candidate or control its admin settings
- **Actual:** Any party can register any public key and gain permanent admin control, with the legitimate owner unable to reclaim control without Parliament governance intervention

**Success Condition:**
The attack succeeds when `State.CandidateAdmins[VICTIM_PUBKEY]` is permanently set to an attacker-controlled address, and all admin-privileged operations (quit election, replace pubkey, control profits) can be executed by the attacker while the legitimate owner is locked out.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L379-398)
```csharp
    public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName) == Context.Sender,
            "No permission.");
        var rankingList = State.DataCentersRankingList;
        if (!rankingList.Value.DataCenters.ContainsKey(input.CandidatePubkey)) return new Empty();
        var beneficiaryAddress = input.PreviousReceiverAddress.Value.Any()
            ? input.PreviousReceiverAddress
            : Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.CandidatePubkey));
        //set same profits receiver address
        if (beneficiaryAddress == input.ReceiverAddress)
        {
            return new Empty();
        }
        RemoveBeneficiary(input.CandidatePubkey,beneficiaryAddress);
        AddBeneficiary(input.CandidatePubkey,input.ReceiverAddress);

        return new Empty();
    }
```

**File:** protobuf/election_contract.proto (L38-39)
```text
    rpc AnnounceElectionFor (AnnounceElectionForInput) returns (google.protobuf.Empty) {
    }
```
