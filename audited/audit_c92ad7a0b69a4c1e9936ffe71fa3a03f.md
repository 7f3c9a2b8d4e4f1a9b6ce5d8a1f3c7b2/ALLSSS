### Title
Unauthorized Candidate Registration via Missing Permission Check in AnnounceElectionFor

### Summary
The `AnnounceElectionFor` function lacks any permission check to verify that the caller has authority to register the specified public key as a candidate. This allows malicious actors to register arbitrary public keys without owner consent, gain admin control over those candidates, and prevent legitimate owners from participating in elections. The attacker can spam candidate registrations and manipulate the governance candidate list at minimal cost.

### Finding Description

The `AnnounceElectionFor` function accepts an arbitrary public key parameter and registers it as a candidate without verifying the caller has permission to do so. [1](#0-0) 

The function directly uses the input `pubkey` parameter without any authorization check. It calls the internal `AnnounceElection` method which only validates that the pubkey is not an initial miner, not already a current candidate, and not banned: [2](#0-1) 

The attacker becomes admin of the victim's public key: [3](#0-2) 

**Why protections fail:**

1. Unlike `AnnounceElection` which uses `Context.RecoverPublicKey()` to ensure only the key owner can register themselves, `AnnounceElectionFor` accepts any pubkey as a parameter: [4](#0-3) 

2. The only cost is locking 100,000 tokens from `Context.Sender`, which the attacker can recover: [5](#0-4) 

3. Once registered, only the admin can quit the election, blocking the legitimate owner: [6](#0-5) 

4. The victim cannot re-register because the public key is already marked as a current candidate: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
1. **Unauthorized Governance Control**: Attacker gains admin authority over arbitrary candidates in the election system, controlling their participation in consensus miner selection
2. **Denial of Service**: Legitimate node operators cannot register their own public keys once pre-registered by an attacker
3. **Candidate List Manipulation**: Attacker can flood the voting options with controlled fake candidates, diluting legitimate votes
4. **Zero Net Cost**: Attacker recovers the 100,000 token lock by calling `QuitElection`, enabling repeated attacks

**Who is affected:**
- Node operators whose public keys are registered without consent
- Voters who face a polluted candidate list
- The consensus mechanism which relies on legitimate candidate participation

**Severity Justification:**
This is CRITICAL because it violates the fundamental authorization invariant that only a public key owner should control their candidate status. The election contract is core to AEDPoS consensus governance, and unauthorized control over candidates directly impacts miner selection and network security.

### Likelihood Explanation

**Attacker capabilities:**
- Needs 100,000 tokens and approval to Election contract (standard requirements)
- Can obtain any public key from blockchain transaction data
- No special privileges required

**Attack complexity:**
Single transaction call with arbitrary pubkey parameter. The attack is trivial to execute:
```
AnnounceElectionFor(pubkey="victim_pubkey", admin=attacker_address)
```

**Feasibility conditions:**
- Public method accessible to anyone
- No rate limiting or spam prevention
- Economic cost is fully recoverable by calling `QuitElection`
- Multiple victims can be attacked with the same capital by cycling through announce-quit-announce

**Detection/operational constraints:**
The attack is difficult to detect proactively since `AnnounceElectionFor` appears to be a legitimate sponsorship feature. Only when legitimate owners attempt to register themselves will they discover the unauthorized registration.

**Probability:** HIGH - The vulnerability is easily exploitable with standard user capabilities and minimal cost.

### Recommendation

**Code-level mitigation:**

Add a signature verification check in `AnnounceElectionFor` to ensure the caller has authorization from the pubkey owner:

```csharp
public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
{
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
    var address = Address.FromPublicKey(pubkeyBytes);
    
    // NEW: Require that either Context.Sender owns the pubkey OR provides valid authorization
    Assert(Context.Sender == address || VerifyAuthorization(address, input), 
        "No permission to announce election for this public key.");
    
    // ... rest of implementation
}
```

**Alternative approach:** Require explicit opt-in from the pubkey owner before allowing sponsored registration, similar to the `SetCandidateAdmin` pattern: [8](#0-7) 

**Invariant checks to add:**
1. Verify `Context.Sender == Address.FromPublicKey(pubkey)` OR require a pre-approved sponsorship mapping
2. Add maximum candidates per sponsor to prevent spam
3. Emit event when third-party sponsorship occurs for transparency

**Test cases to prevent regression:**
1. Test that unauthorized address cannot call `AnnounceElectionFor` for victim pubkey
2. Test that only pubkey owner can authorize sponsorship
3. Test that spam prevention limits work correctly

### Proof of Concept

**Required initial state:**
- Attacker has 100,000 tokens
- Attacker has approved Election contract to spend tokens
- Victim's public key is known (easily obtained from blockchain)

**Transaction steps:**

1. **Attacker registers victim's public key:**
   ```
   ElectionContract.AnnounceElectionFor({
       Pubkey: "victim_public_key_hex",
       Admin: attacker_address
   })
   ```
   - Result: 100,000 tokens locked from attacker
   - Victim's pubkey registered as candidate
   - Attacker stored as admin for victim's pubkey

2. **Victim attempts to register themselves:**
   ```
   ElectionContract.AnnounceElection(admin_address)
   ```
   - Expected: Successful registration with chosen admin
   - Actual: Transaction FAILS with "This public key already announced election"
   
3. **Victim attempts to quit:**
   ```
   ElectionContract.QuitElection(victim_pubkey)
   ```
   - Expected: Remove candidacy
   - Actual: Transaction FAILS with "Only admin can quit election"

4. **Attacker recovers funds at will:**
   ```
   ElectionContract.QuitElection(victim_pubkey)
   ```
   - Result: SUCCESS, attacker receives 100,000 tokens back
   - Can repeat attack on same or different pubkeys

**Success condition:** 
Attacker successfully controls victim's candidate status, victim cannot self-register or quit, and attacker can repeat the attack with zero net cost.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L19-40)
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L235-236)
```csharp
        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```
