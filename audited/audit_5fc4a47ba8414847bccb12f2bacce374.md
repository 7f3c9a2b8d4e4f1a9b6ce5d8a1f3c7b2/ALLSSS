### Title
Unauthorized Admin Takeover via AnnounceElectionFor After Candidate Quits Election

### Summary
The `AnnounceElectionFor` method unconditionally overwrites the `CandidateAdmins` mapping for any pubkey that has quit election, allowing an attacker to seize admin control without authorization. This enables the attacker to replace the candidate's pubkey with one they control, potentially hijacking the validator position and inheriting associated voting weight and reputation.

### Finding Description

The vulnerability exists in the interaction between `QuitElection` and `AnnounceElectionFor` methods:

**Root Cause 1 - Admin Mapping Not Cleared on Quit:**
When a candidate calls `QuitElection`, the method sets `IsCurrentCandidate = false` and removes the candidate from active lists, but critically fails to clear the `CandidateAdmins` mapping. [1](#0-0) 

The admin mapping remains populated with the original owner's admin address, creating a stale state.

**Root Cause 2 - Unconditional Admin Overwrite:**
The `AnnounceElectionFor` method allows anyone to announce election on behalf of any pubkey, setting an arbitrary admin address. At line 128, it unconditionally sets `State.CandidateAdmins[pubkey] = admin` without any authorization checks or validation that an admin already exists. [2](#0-1) 

**Root Cause 3 - Re-announcement Allowed for Quit Candidates:**
The private `AnnounceElection` method permits re-announcing a pubkey that was previously a candidate but quit (IsCurrentCandidate = false), enabling the overwrite attack. [3](#0-2) 

**Why Protections Fail:**
The `CandidateAdmins` state mapping is designed to track the admin address for each candidate pubkey. [4](#0-3) 

However, no protection exists against overwriting an existing admin mapping when re-announcing a quit candidate. The method assumes that if a candidate can be announced, it's safe to set the admin, without considering that:
1. The pubkey may have historical admin ownership
2. The caller may not have permission from the original owner
3. No signature verification proves the caller controls the pubkey

### Impact Explanation

**Direct Unauthorized Control:**
Once the attacker becomes admin, they gain full administrative control over the candidate, as verified by multiple operations:

1. **ReplaceCandidatePubkey**: Requires sender to be the admin, allowing the attacker to replace the original pubkey with one they control. [5](#0-4) 

2. **QuitElection**: Requires sender to be the admin of the initial pubkey, enabling the attacker to quit on behalf of the original owner. [6](#0-5) 

3. **SetCandidateAdmin**: If admin is already set, only the current admin can change it, allowing the attacker to consolidate control. [7](#0-6) 

**Validator Position Hijacking:**
By replacing the pubkey with one they control, the attacker can:
- Inherit any existing voting weight associated with the original candidate
- Potentially become elected as a validator using the hijacked candidate slot
- Receive validator rewards and consensus participation rights
- Leverage historical reputation (produced blocks, terms served) of the original candidate

**Affected Parties:**
- Original candidate owners who quit election lose control over their candidate identity
- The election system's integrity is compromised as candidate ownership becomes insecure
- Voters who previously supported the candidate unknowingly support the attacker
- The broader consensus mechanism is threatened if attackers gain validator positions

**Severity: CRITICAL** - This violates the fundamental invariant that admin control should only be authorized by the legitimate owner or governance, and enables complete takeover of candidate operations including potential validator hijacking.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to call public contract methods (any blockchain user)
- Sufficient native tokens to pay the announcement fee (`ElectionContractConstants.LockTokenForElection`)
- No special permissions, signatures, or trusted role access needed

**Attack Complexity: LOW**
Single transaction attack:
1. Identify a pubkey that has quit election (public information via `GetCandidateInformation`)
2. Call `AnnounceElectionFor(quitPubkey, attackerAddress)` 
3. Immediately gain admin control

**Feasibility Conditions:**
- Target candidate must have called `QuitElection` (common operation when validators retire or change strategy)
- No time window restrictions - the vulnerability persists indefinitely after quit
- The test suite confirms re-announcement is intentionally supported functionality [8](#0-7) 

**Economic Rationality:**
- Attack cost: Only the announcement deposit (e.g., 100,000 tokens), which is recoverable by quitting again
- Potential gain: Validator position, block rewards, voting influence, reputation inheritance
- Risk/reward ratio heavily favors the attacker

**Detection Constraints:**
- No on-chain mechanism to detect unauthorized admin changes
- Original owners may not monitor their quit candidates
- State overwrite appears as legitimate re-announcement in transaction logs

**Probability: HIGH** - The vulnerability is trivially exploitable with minimal cost whenever any candidate quits election, which is a regular occurrence in validator set management.

### Recommendation

**Immediate Mitigation:**
Modify `AnnounceElectionFor` to prevent admin overwrite without authorization:

```csharp
public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
{
    var pubkey = input.Pubkey;
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
    var address = Address.FromPublicKey(pubkeyBytes);
    AnnounceElection(pubkeyBytes);
    var admin = input.Admin ?? Context.Sender;
    
    // FIX: Check if admin already exists for this pubkey
    var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
    var existingAdmin = State.CandidateAdmins[initialPubkey];
    
    if (existingAdmin != null && existingAdmin != new Address())
    {
        // Only allow re-announcement if:
        // 1. Caller is the existing admin, OR
        // 2. Caller is Parliament (governance override)
        Assert(Context.Sender == existingAdmin || 
               Context.Sender == GetParliamentDefaultAddress(),
               "Cannot overwrite existing admin without permission.");
    }
    
    State.CandidateAdmins[initialPubkey] = admin;  // Use initial pubkey for consistency
    // ... rest of method
}
```

**Additional Hardening:**
1. Clear `CandidateAdmins` mapping in `QuitElection` to prevent stale state: [9](#0-8) 
   Add: `State.CandidateAdmins.Remove(initialPubkey);` after line 275

2. Add invariant check: Admin mapping should use initial pubkey consistently (currently `AnnounceElectionFor` uses current pubkey at line 128)

3. Emit event when admin changes for audit trail

**Regression Prevention:**
Add test cases:
1. Attempt `AnnounceElectionFor` on quit candidate by non-owner → should fail
2. Original owner re-announces after quit → should succeed
3. Verify admin mapping cleared after quit or preserved only for authorized re-announcement

### Proof of Concept

**Initial State:**
- Alice has keypair with pubkeyA
- Alice has balance of 200,000 tokens
- Bob (attacker) has balance of 200,000 tokens

**Transaction Sequence:**

1. **Alice announces election:**
   ```
   Call: AnnounceElection(admin=Alice's address)
   Signed by: Alice's private key
   Result: CandidateAdmins[pubkeyA] = Alice
   ```

2. **Alice quits election:**
   ```
   Call: QuitElection(pubkeyA)
   Signed by: Alice's private key
   Result: CandidateInformation[pubkeyA].IsCurrentCandidate = false
           CandidateAdmins[pubkeyA] still = Alice (NOT CLEARED)
   ```

3. **Bob exploits - announces for Alice's pubkey:**
   ```
   Call: AnnounceElectionFor(pubkey=pubkeyA, admin=Bob's address)
   Signed by: Bob's private key
   Result: CandidateAdmins[pubkeyA] = Bob (OVERWRITES Alice)
   ```

4. **Bob verifies admin takeover:**
   ```
   Call: GetCandidateAdmin(pubkeyA)
   Result: Returns Bob's address
   ```

5. **Bob replaces pubkey with one he controls:**
   ```
   Call: ReplaceCandidatePubkey(oldPubkey=pubkeyA, newPubkey=pubkeyB)
   Signed by: Bob's private key
   Result: Candidate now uses pubkeyB (Bob's key)
           Bob can act as validator if elected
   ```

**Expected vs Actual:**
- Expected: Step 3 should FAIL with "No permission" - only Alice or Parliament should modify Alice's candidate admin
- Actual: Step 3 SUCCEEDS - Bob becomes admin and gains full control

**Success Condition:**
After step 3, `GetCandidateAdmin(pubkeyA)` returns Bob's address instead of Alice's, confirming unauthorized admin takeover. Bob can then execute admin-only operations like `ReplaceCandidatePubkey` and `QuitElection` without Alice's authorization.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L35-39)
```csharp
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-280)
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

        // Update candidate information.
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;

        // Remove candidate public key from the Voting Item options.
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
        var dataCenterList = State.DataCentersRankingList.Value;
        if (dataCenterList.DataCenters.ContainsKey(pubkey))
        {
            dataCenterList.DataCenters[pubkey] = 0;
            UpdateDataCenterAfterMemberVoteAmountChanged(dataCenterList, pubkey, true);
            State.DataCentersRankingList.Value = dataCenterList;
        }

        var managedCandidatePubkey = State.ManagedCandidatePubkeysMap[Context.Sender];
        managedCandidatePubkey.Value.Remove(ByteString.CopyFrom(pubkeyBytes));
        if (managedCandidatePubkey.Value.Any())
            State.ManagedCandidatePubkeysMap[Context.Sender] = managedCandidatePubkey;
        else
            State.ManagedCandidatePubkeysMap.Remove(Context.Sender);

        State.CandidateSponsorMap.Remove(pubkey);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L65-68)
```csharp
    /// <summary>
    ///     Pubkey -> Address who has the authority to replace it.
    /// </summary>
    public MappedState<string, Address> CandidateAdmins { get; set; }
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

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L104-119)
```csharp
    public async Task ElectionContract_AnnounceElectionAgain_Test()
    {
        await ElectionContract_QuiteElection_Test();

        var candidatesKeyPair = ValidationDataCenterKeyPairs.First();

        var balanceBeforeAnnouncing = await GetNativeTokenBalance(candidatesKeyPair.PublicKey);
        balanceBeforeAnnouncing.ShouldBe(ElectionContractConstants.UserInitializeTokenAmount);

        await AnnounceElectionAsync(candidatesKeyPair);

        var balanceAfterAnnouncing = await GetNativeTokenBalance(candidatesKeyPair.PublicKey);

        // Check balance after announcing election.
        balanceBeforeAnnouncing.ShouldBe(balanceAfterAnnouncing + ElectionContractConstants.LockTokenForElection);
    }
```
