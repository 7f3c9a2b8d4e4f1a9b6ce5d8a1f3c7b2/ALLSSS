### Title
Admin Hijacking via AnnounceElectionFor Enables ProfitsReceiver Redirect After Candidate Quits

### Summary
After a candidate quits election, any attacker can call `AnnounceElectionFor` to re-announce the same pubkey with an attacker-controlled admin address, completely hijacking the candidate's admin role. The attacker can then call `SetProfitsReceiver` to redirect all future mining rewards and candidate subsidies to an attacker-controlled address. The original candidate cannot recover control through normal means.

### Finding Description

**Root Cause:**

The `QuitElection` method fails to clear the `CandidateAdmins` mapping when a candidate quits, only setting `IsCurrentCandidate = false`. [1](#0-0) 

The `AnnounceElectionFor` method has **no permission checks** and allows anyone to announce election for any pubkey. It only validates that the pubkey is not already a current candidate via the `AnnounceElection` helper, which checks `!candidateInformation.IsCurrentCandidate`. [2](#0-1) 

After passing the check, `AnnounceElectionFor` unconditionally overwrites the admin: `State.CandidateAdmins[pubkey] = admin;` [3](#0-2) 

**Exploitation Path:**

1. Legitimate candidate Alice quits election (sets `IsCurrentCandidate = false`, but `CandidateAdmins[Alice's pubkey]` remains set to Admin A)

2. Attacker Bob calls `AnnounceElectionFor(Alice's pubkey, Admin B)` where Admin B is attacker-controlled

3. The `AnnounceElection` helper at line 156 checks `!candidateInformation.IsCurrentCandidate` - this **passes** because Alice quit [4](#0-3) 

4. Line 128 overwrites: `State.CandidateAdmins[pubkey] = Admin B`, hijacking the admin role

5. Bob (via Admin B) calls `SetProfitsReceiver` in Treasury contract to set attacker's address as the profits receiver. The authorization check passes because `GetCandidateAdmin` now returns Admin B. [5](#0-4) 

6. `ProfitsReceiverMap[Alice's pubkey]` is now set to attacker's address [6](#0-5) 

**Why Existing Protections Fail:**

The `SetCandidateAdmin` method requires the sender to be either the Parliament default address or the current admin. After hijacking, the attacker IS the current admin, so the original candidate cannot use this method to recover. [7](#0-6) 

The original candidate also cannot re-announce themselves because `IsCurrentCandidate` is already true after the attacker's `AnnounceElectionFor` call.

**Reward Redirection Confirmation:**

When miner rewards are distributed, `UpdateBasicMinerRewardWeights` uses `GetProfitsReceiver(i.Pubkey)` to determine the beneficiary, which reads from the hijacked `ProfitsReceiverMap`. [8](#0-7) 

For backup candidate subsidies, `AddBeneficiary` calls `GetBeneficiaryAddress` which uses `GetProfitsReceiverOrDefault`, also reading from the hijacked mapping. [9](#0-8) 

### Impact Explanation

**Direct Fund Theft:**
- All miner rewards (10% of Treasury distribution via BasicRewardHash) meant for the hijacked pubkey are redirected to the attacker
- All backup candidate subsidies (5% of Treasury distribution via SubsidyHash) are redirected to the attacker
- If the hijacked candidate's pubkey later becomes a top miner, this could amount to significant value over time

**Denial of Service:**
- The original candidate permanently loses control of their pubkey's admin role
- They cannot set their own profits receiver even if they regain voting support
- Recovery requires Parliament governance intervention, which is complex and slow

**Who Is Affected:**
- Any candidate who has quit election is vulnerable to immediate admin hijacking
- Former miners who are no longer in consensus but may return
- Backup candidates in the data center who temporarily withdraw

**Severity Justification:** 
Critical - This enables direct theft of protocol reward distributions through unauthorized modification of `ProfitsReceiverMap`, violating the core invariant that "Profit/Treasury/TokenHolder share calculations, donation/release logic, dividend distribution and settlement accuracy" must be maintained.

### Likelihood Explanation

**Attacker Capabilities:**
- Any address with 100,000 tokens (LockTokenForElection amount) [10](#0-9) 
- No special privileges required
- Can monitor blockchain for QuitElection events to identify targets

**Attack Complexity:**
- Low - Two simple transactions: (1) `AnnounceElectionFor`, (2) `SetProfitsReceiver`
- All steps are deterministic with no race conditions
- No timing constraints beyond acting before the original candidate

**Feasibility Conditions:**
- A candidate must have quit election (common during term transitions, regulatory changes, or planned maintenance)
- The attacker must act before the original candidate re-announces (if ever)
- Attack window is unbounded - vulnerability persists indefinitely after quit

**Economic Rationality:**
- Attack cost: 100,000 tokens locked (refundable if attacker later quits)
- Potential gain: All future rewards for a miner/backup candidate, which could be orders of magnitude higher
- Example: A top miner receiving 1/17th of 10% Treasury allocation per term could yield millions in rewards
- Risk/reward ratio is extremely favorable for the attacker

**Detection/Operational Constraints:**
- Difficult to detect until rewards are claimed
- No on-chain alert mechanism for admin changes
- Victim may not notice until they try to reclaim control or check reward distributions

**Probability Assessment:** High likelihood given the low barrier to entry, unbounded attack window, and favorable economics.

### Recommendation

**Immediate Mitigation:**

1. **Add permission check to AnnounceElectionFor:**
```
In ElectionContract_Candidate.cs, line 121-142, add validation that sender must own the pubkey:
    - After line 125, add: Assert(Context.Sender == address, "No permission to announce election for others.");
    - Alternatively, require sender to be the existing admin if one is set
```

2. **Clear admin mapping on quit:**
```
In ElectionContract_Candidate.cs QuitElection method, after line 254, add:
State.CandidateAdmins.Remove(initialPubkey);
State.ManagedCandidatePubkeysMap.Remove(initialPubkey);
```

3. **Prevent admin overwrite on re-announcement:**
```
In ElectionContract_Candidate.cs AnnounceElectionFor, line 127-128, change to:
if (State.CandidateAdmins[pubkey] == null)
    State.CandidateAdmins[pubkey] = admin;
```

**Invariant Checks to Add:**

- Assert that `SetProfitsReceiver` caller is either the admin for an active candidate OR the address derived from the pubkey itself
- Add events for admin changes to enable monitoring
- Implement a time-lock or two-step process for profits receiver changes

**Test Cases:**

1. Test that after QuitElection, CandidateAdmins mapping is cleared
2. Test that AnnounceElectionFor fails if caller doesn't own the pubkey
3. Test that AnnounceElectionFor preserves existing admin if re-announcing
4. Test that SetProfitsReceiver fails if candidate has quit
5. Test end-to-end: quit → hijack attempt → should fail

### Proof of Concept

**Initial State:**
- Alice announces election with Admin A address
- Alice is a candidate with `IsCurrentCandidate = true`
- `CandidateAdmins[Alice's pubkey] = Admin A`

**Attack Steps:**

1. **Admin A calls QuitElection:**
   - Input: `{ Value: Alice's pubkey }`
   - Result: `IsCurrentCandidate = false`, but `CandidateAdmins[Alice's pubkey]` still equals Admin A

2. **Attacker Bob calls AnnounceElectionFor:**
   - Input: `{ Pubkey: Alice's pubkey, Admin: Bob's address }`
   - Transaction cost: 100,000 tokens locked
   - Check at line 156: `!candidateInformation.IsCurrentCandidate` → TRUE (passes)
   - Execution: `State.CandidateAdmins[Alice's pubkey] = Bob's address`
   - Result: Bob is now the admin, `IsCurrentCandidate = true`

3. **Bob calls SetProfitsReceiver:**
   - Input: `{ Pubkey: Alice's pubkey, ProfitsReceiverAddress: Attacker's wallet }`
   - Authorization at line 608: `GetCandidateAdmin` returns Bob's address
   - Check at line 609: `Context.Sender == Bob's address` → TRUE (passes)
   - Execution: `State.ProfitsReceiverMap[Alice's pubkey] = Attacker's wallet`

4. **Alice's pubkey becomes a miner or enters data center**

5. **Rewards distributed:**
   - `UpdateBasicMinerRewardWeights` calls `GetProfitsReceiver(Alice's pubkey)` at line 816
   - Returns: Attacker's wallet (from hijacked ProfitsReceiverMap)
   - Result: All mining rewards sent to attacker

**Expected vs Actual:**
- Expected: Only Admin A can control profits receiver for Alice's pubkey
- Actual: Attacker Bob gains full admin control and redirects all rewards to attacker wallet

**Success Condition:** 
Attacker successfully receives reward tokens that should have gone to Alice's designated receiver, while Alice cannot recover control without Parliament intervention.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-162)
```csharp
        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-279)
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
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L601-629)
```csharp
    public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
    {
        if (State.ElectionContract.Value == null)
            State.ElectionContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        var pubkey = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.Pubkey));
        
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
        
        var candidateList = State.ElectionContract.GetCandidates.Call(new Empty());
        Assert(candidateList.Value.Contains(pubkey),"Pubkey is not a candidate.");

        var previousProfitsReceiver = State.ProfitsReceiverMap[input.Pubkey];
        //Set same profits receiver address.
        if (input.ProfitsReceiverAddress == previousProfitsReceiver)
        {
            return new Empty();
        }
        State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
        State.ElectionContract.SetProfitsReceiver.Send(new AElf.Contracts.Election.SetProfitsReceiverInput
        {
            CandidatePubkey = input.Pubkey,
            ReceiverAddress = input.ProfitsReceiverAddress,
            PreviousReceiverAddress = previousProfitsReceiver ?? new Address()
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L814-818)
```csharp
                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
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

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
