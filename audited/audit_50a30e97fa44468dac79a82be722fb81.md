### Title
Unauthorized Candidate Admin Control via AnnounceElectionFor with Null Admin and Contract Caller

### Summary
The `AnnounceElectionFor` function allows anyone to announce anyone else as a candidate without the candidate's consent. When `input.Admin` is null, line 127 correctly defaults the admin to `Context.Sender`, but this creates a critical vulnerability when `Context.Sender` is a contract address. An attacker can deploy an immutable contract that calls `AnnounceElectionFor` with a victim's pubkey and null admin, permanently seizing control of the victim's candidacy with no recourse except Parliament intervention.

### Finding Description

**Location**: [1](#0-0) 

**Root Cause**: The function has two critical flaws:
1. **Missing consent verification**: Unlike `AnnounceElection` which verifies the candidate's signature via `Context.RecoverPublicKey()` [2](#0-1) , `AnnounceElectionFor` accepts any pubkey without signature validation.

2. **Improper admin defaulting**: Line 127 uses `var admin = input.Admin ?? Context.Sender;` [3](#0-2)  which allows the caller to become admin when `input.Admin` is null.

**Why Protections Fail**:
- Once a candidate is announced, they cannot re-announce themselves due to the check at [4](#0-3) 
- The victim cannot reclaim admin via `SetCandidateAdmin` because it requires being the current admin or Parliament [5](#0-4) 
- Only the admin can quit the election [6](#0-5) 

**Execution Path**:
1. Attacker deploys an immutable contract with no admin transfer or quit functions
2. Contract approves 100,000 ELF to Election contract [7](#0-6) 
3. Contract calls `AnnounceElectionFor` with victim's pubkey and `Admin = null`
4. Line 127 sets admin to the contract address [8](#0-7) 
5. Admin mapping is stored [9](#0-8) 
6. Victim's pubkey is permanently under contract control

### Impact Explanation

**Authorization Impact**:
- Attacker gains unauthorized admin control over any victim's candidacy
- Victim loses the ability to manage their own election participation

**Operational Impact**:
- **DoS of self-announcement**: Victim cannot call `AnnounceElection` for their own pubkey (blocked by duplicate check)
- **Loss of control**: Victim cannot quit election or change admin without Parliament
- **Permanent lock**: If attacker uses an immutable contract, the situation is permanent until Parliament intervenes

**Affected Parties**:
- Any user whose pubkey is announced without consent
- The election system's integrity (candidates exist without real participation intent)

**Severity Justification**: Medium
- No direct fund theft (attacker's locked tokens are refundable via quit)
- Significant governance/operational impact (unauthorized control, DoS)
- Requires external governance intervention to resolve
- Low attack cost with permanent consequences

### Likelihood Explanation

**Attacker Capabilities**:
- Must deploy a contract (trivial)
- Must have 100,000 ELF to lock (modest requirement, fully refundable) [7](#0-6) 
- Must approve tokens to Election contract (standard operation)

**Attack Complexity**: Very low
- Single transaction from contract
- No timing requirements
- No race conditions
- No complex state manipulation

**Feasibility Conditions**:
- Target pubkey must not already be a candidate
- Target must not be an initial miner [10](#0-9) 
- These are common conditions for most addresses

**Economic Rationality**: Highly rational
- Attack cost: Only opportunity cost of locked tokens (refundable via contract quit)
- Impact: Permanent control over victim's candidacy
- Detection: Publicly visible on-chain but victim has no technical recourse

**Probability**: High - All preconditions are easily met and attack is straightforward to execute

### Recommendation

**Code-Level Mitigation**:

1. **Add consent verification** in `AnnounceElectionFor`:
   ```csharp
   // After line 125, add signature verification
   var candidateAddress = Address.FromPublicKey(pubkeyBytes);
   Assert(Context.Sender == candidateAddress || 
          Context.Sender == GetParliamentDefaultAddress(),
          "Only candidate or Parliament can announce election for a pubkey.");
   ```

2. **Remove admin defaulting to Context.Sender**:
   ```csharp
   // Replace line 127 with:
   Assert(input.Admin != null, "Admin address must be explicitly provided.");
   var admin = input.Admin;
   ```
   Or require explicit admin that must be the candidate's address:
   ```csharp
   var admin = input.Admin ?? address; // Default to candidate's address, not Context.Sender
   ```

3. **Add protection check** similar to regular `AnnounceElection`:
   ```csharp
   // After line 126, add:
   Assert(State.ManagedCandidatePubkeysMap[address] == null, 
          "Candidate cannot be others' admin.");
   ```

**Invariant Checks**:
- Admin must be either the candidate's own address or explicitly authorized
- Candidate must provide consent (signature or explicit call)
- Context.Sender should never automatically become admin without candidate consent

**Test Cases**:
1. Test that `AnnounceElectionFor` with null admin from non-candidate address fails
2. Test that contract cannot become admin by passing null admin
3. Test that only candidate's address or explicitly provided admin can be set
4. Test that victim can reclaim control if unauthorized announcement occurs

### Proof of Concept

**Initial State**:
- Attacker has 100,000 ELF
- Victim has a pubkey but has not announced as candidate
- Attacker deploys MinimalContract (immutable, no functions)

**Transaction Steps**:

1. **Deploy immutable contract**:
   ```
   Contract: MinimalContract (no quit/transfer functions)
   Address: 0xMaliciousContract
   ```

2. **Approve tokens from contract**:
   ```
   From: MinimalContract
   To: ElectionContract
   Call: TokenContract.Approve(ElectionContract, 100000_00000000)
   ```

3. **Call AnnounceElectionFor with null admin**:
   ```
   From: MinimalContract (Context.Sender)
   To: ElectionContract
   Call: AnnounceElectionFor({
     Pubkey: "VictimPubkeyHex",
     Admin: null  // Line 127 defaults to MinimalContract address
   })
   ```

4. **Verify attack success**:
   ```
   Query: GetCandidateAdmin(VictimPubkey)
   Result: 0xMaliciousContract ✓
   
   Query: GetCandidates()
   Result: Contains VictimPubkey ✓
   
   Try: Victim calls AnnounceElection(VictimPubkey)
   Result: FAILS "already announced election" ✓
   
   Try: Victim calls SetCandidateAdmin(VictimPubkey, VictimAddress)
   Result: FAILS "No permission" (not current admin) ✓
   ```

**Expected vs Actual**:
- **Expected**: Admin should be victim's address or explicitly provided, with victim consent
- **Actual**: Admin is attacker's immutable contract, victim has no control

**Success Condition**: Victim's pubkey is permanently controlled by immutable contract with no technical recourse except Parliament intervention.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L29-39)
```csharp
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
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-99)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L149-150)
```csharp
        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L156-157)
```csharp
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L236-236)
```csharp
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
