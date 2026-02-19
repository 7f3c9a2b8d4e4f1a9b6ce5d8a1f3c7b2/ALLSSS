### Title
View Method Data Inconsistency: Address-Based Queries Miss Votes Stored Under Legacy Pubkey Format

### Summary
The `GetElectorVote` view method in the Election contract has asymmetric lookup logic that causes votes stored under the legacy pubkey-based key format to become invisible when queried by address. This creates data inconsistency where users with unmigrated vote records see different results depending on whether they query by pubkey or address, breaking the expected invariant of consistent vote visibility.

### Finding Description

The Election contract's `State.ElectorVotes` mapping historically stored data using pubkey hex strings as keys, but was migrated to use Base58-encoded addresses. [1](#0-0) 

The state-changing methods correctly handle migration through the internal `GetElectorVote(byte[] recoveredPublicKey)` method, which attempts lookup by address first, then by pubkey, and removes the old pubkey-based entry when found. [2](#0-1) 

All new vote storage operations use address-based keys exclusively. [3](#0-2) [4](#0-3) 

However, the public view method `GetElectorVote(string value)` has asymmetric lookup logic that fails to find legacy data when queried by address. [5](#0-4) 

**Root Cause:**

When the input `value` is a valid Base58 address:
1. Line 193 attempts direct lookup: `State.ElectorVotes[value]` - misses legacy data stored under pubkey
2. Line 195 checks: `voterVotes == null && !AddressHelper.VerifyFormattedAddress(value)`
3. Since `VerifyFormattedAddress(value)` returns `true` for addresses, the condition fails
4. Lines 197-198 (pubkey derivation fallback) are never executed
5. Returns empty `ElectorVote()` despite existing vote data

When the input `value` is a pubkey hex string:
1. Line 193 finds legacy data if it exists
2. If not found, line 195 condition succeeds (input is not a formatted address)
3. Lines 197-198 derive address and attempt secondary lookup
4. Returns data from either location

The fundamental issue is that address-to-pubkey reverse derivation is cryptographically impossible, so the view method cannot find legacy pubkey-keyed data when queried by address.

### Impact Explanation

**Who is Affected:**
Users with vote records stored under the legacy pubkey format who have not yet performed state-changing operations (Vote/Withdraw) that would trigger migration.

**Operational Impact:**
1. **Data Visibility Loss**: Querying by address returns empty results despite actual votes existing
2. **UI/DApp Inconsistency**: Frontends using address-based queries display incorrect zero balances
3. **User Confusion**: Users see different vote amounts depending on query method (address vs pubkey)
4. **Integration Failures**: External contracts or applications calling the view method with addresses receive incorrect data [6](#0-5) 

**Severity Justification:**
Medium severity (not High) because:
- No fund loss possible - tokens remain locked and accessible
- State-changing operations have correct migration logic
- Governance/consensus decisions are not directly affected
- Impact limited to information visibility rather than state manipulation
- Natural user behavior (address-based queries) triggers the issue

### Likelihood Explanation

**Preconditions:**
1. Vote records exist in `State.ElectorVotes` using pubkey hex string keys (legacy format)
2. User has not performed Vote or Withdraw operations that would trigger automatic migration
3. Query is performed using Base58 address format rather than pubkey hex

**Execution Practicality:**
- High probability scenario: Users and UIs naturally query by wallet address
- Zero cost: View method calls are free
- No special permissions required
- Depends on contract upgrade history and whether legacy data exists

**Attack Complexity:**
Not an attack vector per se, but a logic flaw with high probability of occurrence in normal operations if legacy data exists.

**Detection:**
Would manifest as user complaints about "missing votes" and discrepancies between different query methods.

### Recommendation

**Code-Level Mitigation:**

Modify the `GetElectorVote(string value)` view method to add symmetric lookup logic:

```csharp
private ElectorVote GetElectorVote(string value)
{
    Assert(value != null && value.Length > 1, "Invalid input.");
    
    var voterVotes = State.ElectorVotes[value];

    if (voterVotes == null && !AddressHelper.VerifyFormattedAddress(value))
    {
        // Input is pubkey, try derived address
        voterVotes = State.ElectorVotes[
            Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(value)).ToBase58()];
    }
    
    // NEW: If input is address and data not found, iterate candidates to find matching pubkey
    if (voterVotes == null && AddressHelper.VerifyFormattedAddress(value))
    {
        // Search for any pubkey entries that match this address
        // Note: This requires maintaining a reverse mapping or iterating stored pubkeys
        // Alternative: Return informative message about data migration requirement
    }

    return voterVotes ?? new ElectorVote();
}
```

**Better Solution:**

Implement proactive migration: Add an administrative function to migrate all remaining legacy pubkey-keyed entries to address-keyed entries in batch, then remove the fallback logic once migration is complete.

**Invariant Checks:**
- Verify no pubkey-format keys remain in `State.ElectorVotes` after migration period
- Assert consistent data returned regardless of query input format for same user

**Test Cases:**
1. Test querying by address when data exists under pubkey key - should return data (currently fails)
2. Test querying by pubkey when data exists under address key - should return data (currently works)
3. Test querying by both formats for same user returns identical results
4. Test migration triggered by state-changing operations removes old pubkey entries [7](#0-6) 

### Proof of Concept

**Initial State:**
1. Contract has been upgraded from legacy pubkey-based storage to address-based storage
2. User with address `A` (derived from pubkey `P`) has existing vote data stored at `State.ElectorVotes[P]`
3. User has not performed any state-changing operations since upgrade

**Exploitation Steps:**

Step 1: Query by pubkey hex
```
Call GetElectorVote(P)
Result: Returns ElectorVote with vote data (CORRECT)
```

Step 2: Query by address
```
Call GetElectorVote(A) 
Result: Returns empty ElectorVote() (INCORRECT - should return same data as Step 1)
```

**Expected Result:**
Both queries should return identical vote data for the same user.

**Actual Result:**
Query by address returns empty while query by pubkey returns actual data, demonstrating the vulnerability.

**Success Condition:**
The inconsistency is demonstrated when the same user's votes are visible via pubkey query but invisible via address query, violating the invariant that vote data should be consistently accessible regardless of query input format.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L18-19)
```csharp
    // Old:Pubkey/New:Address -> ElectorVote
    public MappedState<string, ElectorVote> ElectorVotes { get; set; }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L519-519)
```csharp
        State.ElectorVotes[Context.Sender.ToBase58()] = voterVotes;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L522-538)
```csharp
    private ElectorVote GetElectorVote(byte[] recoveredPublicKey)
    {
        var voterVotes = State.ElectorVotes[Context.Sender.ToBase58()];
        if (voterVotes != null) return voterVotes;

        if (recoveredPublicKey == null) return null;

        var publicKey = recoveredPublicKey.ToHex();

        voterVotes = State.ElectorVotes[publicKey]?.Clone();

        if (voterVotes == null) return null;
        voterVotes.Address ??= Context.Sender;

        State.ElectorVotes.Remove(publicKey);
        return voterVotes;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L648-648)
```csharp
        State.ElectorVotes[Context.Sender.ToBase58()] = voterVotes;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L189-202)
```csharp
    private ElectorVote GetElectorVote(string value)
    {
        Assert(value != null && value.Length > 1, "Invalid input.");
        
        var voterVotes = State.ElectorVotes[value];

        if (voterVotes == null && !AddressHelper.VerifyFormattedAddress(value))
        {
            voterVotes = State.ElectorVotes[
                Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(value)).ToBase58()];
        }

        return voterVotes ?? new ElectorVote();
    }
```

**File:** protobuf/election_contract.proto (L142-145)
```text
    // Get the voter information according to voter public key.
    rpc GetElectorVote (google.protobuf.StringValue) returns (ElectorVote) {
        option (aelf.is_view) = true;
    }
```
