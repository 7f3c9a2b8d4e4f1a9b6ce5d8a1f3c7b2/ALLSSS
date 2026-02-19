### Title
Case-Sensitive Public Key Comparison Allows Miner Exclusion and Consensus Disruption via Pubkey Replacement

### Summary
The consensus contract uses case-sensitive string comparison for public keys without proper case normalization when recording candidate replacements. When a miner's public key is replaced with a different casing variant (e.g., "ABC..." instead of "abc..."), the miner becomes unable to produce blocks because cryptographic signature recovery always produces lowercase hex strings, while the stored dictionary key retains the user-provided casing. This can exclude miners from consensus participation and potentially break quorum.

### Finding Description

The root cause is the lack of case normalization in the `RecordCandidateReplacement` method. The vulnerability chain involves multiple components:

**1. Normal Pubkey Flow (Safe):**
All standard pubkey conversions use `ToHex()` which produces lowercase hex strings consistently. [1](#0-0) 

The critical line `c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);` adds 0x20 (32) to produce lowercase 'a'-'f' characters instead of uppercase 'A'-'F'.

**2. Vulnerable Pubkey Replacement Flow:**
The Election contract's `ReplaceCandidatePubkey` function accepts user input without case normalization: [2](#0-1) 

The input pubkeys are passed directly to `PerformReplacement` and then to the consensus contract: [3](#0-2) 

**3. Consensus Contract Stores Raw Input:**
The consensus contract's `RecordCandidateReplacement` stores the new pubkey without normalization: [4](#0-3) 

Line 141 sets `Pubkey = input.NewPubkey` and line 143 uses it as the dictionary key directly.

**4. Block Production Fails:**
When a miner tries to produce blocks, the pubkey is recovered from the cryptographic signature, always producing lowercase: [5](#0-4) 

Line 321 produces lowercase via `Context.RecoverPublicKey().ToHex()`, but line 326 performs case-sensitive lookup via `IsInMinerList`: [6](#0-5) 

The `Contains()` method on line 139 uses case-sensitive comparison. If the dictionary key is "ABC..." but the lookup is "abc...", the check fails, causing PreCheck to fail with "No permission" assertion.

**5. LIB Calculation Impact:**
The `GetSortedImpliedIrreversibleBlockHeights` function is also affected: [7](#0-6) 

Line 14 uses case-sensitive `Contains()` comparison. If miners have case variations, they could be excluded from LIB height calculation.

### Impact Explanation

**Consensus Disruption:**
- A miner whose pubkey is replaced with different casing cannot produce blocks because PreCheck fails
- The miner's blocks are rejected with "No permission" error
- The miner loses block production rewards for their time slot

**Quorum Break Risk:**
- If multiple miners are affected (either intentionally or through operator error during bulk replacements), consensus could fail to achieve the 2/3+1 quorum required for block production
- The chain could halt if insufficient miners can participate

**LIB Calculation Errors:**
The LIB height calculator uses miners who produced blocks in the current round: [8](#0-7) 

If miners are excluded due to case mismatches, the LIB height calculation on line 26 may fail or produce incorrect results, affecting chain finality.

**Affected Parties:**
- Replaced miners lose block rewards
- Chain users experience degraded service or chain halt
- Cross-chain operations depending on LIB could be delayed

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is triggered via the public `ReplaceCandidatePubkey` method which is part of the normal miner replacement process: [9](#0-8) 

**Preconditions:**
- Requires candidate admin permission (line 181 checks `Context.Sender == GetCandidateAdmin`)
- However, this is a legitimate administrative function, not a privileged exploit
- Case variation can occur accidentally (copy-paste errors, manual entry, case-insensitive UIs) or intentionally

**Execution Practicality:**
- Very simple: just call `ReplaceCandidatePubkey` with `NewPubkey` in different case than the normalized form
- No complex transaction sequences required
- Can affect any miner undergoing pubkey replacement

**Detection Difficulty:**
- The issue is silent until the affected miner tries to produce blocks
- Could be disguised as normal permission errors
- May not be detected during testing if all replacements happen to use matching case

**Probability:**
- **Accidental**: Moderate - operators may not be aware of case sensitivity requirement
- **Intentional**: Low-Moderate - malicious admin could intentionally disrupt specific miners
- **Overall**: Medium - the combination of accidental operator error and lack of validation makes this a realistic threat

### Recommendation

**Immediate Fix:**
Normalize all pubkey inputs to lowercase in the `RecordCandidateReplacement` method:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");
    
    // ADD: Normalize pubkeys to lowercase
    var normalizedOldPubkey = input.OldPubkey.ToLower();
    var normalizedNewPubkey = input.NewPubkey.ToLower();

    if (!TryToGetCurrentRoundInformation(out var currentRound) ||
        !currentRound.RealTimeMinersInformation.ContainsKey(normalizedOldPubkey)) 
        return new Empty();

    var realTimeMinerInformation = currentRound.RealTimeMinersInformation[normalizedOldPubkey];
    realTimeMinerInformation.Pubkey = normalizedNewPubkey;
    currentRound.RealTimeMinersInformation.Remove(normalizedOldPubkey);
    currentRound.RealTimeMinersInformation.Add(normalizedNewPubkey, realTimeMinerInformation);
    if (currentRound.ExtraBlockProducerOfPreviousRound == normalizedOldPubkey)
        currentRound.ExtraBlockProducerOfPreviousRound = normalizedNewPubkey;
    // ... rest of method
}
```

**Additional Safeguards:**
1. Add validation in `ReplaceCandidatePubkey` to normalize inputs before sending to consensus contract
2. Add invariant check: `Assert(input.NewPubkey == input.NewPubkey.ToLower(), "Pubkey must be lowercase hex")`
3. Implement case-insensitive dictionary for `RealTimeMinersInformation` (alternative solution)

**Test Cases:**
1. Test replacement with uppercase pubkey and verify miner can still produce blocks
2. Test replacement with mixed-case pubkey
3. Test LIB calculation with case-mismatched pubkeys
4. Regression test: verify all pubkey comparisons use normalized forms

### Proof of Concept

**Initial State:**
- Chain running with miner having lowercase pubkey "abc123..." 
- Miner is actively producing blocks

**Attack Steps:**

1. Candidate admin calls `ReplaceCandidatePubkey`:
```
Input: {
  OldPubkey: "abc123...",  // lowercase (current)
  NewPubkey: "ABC123..."   // uppercase (replacement)
}
```

2. Election contract calls `RecordCandidateReplacement` in consensus contract
3. Consensus contract updates current round:
   - Removes dictionary entry for "abc123..."
   - Adds dictionary entry for "ABC123..." (uppercase)
   - Sets `realTimeMinerInformation.Pubkey = "ABC123..."`

4. Miner attempts to produce next block:
   - Block signature recovery produces lowercase "abc123..."
   - PreCheck calls `IsInMinerList("abc123...")`
   - Dictionary lookup for "abc123..." fails (dictionary has "ABC123...")
   - PreCheck returns false
   - Transaction fails with "No permission"

**Expected Result:**
Miner should be able to continue producing blocks after replacement

**Actual Result:**
Miner is permanently excluded from consensus participation, cannot produce blocks, loses rewards, and consensus may break if multiple miners are affected

**Success Condition:**
The vulnerability is confirmed when a miner with replaced pubkey (different case) consistently fails PreCheck and cannot produce blocks, while other miners with matching case continue normal operation.

### Citations

**File:** src/AElf.Types/Extensions/ByteStringExtensions.cs (L8-32)
```csharp
        public static string ToHex(this ByteString bytes, bool withPrefix = false)
        {
            var offset = withPrefix ? 2 : 0;
            var length = bytes.Length * 2 + offset;
            var c = new char[length];

            byte b;

            if (withPrefix)
            {
                c[0] = '0';
                c[1] = 'x';
            }

            for (int bx = 0, cx = offset; bx < bytes.Length; ++bx, ++cx)
            {
                b = (byte)(bytes[bx] >> 4);
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = (byte)(bytes[bx] & 0x0F);
                c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
            }

            return new string(c);
        }
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-146)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-19)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```
