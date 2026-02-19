### Title
Coordinated LIB Denial-of-Service via Zero ImpliedIrreversibleBlockHeight Bypass

### Summary
The `LibInformationValidationProvider` validation logic contains a critical flaw that allows miners to bypass regression checks by setting their `ImpliedIrreversibleBlockHeight` to zero. When more than 1/3 of miners collude to exploit this bypass, they can permanently halt Last Irreversible Block (LIB) progression, breaking consensus finality and blocking cross-chain operations.

### Finding Description

The vulnerability exists in the validation logic that checks whether a miner's `ImpliedIrreversibleBlockHeight` has regressed (moved backward): [1](#0-0) 

**Root Cause:** Line 24 checks if `ImpliedIrreversibleBlockHeight != 0` before performing regression validation. This check was intended to allow new miners (who legitimately have zero values initially) to pass validation. However, it also allows **existing miners** with previously valid heights to intentionally revert to zero and bypass the validation entirely.

During normal operation, when a miner produces a block, their `ImpliedIrreversibleBlockHeight` is set to the current block height: [2](#0-1) 

After producing their first block, a miner's `ImpliedIrreversibleBlockHeight` should never be zero again during normal operation. However, miners control their own consensus data submission and can intentionally set this value to zero.

This malicious zero value bypasses validation and gets stored in the round state: [3](#0-2) 

**Why Protection Fails:** When LIB is calculated in subsequent rounds, the system filters out zero values from consideration: [4](#0-3) 

The LIB calculation requires a minimum number of valid heights equal to `MinersCountOfConsent`: [5](#0-4) 

If insufficient valid heights remain after filtering, LIB calculation returns zero (no advancement): [6](#0-5) 

### Impact Explanation

**Consensus Finality Breakdown:**
- LIB stops advancing permanently, preventing any blocks from becoming irreversible
- The entire consensus finality mechanism is broken
- This violates the critical invariant: "LIB height rules" under "Consensus & Cross-Chain" integrity

**Cross-Chain Operations Blocked:**
- Cross-chain indexing and verification depend on irreversible block heights
- Parent/side-chain synchronization halts
- Inter-chain asset transfers and communication become impossible

**Quantified Attack Threshold:**
- For 21 miners: `MinersCountOfConsent = 21 × 2 ÷ 3 + 1 = 15`
- Attack requires only 8 colluding miners (>1/3) to set heights to zero
- This leaves only 13 valid heights, which is below the 15 required
- LIB calculation returns 0, halting finality

**Affected Parties:**
- All network participants lose finality guarantees
- Cross-chain users cannot complete transactions
- Applications depending on irreversible state cannot function reliably

**Severity Justification:** Critical - breaks fundamental consensus safety property with protocol-wide operational impact.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires collusion of >1/3 of current miners (Byzantine threshold)
- Miners have full control over their consensus data submission
- No special privileges beyond normal mining rights required

**Attack Complexity:**
- Trivial to execute: simply set `ImpliedIrreversibleBlockHeight = 0` in consensus extra data
- No sophisticated cryptographic manipulation required
- Can be performed repeatedly to maintain DoS

**Feasibility Conditions:**
- Byzantine fault tolerance assumption expects up to 1/3 malicious actors
- This attack needs exactly that threshold, making it feasible under standard adversary models
- No economic cost to attackers (no slashing or penalties for this behavior)

**Detection Constraints:**
- Attack effect (LIB not advancing) is immediately observable
- However, attributing blame is difficult since multiple miners could be involved
- No built-in mechanism to penalize or prevent this specific behavior

**Economic Rationality:**
- Attackers aiming to disrupt finality or block cross-chain operations have clear incentives
- Competing chain operators or malicious actors seeking to damage network reliability
- Zero cost makes risk-reward favorable for malicious actors

### Recommendation

**Immediate Fix:** Modify the validation logic in `LibInformationValidationProvider` to properly detect backward movement including regression to zero:

```csharp
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    var baseHeight = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    var providedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // If base round has a valid height, provided height must not regress (including to zero)
    if (baseHeight > 0 && providedHeight < baseHeight)
    {
        validationResult.Message = "Incorrect implied lib height - regression detected.";
        return validationResult;
    }
    
    // Additionally, during normal operation, height should never be zero after first block
    if (baseHeight > 0 && providedHeight == 0)
    {
        validationResult.Message = "Implied lib height cannot be zero after initialization.";
        return validationResult;
    }
}
```

**Invariant Checks:**
1. `ImpliedIrreversibleBlockHeight` must be monotonically non-decreasing per miner across rounds
2. Once set to a value > 0, it cannot return to 0
3. During `UpdateValue` behavior, the height must equal `Context.CurrentHeight`

**Test Cases:**
1. Test that miner with previous height 1000 cannot submit height 0
2. Test that miner with previous height 1000 cannot submit height 500
3. Test that >1/3 miners submitting zero heights fails validation
4. Test that new miners in a term can legitimately start with zero
5. Verify LIB calculation proceeds correctly after fix with edge cases

### Proof of Concept

**Initial State:**
- Chain running with 21 active miners
- Current round N with all miners having valid `ImpliedIrreversibleBlockHeight` values from previous blocks
- LIB advancing normally

**Attack Sequence:**

**Round N+1:**
1. Honest miners (13 miners): Produce blocks with `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` (normal operation)
2. Colluding miners (8 miners): Produce blocks with `ImpliedIrreversibleBlockHeight = 0` (malicious modification)
3. Validation passes for all miners (lines 23-30 skipped for attackers due to zero check on line 24)
4. Round N+1 state contains: 13 valid heights + 8 zero heights

**Round N+2 (LIB Calculation):**
1. `LastIrreversibleBlockHeightCalculator` executes using Round N+1 data
2. `GetSortedImpliedIrreversibleBlockHeights` filters out 8 zero values (line 15)
3. Remaining valid heights: 13
4. Required heights: `MinersCountOfConsent = 15`
5. Condition `13 < 15` evaluates to true
6. LIB calculation returns 0 (lines 26-30)
7. No `IrreversibleBlockFound` event fired
8. LIB height remains at previous value

**Expected vs Actual Result:**
- **Expected:** Validation should reject blocks with regressed `ImpliedIrreversibleBlockHeight` values, including zero
- **Actual:** Validation accepts zero values, allowing attack to succeed and halting LIB progression

**Success Condition:**
- LIB stops advancing (can be verified by monitoring `ConfirmedIrreversibleBlockHeight` in subsequent rounds)
- Attackers can maintain this state indefinitely by continuing to submit zero values
- Cross-chain operations depending on LIB fail or stall

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```
