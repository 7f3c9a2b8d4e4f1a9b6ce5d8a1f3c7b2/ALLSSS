### Title
ImpliedIrreversibleBlockHeight Validation Bypass Allows Malicious Miners to Prevent LIB Advancement

### Summary
The validation logic in `LibInformationValidationProvider` skips validation when a miner sets their `ImpliedIrreversibleBlockHeight` to 0, allowing malicious miners to bypass the monotonicity check. If 1/3 or more miners collude to provide zero values, the Last Irreversible Block (LIB) calculation fails or stops advancing, breaking block finality and cross-chain verification.

### Finding Description

The vulnerability exists in the validation logic that checks miner-reported implied irreversible block heights: [1](#0-0) 

The validation only executes when `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0`. This guard condition allows a malicious miner to completely bypass validation by setting this value to 0 in their block's consensus extra data.

During normal block production, the consensus contract automatically sets this value to the current block height: [2](#0-1) 

However, a malicious block producer can modify the consensus extra data in the block header before submitting the block, setting `ImpliedIrreversibleBlockHeight` to 0 instead of the proper value. This bypasses the validation and the zero value gets stored in state: [3](#0-2) 

The zero values are then filtered out during LIB calculation: [4](#0-3) 

If the count of valid (non-zero) implied heights falls below the consensus threshold (`MinersCountOfConsent = (N * 2/3) + 1`), the LIB calculation returns 0: [5](#0-4) 

The protection at line 272 prevents updating the LIB if the calculated value is not higher than the current value, causing the LIB to fail to advance: [6](#0-5) 

### Impact Explanation

**Consensus Impact:** If more than 1/3 of miners collude to set their `ImpliedIrreversibleBlockHeight` to 0, the LIB stops advancing. For example, with 7 miners requiring 5 valid values, if 3 miners provide 0, only 4 valid values remain, causing the LIB calculation to return 0 and preventing any LIB updates.

**Cross-Chain Impact:** Cross-chain verification relies on the LIB for confirming irreversible state, so a stalled LIB breaks cross-chain indexing and verification: [7](#0-6) 

**Finality Impact:** Without advancing LIB, blocks never achieve true finality, undermining network security guarantees and breaking applications that depend on irreversible transactions.

**Severity:** HIGH - This directly violates the critical invariant that "LIB height rules" must be maintained, compromising consensus integrity and cross-chain functionality.

### Likelihood Explanation

**Attacker Capabilities:** The attack requires:
- Controlling 1/3 or more of the miner nodes (in a PoS/DPoS system with 7-21 miners, this means 3-7 colluding miners)
- Ability to modify block header consensus extra data before block submission
- Coordinated action across multiple blocks to sustain the attack

**Attack Complexity:** MODERATE - Miners can modify their block's consensus extra data since they control block creation. The node software normally calls the contract to get proper values, but malicious miners can override this.

**Detection:** The attack would be immediately observable as the LIB would stop advancing, visible in blockchain monitoring. However, identifying which specific miners are providing zero values requires inspecting block headers.

**Economic Rationality:** MODERATE likelihood - While miners have economic stake in network health (making sabotage counterintuitive), scenarios include: compromised miner nodes, miners shorting the token, or targeted attacks during critical cross-chain operations. The low cost (just modifying block data) vs potential profit from exploiting finality failures makes this economically viable for motivated attackers.

**Probability:** MODERATE - Requires significant miner collusion (>1/3), but the technical execution is straightforward and the bypass condition explicitly enables the attack.

### Recommendation

1. **Remove the != 0 guard condition** and always validate `ImpliedIrreversibleBlockHeight`:

```csharp
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
{
    validationResult.Message = "Incorrect implied lib height.";
    return validationResult;
}
```

2. **Add a minimum value check** to ensure miners provide reasonable implied heights:

```csharp
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    var providedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    var baseHeight = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Reject zero values outright (should be close to current height)
    if (providedHeight == 0)
    {
        validationResult.Message = "ImpliedIrreversibleBlockHeight cannot be zero.";
        return validationResult;
    }
    
    // Ensure monotonicity
    if (baseHeight > providedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
}
```

3. **Add invariant checks** in `ProcessUpdateValue` to reject zero values:

```csharp
Assert(updateValueInput.ImpliedIrreversibleBlockHeight > 0, 
    "ImpliedIrreversibleBlockHeight must be greater than zero.");
```

4. **Add test cases** to verify:
    - Blocks with zero `ImpliedIrreversibleBlockHeight` are rejected
    - LIB calculation handles edge cases when miners provide invalid values
    - Validation cannot be bypassed by providing zero values

### Proof of Concept

**Initial State:**
- 7 active miners in consensus
- Current LIB height: 1000
- MinersCountOfConsent: (7 * 2 / 3) + 1 = 5

**Attack Sequence:**

1. **Block Height 1001**: Miner A produces block with modified consensus extra data:
   - Set `ImpliedIrreversibleBlockHeight = 0` (instead of 1001)
   - Validation at lines 24-26 is skipped due to `!= 0` check
   - Zero value stored in state

2. **Block Height 1002**: Miner B produces block with modified data:
   - Set `ImpliedIrreversibleBlockHeight = 0`
   - Validation skipped, zero value stored

3. **Block Height 1003**: Miner C produces block with modified data:
   - Set `ImpliedIrreversibleBlockHeight = 0`
   - Validation skipped, zero value stored

4. **Block Height 1004**: Honest Miner D produces normal block:
   - Proper `ImpliedIrreversibleBlockHeight = 1004`
   - LIB calculation in `ProcessUpdateValue` executes:
     - `GetSortedImpliedIrreversibleBlockHeights` filters out 3 zero values
     - Only 4 valid values remain from miners D, E, F, G
     - Count (4) < MinersCountOfConsent (5)
     - `libHeight = 0` returned
   - Check at line 272: `currentRound.ConfirmedIrreversibleBlockHeight (1000) < libHeight (0)` is FALSE
   - LIB not updated, remains at 1000

**Expected Result:** LIB should advance to ~1002-1003 based on consensus of honest miners

**Actual Result:** LIB stays at 1000 and stops advancing due to insufficient valid implied height values

**Success Condition:** LIB remains frozen at 1000 despite blocks continuing to be produced, demonstrating the validation bypass enables LIB advancement prevention.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-281)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
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
