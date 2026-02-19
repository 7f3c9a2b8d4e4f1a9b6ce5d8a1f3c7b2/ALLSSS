### Title
Cross-Chain Consensus Update DoS via Unbounded Round Number Injection

### Summary
The `UpdateInformationFromCrossChain` function lacks upper bound validation on the incoming `RoundNumber`, allowing miners to inject extremely large values (e.g., `long.MaxValue`) that permanently block all subsequent legitimate consensus updates. This creates a denial-of-service condition for cross-chain consensus information propagation on side chains.

### Finding Description

The vulnerability exists in the validation logic at line 46 of `UpdateInformationFromCrossChain`: [1](#0-0) 

The check only validates that the incoming round number is strictly greater than the stored value, with no upper bound or increment size validation. If an attacker supplies `RoundNumber = long.MaxValue` (or any extremely large value), it passes this check and updates the state: [2](#0-1) 

**Root Cause:** The cross-chain update path lacks the strict validation enforced in normal consensus operations. Main chain round transitions require the round number to increment by exactly 1: [3](#0-2) 

However, the cross-chain update path has no such constraint.

**Why Protections Fail:**
The CrossChain contract's validation only checks structural properties (chain ID, height continuity, merkle roots) but does not validate consensus round number reasonableness: [4](#0-3) 

The consensus information bytes are extracted from `ParentChainBlockData.ExtraData` and passed directly to the consensus contract without validation: [5](#0-4) 

**Execution Path:**
1. Malicious miner calls `ProposeCrossChainIndexing` with crafted parent chain block data containing extremely large round number in consensus info
2. `ValidateParentChainBlockData` validates structural properties only (not consensus values)
3. Parliament proposal created and approved (votes on chain ID, not specific data values)
4. `ReleaseCrossChainIndexingProposal` → `RecordCrossChainData` → `IndexParentChainBlockData` → `UpdateConsensusInformation`
5. `UpdateInformationFromCrossChain` accepts the large round number
6. All future legitimate updates are rejected because any normal round number ≤ injected value

### Impact Explanation

**Direct Harm:** Complete denial-of-service of cross-chain consensus information updates for the affected side chain. Once a large round number is injected, the side chain can no longer receive:
- Updated miner lists from the main chain
- Updated consensus round information
- Critical cross-chain coordination data

**Protocol Damage:** The side chain's cross-chain consensus mechanism becomes permanently stuck. This affects:
- Cross-chain miner list synchronization
- Resource token distribution to miners (calls `DistributeResourceTokensToPreviousMiners` which depends on updated miner list)
- Cross-chain operation integrity

**Who Is Affected:** All participants in the side chain ecosystem, as the chain can no longer maintain consensus synchronization with its parent chain.

**Severity Justification:** Medium severity - while the impact is significant (DoS), it requires either miner collusion or exploitation of off-chain validation weaknesses to inject malicious data through the governance process.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a current miner to propose cross-chain indexing data
- Requires parliament approval (majority miner vote) to accept the malicious proposal, OR
- Exploitation of weaknesses in off-chain validation to get corrupt data accepted

**Attack Complexity:** Moderate
- Single miner can propose the data
- Requires bypassing or colluding with parliament governance
- No cryptographic barriers once proposal is accepted

**Feasibility Conditions:**
- Side chain with cross-chain indexing enabled
- Malicious miner(s) with proposal rights
- Either majority miner collusion or negligent validation

**Detection Constraints:** The attack is visible on-chain as an abnormal round number jump, but prevention requires active monitoring of proposed values before approval.

**Probability:** Medium - requires governance compromise but attack vector is straightforward once conditions are met.

### Recommendation

Add upper bound validation to `UpdateInformationFromCrossChain` to ensure round numbers are within reasonable bounds:

1. **Implement increment size validation:**
```csharp
// Validate round number increment is reasonable (e.g., max 10 rounds ahead)
const long maxRoundIncrement = 10;
if (consensusInformation.Round.RoundNumber > State.MainChainRoundNumber.Value.Add(maxRoundIncrement))
{
    Assert(false, "Round number increment exceeds maximum allowed.");
}
```

2. **Add absolute upper bound check:**
```csharp
// Prevent values near long.MaxValue that could cause permanent DoS
const long maxReasonableRound = long.MaxValue / 2;
Assert(consensusInformation.Round.RoundNumber < maxReasonableRound, 
    "Round number exceeds maximum reasonable value.");
```

3. **Add validation in CrossChain contract:**
Enhance `ValidateParentChainBlockData` to parse and validate consensus information round numbers before creating proposals.

4. **Test cases:**
    - Attempt to update with RoundNumber = long.MaxValue (should fail)
    - Attempt to update with RoundNumber = current + 1000 (should fail if > maxRoundIncrement)
    - Verify legitimate sequential updates still work
    - Verify recovery mechanism if chain becomes stuck

### Proof of Concept

**Initial State:**
- Side chain operational with `MainChainRoundNumber = 100`
- Attacker is a current miner with proposal rights

**Attack Steps:**
1. Attacker creates `ParentChainBlockData` with valid chain ID, height, merkle root
2. In `ExtraData[ConsensusExtraDataName]`, includes crafted `AElfConsensusHeaderInformation` with `Round.RoundNumber = 9223372036854775807` (long.MaxValue)
3. Calls `ProposeCrossChainIndexing` with malicious data - validation passes
4. Parliament votes to approve (approving chain indexing, not validating specific round values)
5. Attacker calls `ReleaseCrossChainIndexingProposal`
6. `UpdateInformationFromCrossChain` executes: `9223372036854775807 > 100` → passes check
7. `State.MainChainRoundNumber.Value = 9223372036854775807`

**Result:**
- Legitimate update attempt with `RoundNumber = 101`: check `101 <= 9223372036854775807` → true → early return → update rejected
- All future legitimate updates permanently blocked
- Side chain can no longer receive consensus updates from main chain

**Success Condition:** `State.MainChainRoundNumber.Value` stuck at extremely large value, all subsequent legitimate `UpdateInformationFromCrossChain` calls return early without updating state.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L46-47)
```csharp
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L55-55)
```csharp
        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-30)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L720-743)
```csharp
    private bool ValidateParentChainBlockData(IList<ParentChainBlockData> parentChainBlockData,
        out Dictionary<int, List<ParentChainBlockData>> validatedParentChainBlockData)
    {
        var parentChainId = State.ParentChainId.Value;
        var currentHeight = State.CurrentParentChainHeight.Value;
        validatedParentChainBlockData = new Dictionary<int, List<ParentChainBlockData>>();
        foreach (var blockData in parentChainBlockData)
        {
            if (parentChainId != blockData.ChainId || currentHeight + 1 != blockData.Height ||
                blockData.TransactionStatusMerkleTreeRoot == null)
                return false;
            if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
                    State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
                    State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
                return false;

            currentHeight += 1;
        }

        if (parentChainBlockData.Count > 0)
            validatedParentChainBlockData[parentChainId] = parentChainBlockData.ToList();

        return true;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L783-788)
```csharp
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
            }
```
