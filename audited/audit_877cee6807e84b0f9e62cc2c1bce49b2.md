### Title
Missing Round Number Gap Detection Enables Permanent Cross-Chain Consensus Synchronization DoS

### Summary
The `UpdateInformationFromCrossChain()` function fails to detect unreasonably large gaps in round numbers when updating consensus information from the main chain. An attacker who compromises the main chain can inject consensus data with an extremely high round number (e.g., jumping from round 100 to 10,000), which permanently locks the side chain's cross-chain consensus synchronization and enables resource token theft through a malicious miner list.

### Finding Description

The vulnerability exists in the `UpdateInformationFromCrossChain()` function which only validates that the incoming round number is strictly greater than the currently stored round number, without any upper bound or reasonable gap validation. [1](#0-0) 

The function accepts any round number higher than the current `State.MainChainRoundNumber.Value`, regardless of the magnitude of the jump. After this insufficient check, the function unconditionally updates the stored round number and miner list: [2](#0-1) 

The cross-chain data validation processes in both the contract-level validation and the application-level validation service do not inspect or validate the consensus information content: [3](#0-2) [4](#0-3) 

The consensus information is extracted from parent chain block data and passed through without content validation: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Consensus Synchronization DoS**: Once a malicious round number with a large gap (e.g., 10,000) is accepted when the current round is 100, all future legitimate updates with sequential round numbers (101, 102, 103, etc.) will be permanently rejected because they fail the `<=` check. The side chain's view of the main chain consensus becomes permanently locked to the malicious state.

**Resource Token Theft**: Before updating the miner list, the function distributes accumulated resource tokens to miners in the previous miner list: [7](#0-6) [8](#0-7) 

After the malicious update, subsequent distributions will send tokens to the attacker-controlled miner list. The side chain's accumulated transaction fees and rental fees (in symbols like ELF, READ, WRITE, etc.) are distributed to these malicious addresses.

**Protocol-Wide Impact**: The side chain cannot recover from this state without manual intervention or contract upgrade, as there is no mechanism to rollback or override the corrupted MainChainRoundNumber state. This affects all cross-chain consensus synchronization operations for the lifetime of the side chain.

### Likelihood Explanation

**Attack Prerequisites**: The attack requires the ability to inject malicious consensus data into the cross-chain indexing flow, which the security question explicitly identifies as occurring through "main chain compromise." In this scenario:

1. The attacker controls main chain consensus and can produce blocks with arbitrary consensus extra data
2. The cross-chain indexing mechanism (designed to trust parent chain data after merkle proof verification) will accept and relay this data to the side chain
3. No additional vulnerabilities or permissions beyond main chain compromise are required

**Attack Complexity**: The attack is straightforward once main chain control is achieved:
- Create a parent chain block with consensus extra data containing a malicious round number
- The data passes through standard cross-chain indexing (which validates merkle proofs but not consensus content)
- The `UpdateInformationFromCrossChain` function automatically accepts the data

**Detection Constraints**: The attack is difficult to detect in real-time because:
- Large round number jumps could theoretically occur during extended network disruptions
- The cross-chain system is designed to accept parent chain data as authoritative
- No alerting mechanisms exist for abnormal round number progression

**Economic Rationality**: For an attacker who has already compromised the main chain, executing this attack requires minimal additional cost while achieving permanent side chain disruption and ongoing token theft.

### Recommendation

Implement round number gap validation with a configurable maximum allowed gap:

```csharp
// Add state variable for maximum allowed round gap
public Int64State MaxAllowedRoundGap { get; set; }

// In UpdateInformationFromCrossChain(), after line 46:
if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
    return new Empty();

// Add gap validation
var currentRound = State.MainChainRoundNumber.Value;
var newRound = consensusInformation.Round.RoundNumber;
var maxGap = State.MaxAllowedRoundGap.Value; // e.g., 100 rounds
if (maxGap > 0 && newRound - currentRound > maxGap)
{
    Context.LogDebug(() => 
        $"Round number gap too large: current {currentRound}, new {newRound}, max gap {maxGap}");
    return new Empty();
}
```

**Additional Safeguards**:
1. Add a governance-controlled function to set/update the maximum allowed round gap
2. Emit an event when suspicious round number gaps are detected for monitoring
3. Implement a recovery mechanism allowing authorized governance to reset MainChainRoundNumber in emergency scenarios
4. Add comprehensive test cases validating rejection of large gaps:
   - Normal sequential updates (should pass)
   - Small gaps of 1-10 rounds (should pass)
   - Large gaps of 100+ rounds (should fail)
   - Extremely large gaps of 1000+ rounds (should fail)

### Proof of Concept

**Initial State**:
- Side chain is running with MainChainRoundNumber = 100
- MainChainCurrentMinerList contains 5 legitimate miners
- Consensus contract holds 1000 READ tokens accumulated from fees

**Attack Sequence**:

1. **Attacker compromises main chain** and creates parent chain block at height 10,000 with consensus extra data:
   ```
   AElfConsensusHeaderInformation {
     Round {
       RoundNumber: 100000,
       RealTimeMinersInformation: {
         "attacker_pubkey_1": MinerInRound {...},
         "attacker_pubkey_2": MinerInRound {...},
         "attacker_pubkey_3": MinerInRound {...}
       }
     }
   }
   ```

2. **Cross-chain indexing proposal** is created and approved by miners for this parent chain block data

3. **ReleaseCrossChainIndexingProposal** executes, triggering `IndexParentChainBlockData()`, which calls `UpdateConsensusInformation()`, which calls `UpdateInformationFromCrossChain()`

4. **Validation check passes**: `100000 > 100` evaluates to true

5. **State corruption occurs**:
   - `State.MainChainRoundNumber.Value = 100000`
   - `State.MainChainCurrentMinerList.Value` updated to attacker's 3 miners
   - 1000 READ tokens divided and sent to old miners (200 each to 5 addresses)

6. **Subsequent legitimate update attempt** with main chain round 101:
   - Check fails: `101 <= 100000` evaluates to true
   - Update rejected, returns early
   - Side chain permanently stuck at malicious round 100000

7. **Next round of fee distribution**:
   - 500 new READ tokens accumulated
   - Distributed to attacker's 3 miners (~166 READ each)
   - Attack succeeds in ongoing token theft

**Expected vs Actual Result**:
- **Expected**: Round number 100000 rejected due to unreasonable gap (99,900 rounds)
- **Actual**: Round number 100000 accepted, permanently corrupting side chain state

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L46-47)
```csharp
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-53)
```csharp
        DistributeResourceTokensToPreviousMiners();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L55-61)
```csharp
        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L66-96)
```csharp
    private void DistributeResourceTokensToPreviousMiners()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
            foreach (var pubkey in minerList)
            {
                var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
                Context.LogDebug(() => $"Will send {amount} {symbol}s to {pubkey}");
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
        }
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L227-234)
```csharp
    private void UpdateConsensusInformation(ByteString bytes)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        Context.SendInline(State.CrossChainInteractionContract.Value,
            nameof(State.CrossChainInteractionContract.UpdateInformationFromCrossChain),
            new BytesValue { Value = bytes });
    }
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

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataValidationService.cs (L117-173)
```csharp
    private async Task<bool> ValidateParentChainBlockDataAsync(
        IEnumerable<ParentChainBlockData> multiParentChainBlockData,
        Hash blockHash, long blockHeight)
    {
        var parentChainBlockDataList = multiParentChainBlockData.ToList();
        if (parentChainBlockDataList.Count == 0)
            return true;
        var crossChainContractAddress = await GetCrossChainContractAddressAsync(new ChainContext
        {
            BlockHash = blockHash,
            BlockHeight = blockHeight
        });
        var parentChainId = (await _contractReaderFactory
            .Create(new ContractReaderContext
            {
                BlockHash = blockHash,
                BlockHeight = blockHeight,
                ContractAddress = crossChainContractAddress
            }).GetParentChainId
            .CallAsync(new Empty())).Value;
        if (parentChainId == 0)
            // no configured parent chain
            return false;

        var length = parentChainBlockDataList.Count;
        var i = 0;
        var targetHeight = (await _contractReaderFactory.Create(new ContractReaderContext
            {
                BlockHash = blockHash,
                BlockHeight = blockHeight,
                ContractAddress = crossChainContractAddress
            }).GetParentChainHeight
            .CallAsync(new Empty())).Value + 1;
        while (i < length)
        {
            var parentChainBlockData =
                _blockCacheEntityConsumer.Take<ParentChainBlockData>(parentChainId, targetHeight, false);
            if (parentChainBlockData == null)
            {
                Logger.LogDebug(
                    $"Parent chain data not found. Parent chain height: {targetHeight}.");
                return false;
            }

            if (!parentChainBlockDataList[i].Equals(parentChainBlockData))
            {
                Logger.LogDebug(
                    $"Incorrect parent chain data. Parent chain height: {targetHeight}.");
                return false;
            }

            targetHeight++;
            i++;
        }

        return true;
    }
```
