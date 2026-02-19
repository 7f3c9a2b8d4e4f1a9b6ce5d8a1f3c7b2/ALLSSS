### Title
Missing Round Number Bounds Validation Enables Permanent DoS of Cross-Chain Consensus Synchronization

### Summary
The `UpdateInformationFromCrossChain` function in the AEDPoS consensus contract lacks upper bound validation on the round number received from parent chain data. An attacker with the ability to propose malicious cross-chain data can set `MainChainRoundNumber` to an extremely large value (e.g., Int64.MaxValue), permanently preventing legitimate parent chain consensus updates from being processed and freezing the side chain's miner list synchronization.

### Finding Description
The vulnerability exists in the `UpdateInformationFromCrossChain` function which only validates that the incoming round number is greater than the stored value, without checking if it's within reasonable bounds. [1](#0-0) 

The function accepts consensus information from parent chain block data's `extra_data` field, which is passed through the CrossChain contract's indexing process. The CrossChain contract's validation only checks basic fields like height sequencing and merkle roots, but does not validate the content of the `extra_data` field: [2](#0-1) 

The consensus data is extracted and passed to the consensus contract during parent chain block indexing: [3](#0-2) 

While node-level validation exists in `CrossChainIndexingDataValidationService`, it can be disabled via configuration: [4](#0-3) 

Once a malicious round number is accepted and stored, all future legitimate updates will be rejected because they will have lower round numbers: [5](#0-4) 

### Impact Explanation
The attack results in permanent denial of service for cross-chain consensus synchronization:

1. **Frozen Miner List**: The side chain cannot update its miner list from the main chain, as `MainChainCurrentMinerList` becomes locked to the value from the malicious update. This affects consensus round generation: [6](#0-5) 

2. **Permanent Update Blockage**: All subsequent legitimate parent chain consensus updates are rejected because their round numbers will be lower than the malicious value, causing the comparison check to fail and return early.

3. **Resource Token Distribution Lock**: The frozen miner list affects resource token distribution to validators: [7](#0-6) 

This is a **Medium severity** issue because it causes operational DoS of critical cross-chain functionality, though it requires some level of validator coordination or system misconfiguration to execute.

### Likelihood Explanation
The attack requires one of the following conditions:

1. **Consensus Attack**: Malicious validators controlling enough voting power to propose and approve invalid cross-chain indexing data through the governance proposal system: [8](#0-7) 

2. **Validation Bypass**: The `CrossChainDataValidationIgnored` configuration option is set to true, disabling off-chain validation that would normally catch invalid data.

3. **Node Software Compromise**: Attackers compromise the node software's cross-chain data validation service to accept malicious cached parent chain data.

The attack is **feasible but not trivial**. It requires either a consensus-level attack with validator coordination or exploitation of configuration/deployment weaknesses. The contract itself provides no defense-in-depth protection, relying entirely on off-chain validation which can be bypassed.

The entry point is reachable by any current miner who can call `ProposeCrossChainIndexing`, and if the malicious proposal gains governance approval, the vulnerability is exploited with no additional barriers.

### Recommendation
Add bounds validation in the `UpdateInformationFromCrossChain` function to ensure the round number increment is reasonable:

```csharp
// After line 46, add:
var roundNumberDiff = consensusInformation.Round.RoundNumber - State.MainChainRoundNumber.Value;
Assert(roundNumberDiff > 0 && roundNumberDiff <= MaxReasonableRoundIncrement, 
    "Round number increment out of reasonable bounds.");
```

Define `MaxReasonableRoundIncrement` as a configurable constant (e.g., 1000 rounds) based on expected main chain block production rates and cross-chain indexing frequency.

Additionally, add bounds validation in the CrossChain contract's `ValidateParentChainBlockData` to check extra_data content:

```csharp
// In ValidateParentChainBlockData, validate consensus extra data if present
if (blockData.ExtraData.TryGetValue("Consensus", out var consensusBytes))
{
    var consensusInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusBytes);
    Assert(consensusInfo.Round.RoundNumber <= currentHeight + MaxReasonableRoundIncrement,
        "Parent chain consensus round number out of bounds.");
}
```

Add test cases verifying that:
- Round numbers with reasonable increments (1-100) are accepted
- Round numbers with excessive jumps (>1000) are rejected
- Attempts to set round number to Int64.MaxValue fail

### Proof of Concept

**Initial State:**
- Side chain is operational with `MainChainRoundNumber = 100`
- Attacker controls a miner account or validator quorum

**Attack Steps:**

1. Attacker creates malicious `ParentChainBlockData` with valid height/chain_id but crafted `extra_data`:
   - `extra_data["Consensus"]` = serialized `AElfConsensusHeaderInformation` with `Round.RoundNumber = 9223372036854775807` (Int64.MaxValue)
   - Include valid `TransactionStatusMerkleTreeRoot` to pass basic validation

2. Attacker calls `ProposeCrossChainIndexing` with the malicious `CrossChainBlockData` containing the crafted parent chain data (requires miner permission).

3. If node-level validation is disabled or bypassed, the proposal is created successfully.

4. Attacker uses governance control to approve the cross-chain indexing proposal.

5. Attacker calls `ReleaseCrossChainIndexingProposal` to index the malicious data.

6. During indexing, `UpdateInformationFromCrossChain` is called with the malicious consensus data, setting `MainChainRoundNumber = 9223372036854775807`.

**Expected Result:** Round number validation should reject the excessive increment.

**Actual Result:** `MainChainRoundNumber` is set to Int64.MaxValue. All future legitimate parent chain updates are permanently blocked because their round numbers (e.g., 101, 102, ...) are less than the stored value, causing the function to return early without updating.

**Success Condition:** Side chain can no longer synchronize miner lists or consensus information from the main chain, effectively freezing cross-chain consensus coordination.

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

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataProposedLogEventProcessor.cs (L60-64)
```csharp
                if (CrossChainConfigOptions.Value.CrossChainDataValidationIgnored)
                {
                    Logger.LogTrace("Cross chain data validation disabled.");
                    return;
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-295)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-291)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
    }
```
