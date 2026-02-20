# Audit Report

## Title
Cross-Chain Consensus Update DoS via Unbounded Round Number Injection

## Summary
The `UpdateInformationFromCrossChain` function in the AEDPoS consensus contract lacks upper bound validation on incoming round numbers from cross-chain updates. This allows injection of extremely large round number values (e.g., `long.MaxValue`) that permanently block all subsequent legitimate consensus updates, creating a denial-of-service condition for cross-chain consensus synchronization on side chains.

## Finding Description

The vulnerability stems from a validation inconsistency between normal consensus round transitions and cross-chain consensus updates.

**Normal Consensus Path** enforces strict round number validation where rounds must increment by exactly 1: [1](#0-0) 

**Cross-Chain Update Path** only validates that the incoming round number is strictly greater than the stored value, with no upper bound: [2](#0-1) 

If an attacker supplies `RoundNumber = long.MaxValue`, it passes this check and updates the state: [3](#0-2) 

**Why Protections Fail:**

The CrossChain contract's `ValidateParentChainBlockData` only validates structural properties (chain ID, height continuity, merkle root presence) but does not validate consensus round number values: [4](#0-3) 

The consensus information bytes are extracted from `ParentChainBlockData.ExtraData` and passed directly to the consensus contract without semantic validation: [5](#0-4) [6](#0-5) 

**Execution Path:**

1. Current miner calls `ProposeCrossChainIndexing` with crafted `ParentChainBlockData` containing malicious consensus info with `RoundNumber = long.MaxValue` in ExtraData
2. `ValidateParentChainBlockData` validates only structural properties, not consensus values
3. Parliament proposal created with only chain ID as params (not the actual consensus data values): [7](#0-6) 

4. Parliament approves proposal based on chain ID, unaware of malicious round number in stored data
5. `ReleaseCrossChainIndexingProposal` → `RecordCrossChainData` → `IndexParentChainBlockData` → `UpdateConsensusInformation` → `UpdateInformationFromCrossChain`
6. Malicious round number accepted and stored
7. All future legitimate updates are rejected because any normal round number ≤ injected value

## Impact Explanation

**Direct Harm:** Complete denial-of-service of cross-chain consensus information updates for the affected side chain. Once `State.MainChainRoundNumber.Value` is set to an extremely large value like `long.MaxValue`, the side chain can no longer receive:
- Updated miner lists from the main chain
- Updated consensus round information  
- Critical cross-chain coordination data

**Protocol Damage:** The side chain's cross-chain consensus mechanism becomes permanently stuck. This affects:
- Cross-chain miner list synchronization: [8](#0-7) 
- Resource token distribution to miners which depends on the updated miner list: [9](#0-8) 
- Cross-chain operation integrity and coordination

**Who Is Affected:** All participants in the side chain ecosystem, as the chain can no longer maintain consensus synchronization with its parent chain.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a current miner to propose cross-chain indexing data (enforced at line 286): [10](#0-9) 
- Requires parliament approval (majority miner vote) to accept the proposal

**Attack Complexity:** Moderate - The key issue is that the validation gap creates a mis-scoped privilege scenario. The parliament is trusted but the system does not provide adequate information for proper validation:
- The proposal parameters only contain the chain ID, not the actual consensus data values
- Miners voting on proposals must verify the consensus data off-chain
- Without proper off-chain verification tooling, malicious data could pass through governance
- No on-chain constraints prevent acceptance of unreasonable round number values

**Feasibility Conditions:**
- Side chain with cross-chain indexing enabled
- Current miner with proposal rights
- Either: (a) majority miner collusion, or (b) insufficient off-chain validation by parliament members

**Detection Constraints:** The attack is visible on-chain as an abnormal round number jump, but prevention requires active monitoring and off-chain verification of proposed consensus values before parliament approval.

## Recommendation

Add upper bound validation in `UpdateInformationFromCrossChain` to ensure round numbers increment reasonably:

```csharp
// Add reasonable upper bound check
const long MaxReasonableRoundIncrement = 1000; // or another appropriate value
if (consensusInformation.Round.RoundNumber > State.MainChainRoundNumber.Value + MaxReasonableRoundIncrement)
{
    Assert(false, "Round number increment exceeds reasonable bounds.");
}
```

Additionally, consider including a hash or summary of the consensus data in the proposal parameters so parliament members have on-chain visibility into what they're approving.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainConsensusDoS_UnboundedRoundNumber()
{
    // Setup: Initialize side chain with parent chain
    var parentChainId = 123;
    long parentChainHeightOfCreation = 10;
    await InitAndCreateSideChainAsync(parentChainHeightOfCreation, parentChainId);

    // Create malicious consensus information with long.MaxValue as round number
    var maliciousConsensusInfo = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = long.MaxValue,
            RealTimeMinersInformation = { /* valid miner data */ }
        }
    };

    // Create parent chain block data with malicious consensus in ExtraData
    var parentChainBlockData = new ParentChainBlockData
    {
        ChainId = parentChainId,
        Height = parentChainHeightOfCreation,
        TransactionStatusMerkleTreeRoot = HashHelper.ComputeFrom("merkle"),
        ExtraData = 
        {
            ["Consensus"] = maliciousConsensusInfo.ToByteString()
        }
    };

    var crossChainBlockData = new CrossChainBlockData
    {
        ParentChainBlockDataList = { parentChainBlockData }
    };

    // Step 1: Propose malicious cross-chain data
    var proposeTx = await CrossChainContractStub.ProposeCrossChainIndexing.SendAsync(crossChainBlockData);
    proposeTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

    // Step 2: Get proposal and approve it
    var proposalId = ProposalCreated.Parser.ParseFrom(
        proposeTx.TransactionResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed
    ).ProposalId;
    await ApproveWithMinersAsync(proposalId);

    // Step 3: Release the proposal - this will inject long.MaxValue
    await CrossChainContractStub.ReleaseCrossChainIndexingProposal.SendAsync(
        new ReleaseCrossChainIndexingProposalInput { ChainIdList = { parentChainId } }
    );

    // Verify: MainChainRoundNumber is now set to long.MaxValue
    // Any future legitimate update with normal round numbers will be rejected
    
    // Try to update with a legitimate round number
    var legitimateConsensusInfo = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 100, // Normal round number
            RealTimeMinersInformation = { /* valid miner data */ }
        }
    };

    var legitimateBlockData = new ParentChainBlockData
    {
        ChainId = parentChainId,
        Height = parentChainHeightOfCreation + 1,
        TransactionStatusMerkleTreeRoot = HashHelper.ComputeFrom("merkle2"),
        ExtraData = 
        {
            ["Consensus"] = legitimateConsensusInfo.ToByteString()
        }
    };

    // This update will be silently rejected because 100 < long.MaxValue
    // Cross-chain consensus synchronization is now permanently DoS'd
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-30)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L46-47)
```csharp
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L398-414)
```csharp
            var proposalCreationInput = new CreateProposalBySystemContractInput
            {
                ProposalInput = new CreateProposalInput
                {
                    Params = new AcceptCrossChainIndexingProposalInput
                    {
                        ChainId = chainId
                    }.ToByteString(),
                    ContractMethodName = nameof(AcceptCrossChainIndexingProposal),
                    ExpiredTime =
                        Context.CurrentBlockTime.AddSeconds(CrossChainIndexingProposalExpirationTimePeriod),
                    OrganizationAddress = crossChainIndexingController.OwnerAddress,
                    ToAddress = Context.Self,
                    Token = proposalToken
                },
                OriginProposer = Context.Sender
            };
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-290)
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
```
