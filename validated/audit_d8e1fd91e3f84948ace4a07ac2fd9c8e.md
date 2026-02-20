# Audit Report

## Title
Unhandled Protobuf Parsing Exception Causes DoS of Cross-Chain Consensus Update Mechanism

## Summary
The `UpdateInformationFromCrossChain` method in the AEDPoS consensus contract lacks exception handling around protobuf deserialization. A malicious miner can propose parent chain block data with malformed protobuf bytes in the `ExtraData["Consensus"]` field, which passes validation but causes parsing exceptions during proposal release, leaving the governance-approved proposal stuck in Pending status and blocking all cross-chain consensus updates for 120 seconds.

## Finding Description

The vulnerability exists at the intersection of three implementation gaps:

**Root Cause - Unhandled Parsing Exception:**

The protobuf parsing occurs without any try-catch protection: [1](#0-0) 

When `input.Value` contains malformed protobuf data, `AElfConsensusHeaderInformation.Parser.ParseFrom` throws an exception that propagates up and reverts the entire transaction.

**Validation Gap - ExtraData Content Not Validated:**

The `ValidateParentChainBlockData` function only validates structural properties but does NOT inspect the `ExtraData` dictionary content: [2](#0-1) 

This validation checks chain ID, sequential heights, non-null merkle root, and duplicate prevention, but malformed protobuf bytes in `ExtraData["Consensus"]` pass undetected.

**Atomic Inline Call Propagates Exceptions:**

The cross-chain contract calls the consensus contract via `Context.SendInline`, making the parsing failure part of the same transaction context: [3](#0-2) 

This inline call is triggered during parent chain block indexing when consensus data is present: [4](#0-3) 

**Attack Execution Path:**

1. Miner calls `ProposeCrossChainIndexing` with malformed protobuf in `ParentChainBlockData.ExtraData["Consensus"]`
2. Validation passes because `ValidateCrossChainDataBeforeIndexing` calls `ValidateParentChainBlockData` which doesn't check ExtraData content: [5](#0-4) 

3. Proposal is created with Pending status via `ProposeCrossChainBlockData`: [6](#0-5) 

4. Governance approves the proposal
5. When `ReleaseCrossChainIndexingProposal` is called, it attempts to index the data: [7](#0-6) 

6. `RecordCrossChainData` calls `IndexParentChainBlockData`, which triggers consensus data parsing: [8](#0-7) 

7. Parsing exception occurs, transaction reverts, and the proposal status update to Accepted (line 327) never executes
8. Future proposals are blocked by the assertion that prevents duplicate proposals: [9](#0-8) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes a denial-of-service of the cross-chain consensus update mechanism, which is critical for side chain operation:

**Operational Impact:**
- Side chains cannot receive updated miner lists from the parent chain, blocking the core function of `UpdateInformationFromCrossChain`
- Consensus synchronization is blocked for a minimum of 120 seconds per attack [10](#0-9) 

**Cascading Effects:**
- Resource token distribution to miners is blocked during the DoS period, as `DistributeResourceTokensToPreviousMiners` is called within `UpdateInformationFromCrossChain`: [11](#0-10) 
- Outdated miner lists compromise consensus integrity
- Side chain validators cannot properly synchronize with parent chain state

**Persistence:**
- Attack can be repeated every 120 seconds once expired proposals are cleared by `ClearCrossChainIndexingProposalIfExpired`: [12](#0-11) 
- No manual override mechanism exists to clear stuck proposals before expiration

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

**Attacker Capabilities:**
- Must be a current miner, verified via `AssertAddressIsCurrentMiner`: [13](#0-12) 
- Miner status is semi-trusted but obtainable through the election system
- Crafting malformed protobuf is trivial (random bytes, truncated data, wrong message type)

**Attack Complexity: LOW**
- Technical barrier is minimal - any invalid byte sequence in `ExtraData["Consensus"]` will trigger parsing failure
- Malformed protobuf appears as opaque hex data to governance voters, making detection difficult
- No code inspection occurs during governance approval process

**Feasibility:**
- The inline call model confirms exception propagation is atomic
- No exception handling exists in the parsing code path
- The proposal blocking mechanism is by design but becomes exploitable in this scenario

**Detection Difficulty:**
- Failed release transactions are visible on-chain but root cause may be unclear
- No automated detection or recovery mechanism exists
- Operators must wait for the 120-second expiration period

## Recommendation

Implement exception handling around the protobuf parsing operation:

```csharp
public override Empty UpdateInformationFromCrossChain(BytesValue input)
{
    Assert(
        Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
        "Only Cross Chain Contract can call this method.");

    Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

    if (input == null || input.Value.IsEmpty) return new Empty();

    AElfConsensusHeaderInformation consensusInformation;
    try
    {
        consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);
    }
    catch
    {
        // Log the error and return empty to allow transaction to succeed
        Context.LogDebug(() => "Failed to parse consensus information from cross chain.");
        return new Empty();
    }

    // Rest of the method...
}
```

Additionally, add validation for ExtraData content in `ValidateParentChainBlockData` to verify that if consensus data exists, it can be successfully parsed before proposal creation.

## Proof of Concept

```csharp
[Fact]
public async Task MalformedConsensusDataCausesProposalStuck()
{
    var parentChainId = 123;
    long parentChainHeightOfCreation = 10;
    await InitAndCreateSideChainAsync(parentChainHeightOfCreation, parentChainId);

    // Create parent chain block data with malformed consensus bytes
    var parentChainBlockData = new ParentChainBlockData
    {
        ChainId = parentChainId,
        Height = parentChainHeightOfCreation,
        TransactionStatusMerkleTreeRoot = HashHelper.ComputeFrom("MerkleRoot")
    };
    
    // Add malformed protobuf data that will pass validation but fail parsing
    parentChainBlockData.ExtraData.Add("Consensus", ByteString.CopyFrom(new byte[] { 0xFF, 0xFF, 0xFF }));

    var crossChainBlockData = new CrossChainBlockData
    {
        ParentChainBlockDataList = { parentChainBlockData }
    };

    // Step 1: Propose with malformed data - should succeed (validation gap)
    var proposeResult = await CrossChainContractStub.ProposeCrossChainIndexing.SendAsync(crossChainBlockData);
    proposeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

    var proposalId = ProposalCreated.Parser
        .ParseFrom(proposeResult.TransactionResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;

    // Step 2: Approve the proposal
    await ApproveWithMinersAsync(proposalId, ParliamentContractStub);

    // Step 3: Attempt to release - should FAIL due to parsing exception
    var releaseResult = await CrossChainContractStub.ReleaseCrossChainIndexingProposal
        .SendWithExceptionAsync(new ReleaseCrossChainIndexingProposalInput
        {
            ChainIdList = { parentChainId }
        });
    
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    
    // Step 4: Verify proposal is stuck in Pending status
    var proposalStatus = await CrossChainContractStub.GetIndexingProposalStatus.CallAsync(new Empty());
    proposalStatus.ChainIndexingProposalStatus[parentChainId].Status
        .ShouldBe(CrossChainIndexingProposalStatus.Pending);
    
    // Step 5: Verify new proposals are blocked
    var secondProposeResult = await CrossChainContractStub.ProposeCrossChainIndexing
        .SendWithExceptionAsync(crossChainBlockData);
    secondProposeResult.TransactionResult.Error.ShouldContain("Chain indexing already proposed");
}
```

## Notes

The vulnerability is particularly dangerous because:
1. The malformed data passes all contract-level validation checks
2. Governance voters cannot easily detect malformed protobuf in hex-encoded proposal data  
3. The DoS window of 120 seconds can be repeatedly exploited
4. The attack requires only miner privileges, which are obtainable through the public election mechanism
5. The inline call model ensures atomic transaction failure, preventing any partial state updates

This represents a critical gap in cross-chain data validation that allows malicious miners to disrupt side chain consensus synchronization with minimal effort.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L43-43)
```csharp
        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-96)
```csharp
        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
    }

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L309-336)
```csharp
    private void RecordCrossChainData(IEnumerable<int> chainIdList)
    {
        var indexedSideChainBlockData = new IndexedSideChainBlockData();
        foreach (var chainId in chainIdList)
        {
            var pendingProposalExists = TryGetIndexingProposalWithStatus(chainId,
                CrossChainIndexingProposalStatus.Pending,
                out var pendingCrossChainIndexingProposal);
            Assert(pendingProposalExists, "Chain indexing not proposed.");

            if (chainId == State.ParentChainId.Value)
                IndexParentChainBlockData(pendingCrossChainIndexingProposal.ProposedCrossChainBlockData
                    .ParentChainBlockDataList);
            else
                indexedSideChainBlockData.SideChainBlockDataList.Add(IndexSideChainBlockData(
                    pendingCrossChainIndexingProposal.ProposedCrossChainBlockData.SideChainBlockDataList,
                    pendingCrossChainIndexingProposal.Proposer, chainId));

            SetCrossChainIndexingProposalStatus(pendingCrossChainIndexingProposal,
                CrossChainIndexingProposalStatus.Accepted);
        }

        if (indexedSideChainBlockData.SideChainBlockDataList.Count > 0)
        {
            State.IndexedSideChainBlockData.Set(Context.CurrentHeight, indexedSideChainBlockData);
            Context.Fire(new SideChainBlockDataIndexed());
        }
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L390-446)
```csharp
    private void ProposeCrossChainBlockData(CrossChainDataDto crossChainDataDto, Address proposer)
    {
        var crossChainIndexingController = GetCrossChainIndexingController();
        foreach (var chainId in crossChainDataDto.GetChainIdList())
        {
            Assert(!TryGetIndexingProposal(chainId, out _), "Chain indexing already proposed.");
            var proposalToken =
                HashHelper.ConcatAndCompute(Context.PreviousBlockHash, ConvertChainIdToHash(chainId));
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

            Context.SendInline(crossChainIndexingController.ContractAddress,
                nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                    .CreateProposalBySystemContract), proposalCreationInput);

            var proposedCrossChainBlockData = new CrossChainBlockData();
            if (crossChainDataDto.ParentChainToBeIndexedData.TryGetValue(chainId,
                    out var parentChainToBeIndexedData))
                proposedCrossChainBlockData.ParentChainBlockDataList.Add(parentChainToBeIndexedData);
            else if (crossChainDataDto.SideChainToBeIndexedData.TryGetValue(chainId,
                         out var sideChainToBeIndexedData))
                proposedCrossChainBlockData.SideChainBlockDataList.Add(sideChainToBeIndexedData);

            var crossChainIndexingProposal = new ChainIndexingProposal
            {
                ChainId = chainId,
                Proposer = proposer,
                ProposedCrossChainBlockData = proposedCrossChainBlockData
            };
            var proposalId = Context.GenerateId(crossChainIndexingController.ContractAddress, proposalToken);
            crossChainIndexingProposal.ProposalId = proposalId;
            SetCrossChainIndexingProposalStatus(crossChainIndexingProposal,
                CrossChainIndexingProposalStatus.Pending);
            Context.Fire(new CrossChainIndexingDataProposedEvent
            {
                ProposedCrossChainData = proposedCrossChainBlockData,
                ProposalId = proposalId
            });

            Context.LogDebug(() =>
                $"Proposed cross chain data for chain {ChainHelper.ConvertChainIdToBase58(chainId)}");
        }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L465-481)
```csharp
    private CrossChainDataDto ValidateCrossChainDataBeforeIndexing(CrossChainBlockData crossChainBlockData)
    {
        Assert(
            crossChainBlockData.ParentChainBlockDataList.Count > 0 ||
            crossChainBlockData.SideChainBlockDataList.Count > 0,
            "Empty cross chain data proposed.");
        var validatedParentChainBlockData = new Dictionary<int, List<ParentChainBlockData>>();
        var validationResult = ValidateSideChainBlockData(crossChainBlockData.SideChainBlockDataList,
                                   out var validatedSideChainBlockData) &&
                               ValidateParentChainBlockData(crossChainBlockData.ParentChainBlockDataList,
                                   out validatedParentChainBlockData);
        Assert(validationResult, "Invalid cross chain data to be indexed.");
        var crossChainDataDto = new CrossChainDataDto(validatedSideChainBlockData, validatedParentChainBlockData);

        Assert(crossChainDataDto.GetChainIdList().Count > 0, "Empty cross chain data not allowed.");
        return crossChainDataDto;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L559-575)
```csharp
    private void ClearCrossChainIndexingProposalIfExpired()
    {
        var crossChainIndexingProposal = State.IndexingPendingProposal.Value;
        if (crossChainIndexingProposal == null)
        {
            State.IndexingPendingProposal.Value = new ProposedCrossChainIndexing();
            return;
        }

        foreach (var chainId in crossChainIndexingProposal.ChainIndexingProposalCollections.Keys.ToList())
        {
            var indexingProposal = crossChainIndexingProposal.ChainIndexingProposalCollections[chainId];
            var isExpired = CheckProposalExpired(GetCrossChainIndexingController(), indexingProposal.ProposalId);
            if (isExpired)
                ResetChainIndexingProposal(chainId);
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-302)
```csharp
    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
        ReleaseIndexingProposal(input.ChainIdList);
        RecordCrossChainData(input.ChainIdList);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Constants.cs (L5-5)
```csharp
    private const int CrossChainIndexingProposalExpirationTimePeriod = 120;
```
