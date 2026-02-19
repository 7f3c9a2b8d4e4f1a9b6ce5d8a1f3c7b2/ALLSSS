### Title
Missing Chain-Specific Miner Authorization in Cross-Chain Data Proposal

### Summary
The `ProposeCrossChainIndexing` function allows any current miner to propose cross-chain block data for any chain without verifying that the miner actually validates or has access to that specific chain. [1](#0-0)  The authorization check only validates the sender is a current miner on the local chain, not whether they have any relationship to the chain ID being proposed. This enables miners to propose potentially fake cross-chain data that relies solely on governance approval rather than cryptographic verification.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The `AssertAddressIsCurrentMiner` check calls the consensus contract's `CheckCrossChainIndexingPermission` method [2](#0-1) , which delegates to `IsCurrentMiner` [3](#0-2) . This check only verifies the address is a current miner on the local chain based on time slots and miner list membership [4](#0-3) , but never validates any authorization for the specific chain ID in the proposed data.

**Why Protections Fail:**

1. **Structural-Only Validation:** The `ValidateCrossChainDataBeforeIndexing` method only checks structural properties like sequential heights and chain existence [5](#0-4) [6](#0-5) , not cryptographic proofs or miner-to-chain authorization.

2. **Off-Chain Validation Bypass:** While a `CrossChainIndexingDataValidationService` exists [7](#0-6) , it can be disabled via configuration [8](#0-7)  and is not enforced on-chain.

3. **Governance Dependency:** The proposal requires Parliament approval [9](#0-8) , but Parliament approval is not cryptographically bound to data correctness and can be granted through collusion or negligence.

**Execution Path:**
1. Miner on Chain A proposes cross-chain data for Chain B (where they are not a validator)
2. `AssertAddressIsCurrentMiner` checks only Chain A miner status (passes)
3. `ValidateCrossChainDataBeforeIndexing` checks structural validity only (passes with correct heights/format)
4. Proposal created and stored with Pending status
5. If Parliament approves (manually or with disabled validation), proposal becomes ToBeReleased
6. Miner calls `ReleaseCrossChainIndexingProposal` [10](#0-9) 
7. Fake data indexed via `RecordCrossChainData` [11](#0-10) 

### Impact Explanation

**Direct Harm:** Enables indexing of fabricated cross-chain block data with fake merkle tree roots and transaction status. Once indexed, this fake data can be used in cross-chain transaction verification flows to falsely prove transactions occurred on chains where they didn't.

**Protocol Damage:**
- Breaks cross-chain integrity guarantees
- Enables fake cross-chain message verification
- Could allow theft through false proof of deposits/burns on other chains
- Undermines trust in the entire cross-chain infrastructure

**Affected Parties:**
- Users relying on cross-chain transaction verification
- Side chains whose fake data is indexed
- Main chain integrity when fake parent/side chain data is accepted

**Severity Justification:** HIGH - This violates the critical invariant "cross-chain proof verification and index heights" by allowing unverified cross-chain data to be indexed without cryptographic proof of correctness or authorization of the proposer for the specific chain.

### Likelihood Explanation

**Attacker Capabilities:** Must be a current miner on the local chain (high technical and economic barrier, but realistic for motivated attackers or colluding miners).

**Attack Complexity:** MEDIUM
- Proposing data requires understanding block structure and heights
- Must craft structurally valid but content-fake cross-chain data
- Requires either: (1) Parliament collusion/negligence, or (2) disabled off-chain validation

**Feasibility Conditions:**
- Off-chain validation disabled via `CrossChainDataValidationIgnored` config, OR
- Parliament members approve without proper validation, OR  
- Coordination between malicious miner and Parliament members

**Detection Constraints:** Off-chain validation would detect mismatches if enabled and properly configured, but this is not cryptographically enforced on-chain.

**Probability:** MEDIUM - While requiring miner status and governance approval creates barriers, the absence of on-chain cryptographic verification and reliance on configurable off-chain validation makes exploitation realistic under certain operational configurations or governance compromise scenarios.

### Recommendation

**Code-Level Mitigation:**

1. **Add Chain-Specific Authorization:** Implement a mechanism to verify miners are authorized for the specific chains they propose data for. This could involve:
   - Storing registered validators/miners per side chain ID
   - Checking proposer is in the validator set for the chain being proposed
   - Cross-referencing with chain initialization data

2. **Enhance On-Chain Cryptographic Verification:** Add verification of merkle proofs and block signatures within the validation logic:
   - Verify merkle tree roots against signed block headers
   - Validate block headers contain signatures from known validators of that chain
   - Check chain-specific consensus proofs before accepting data

3. **Enforce Validation On-Chain:** Move critical validation logic from off-chain service to on-chain contract code that cannot be bypassed.

**Invariant Checks to Add:**
```
Assert(IsMinerAuthorizedForChain(Context.Sender, chainId), 
    "Miner not authorized for this chain");
Assert(VerifyCrossChainBlockProof(blockData, chainId), 
    "Invalid cryptographic proof for cross-chain block");
```

**Test Cases:**
- Test that miners cannot propose data for chains they don't validate
- Test that proposals with invalid merkle proofs are rejected on-chain
- Test that cross-chain data verification cannot be bypassed with configuration changes

### Proof of Concept

**Required Initial State:**
- Main Chain with miner Alice
- Side Chain X with different miners (Bob, Carol)
- Alice is NOT a validator on Side Chain X

**Transaction Steps:**

1. **Alice crafts fake Side Chain X data:**
   ```
   sideChainBlockData = {
       ChainId: X,
       Height: 1,
       BlockHeaderHash: FakeHash1,
       TransactionStatusMerkleTreeRoot: FakeRoot1
   }
   ```

2. **Alice calls ProposeCrossChainIndexing:**
   - Sender: Alice (Main Chain miner) ✓
   - Input: CrossChainBlockData with fake sideChainBlockData
   - Authorization check: Passes (Alice is Main Chain miner)
   - Validation check: Passes (structurally valid - correct height sequence)
   - Result: Proposal created with Pending status

3. **Parliament approves** (if validation disabled or colluding members)

4. **Alice calls ReleaseCrossChainIndexingProposal:**
   - Proposal status changed to Accepted
   - Fake data indexed in State.IndexedSideChainBlockData

**Expected vs Actual:**
- **Expected:** Proposal should be rejected because Alice is not a validator for Side Chain X
- **Actual:** Proposal succeeds and fake data can be indexed if Parliament approves

**Success Condition:** Fake cross-chain block data from Side Chain X is successfully indexed on Main Chain despite being proposed by a miner who doesn't validate Side Chain X, with no cryptographic verification of the data's authenticity.

### Notes

The vulnerability stems from a fundamental architectural design where authorization is checked at the miner level (any miner) rather than at the chain-specific level (miner for THIS chain). While the off-chain validation service provides defense in depth, it can be disabled and is not cryptographically enforced. The system relies on governance trustworthiness rather than cryptographic guarantees for cross-chain data integrity, which violates the principle of trustless cross-chain verification.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L390-447)
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L690-743)
```csharp
    private bool ValidateSideChainBlockData(IEnumerable<SideChainBlockData> sideChainBlockData,
        out Dictionary<int, List<SideChainBlockData>> validatedSideChainBlockData)
    {
        var groupResult = sideChainBlockData.GroupBy(data => data.ChainId, data => data);

        validatedSideChainBlockData = new Dictionary<int, List<SideChainBlockData>>();
        foreach (var group in groupResult)
        {
            var chainId = group.Key;
            validatedSideChainBlockData[chainId] = group.ToList();
            var info = State.SideChainInfo[chainId];
            if (info == null || info.SideChainStatus == SideChainStatus.Terminated)
                return false;
            var currentSideChainHeight = State.CurrentSideChainHeight[chainId];
            var target = currentSideChainHeight != 0
                ? currentSideChainHeight + 1
                : AElfConstants.GenesisBlockHeight;

            foreach (var blockData in group)
            {
                var sideChainHeight = blockData.Height;
                if (target != sideChainHeight)
                    return false;
                target++;
            }
        }

        return true;
    }

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L136-221)
```csharp
    private bool IsCurrentMiner(string pubkey)
    {
        if (pubkey == null) return false;

        if (!TryToGetCurrentRoundInformation(out var currentRound)) return false;

        if (!currentRound.IsMinerListJustChanged)
            if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
                return false;

        Context.LogDebug(() =>
            $"Extra block producer of previous round: {currentRound.ExtraBlockProducerOfPreviousRound}");

        // Check confirmed extra block producer of previous round.
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }

        var miningInterval = currentRound.GetMiningInterval();
        var minerInRound = currentRound.RealTimeMinersInformation[pubkey];
        var timeSlotStartTime = minerInRound.ExpectedMiningTime;

        // Check normal time slot.
        if (timeSlotStartTime <= Context.CurrentBlockTime && Context.CurrentBlockTime <=
            timeSlotStartTime.AddMilliseconds(miningInterval))
        {
            Context.LogDebug(() => "[CURRENT MINER]NORMAL");
            return true;
        }

        var supposedExtraBlockProducer =
            currentRound.RealTimeMinersInformation.Single(m => m.Value.IsExtraBlockProducer).Key;

        // Check extra block time slot.
        if (Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime() &&
            supposedExtraBlockProducer == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]EXTRA");
            return true;
        }

        // Check saving extra block time slot.
        var nextArrangeMiningTime =
            currentRound.ArrangeAbnormalMiningTime(pubkey, Context.CurrentBlockTime, true);
        var actualArrangedMiningTime = nextArrangeMiningTime.AddMilliseconds(-currentRound.TotalMilliseconds());
        if (actualArrangedMiningTime <= Context.CurrentBlockTime &&
            Context.CurrentBlockTime <= actualArrangedMiningTime.AddMilliseconds(miningInterval))
        {
            Context.LogDebug(() => "[CURRENT MINER]SAVING");
            return true;
        }

        // If current round is the first round of current term.
        if (currentRound.RoundNumber == 1)
        {
            Context.LogDebug(() => "First round");

            var latestMinedInfo =
                currentRound.RealTimeMinersInformation.Values.OrderByDescending(i => i.Order)
                    .FirstOrDefault(i => i.ActualMiningTimes.Any() && i.Pubkey != pubkey);
            if (latestMinedInfo != null)
            {
                var minersCount = currentRound.RealTimeMinersInformation.Count;
                var latestMinedSlotLastActualMiningTime = latestMinedInfo.ActualMiningTimes.Last();
                var latestMinedOrder = latestMinedInfo.Order;
                var currentMinerOrder =
                    currentRound.RealTimeMinersInformation.Single(i => i.Key == pubkey).Value.Order;
                var passedSlotsCount =
                    (Context.CurrentBlockTime - latestMinedSlotLastActualMiningTime).Milliseconds()
                    .Div(miningInterval);
                if (passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(1).Add(minersCount) ||
                    passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(minersCount))
                {
                    Context.LogDebug(() => "[CURRENT MINER]FIRST ROUND");
                    return true;
                }
            }
        }

        Context.LogDebug(() => "[CURRENT MINER]NOT MINER");

        return false;
    }
```

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataValidationService.cs (L38-52)
```csharp
    public async Task<bool> ValidateCrossChainIndexingDataAsync(CrossChainBlockData crossChainBlockData,
        Hash blockHash, long blockHeight)
    {
        var sideChainBlockDataValidationResult =
            await ValidateSideChainBlockDataAsync(crossChainBlockData.SideChainBlockDataList, blockHash,
                blockHeight);
        if (!sideChainBlockDataValidationResult)
            return false;

        var parentChainBlockDataValidationResult =
            await ValidateParentChainBlockDataAsync(crossChainBlockData.ParentChainBlockDataList, blockHash,
                blockHeight);

        return parentChainBlockDataValidationResult;
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
