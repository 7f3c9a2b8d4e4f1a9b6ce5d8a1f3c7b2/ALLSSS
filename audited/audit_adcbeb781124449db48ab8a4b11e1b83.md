### Title
Missing Cryptographic Verification of Parent Chain Block Data Enables Consensus Manipulation via ExtraData Injection

### Summary
The `IndexParentChainBlockData()` helper function at line 784 extracts consensus information from `ExtraData[ConsensusExtraDataName]` without any cryptographic verification of the parent chain block data's authenticity. Colluding miners can propose fabricated parent chain block data containing malicious consensus information, and once approved through parliament governance, inject arbitrary miner lists to compromise the side chain's consensus mechanism. [1](#0-0) 

### Finding Description

**Root Cause:** The `ParentChainBlockData` structure lacks any cryptographic authentication fields (signature, signer public key, or merkle proofs linking to verified parent chain state). [2](#0-1) 

The validation function `ValidateParentChainBlockData()` only performs structural checks (chain ID match, height sequence, merkle root presence) but performs zero cryptographic verification that the data actually originated from the legitimate parent chain: [3](#0-2) 

**Exploitation Path:**

1. Malicious miner calls `ProposeCrossChainIndexing()` with fabricated `ParentChainBlockData` containing malicious bytes in `ExtraData[ConsensusExtraDataName]`: [4](#0-3) 

2. Data passes structural validation and creates a parliament proposal: [5](#0-4) 

3. Colluding miners approve the proposal through parliament governance, setting `ToBeReleased = true`: [6](#0-5) 

4. Any miner releases the proposal via `ReleaseCrossChainIndexingProposal()`, which calls `RecordCrossChainData()`: [7](#0-6) 

5. `IndexParentChainBlockData()` blindly extracts and forwards the malicious bytes to `UpdateConsensusInformation()` without verification: [8](#0-7) 

6. The consensus contract parses the injected bytes as `AElfConsensusHeaderInformation` and updates the miner list, with sender verification only confirming it came from the CrossChain contract (not validating data authenticity): [9](#0-8) 

### Impact Explanation

**Consensus Compromise:** Attackers can inject an arbitrary miner list (`State.MainChainCurrentMinerList.Value`) by crafting fake `AElfConsensusHeaderInformation` with controlled `Round.RealTimeMinersInformation`. This allows them to dictate who produces blocks on the side chain.

**Token Theft:** The `DistributeResourceTokensToPreviousMiners()` function sends accumulated resource tokens to the addresses in the injected miner list, enabling direct fund theft: [10](#0-9) 

**Side Chain Takeover:** By controlling the consensus miner list, attackers gain complete authority over block production, transaction inclusion, and all subsequent governance decisions on the side chain. All users and applications on the compromised side chain are affected.

**Severity Justification:** This violates the critical invariant "miner schedule integrity" and enables "fake header acceptance" - both listed as CRITICAL concerns. While block signatures exist in the system, they are never verified for parent chain data because `ParentChainBlockData` doesn't even include signature fields. [11](#0-10) 

### Likelihood Explanation

**Attacker Capabilities:** Requires corrupting sufficient miners to meet parliament approval thresholds. The default thresholds are defined in `CreateInitialOrganizationForInitialControllerAddress()`: [12](#0-11) 

**Attack Complexity:** MEDIUM - The attack requires:
- Multiple colluding miners (governance attack)
- Coordination to propose and approve malicious data
- Sustained collusion to maintain control

**Feasibility:** HIGH once preconditions met - The technical execution is straightforward since no cryptographic verification exists. The only barrier is achieving miner collusion.

**Economic Rationality:** HIGH - The reward (complete side chain control + token theft) significantly outweighs the cost of corrupting miners, especially for high-value side chains.

**Detection Constraints:** LOW - The malicious consensus updates appear legitimate since they pass all structural checks and governance approval. Without comparing against actual parent chain state, detection is difficult.

### Recommendation

**Immediate Mitigation:**

1. Add signature verification to `ParentChainBlockData`:
```protobuf
message ParentChainBlockData {
    // ... existing fields ...
    bytes signature = 7;
    bytes signer_pubkey = 8;
    aelf.Hash block_hash = 9;
}
```

2. Implement cryptographic verification in `ValidateParentChainBlockData()`:
   - Verify block signature using parent chain's known validator set
   - Validate that ExtraData matches the signed block's actual extra data
   - Confirm signer is an authorized parent chain miner

3. Add merkle proof verification for `ExtraData[ConsensusExtraDataName]`:
   - Include merkle proof showing consensus data was part of authenticated parent chain state
   - Verify proof against the already-validated `TransactionStatusMerkleTreeRoot`

**Invariant Checks:**
- Assert signature verification succeeds before storing parent chain data
- Assert ExtraData merkle proof validates before calling `UpdateConsensusInformation()`
- Log consensus information updates with parent chain block hash for auditability

**Test Cases:**
- Test rejection of parent chain data with invalid signatures
- Test rejection of parent chain data with mismatched ExtraData merkle proofs
- Test that governance approval cannot override cryptographic verification failures

### Proof of Concept

**Initial State:**
- Side chain initialized with legitimate parent chain connection
- Multiple colluding miners control parliament approval threshold
- Legitimate miner list: [M1, M2, M3, M4, M5]
- Attacker-controlled addresses: [A1, A2, A3]

**Attack Steps:**

1. **Propose Malicious Data:**
   - Colluding miner M1 calls `ProposeCrossChainIndexing()` with fabricated `ParentChainBlockData`:
     - `height`: current_height + 1 (passes sequence check)
     - `chain_id`: correct parent chain ID (passes ID check)
     - `transaction_status_merkle_tree_root`: arbitrary non-null hash (passes null check)
     - `extra_data["Consensus"]`: crafted `AElfConsensusHeaderInformation` with:
       - `Round.RoundNumber`: current_round + 1
       - `Round.RealTimeMinersInformation`: {A1, A2, A3}

2. **Approve via Governance:**
   - Colluding miners M1, M2, M3 approve the parliament proposal
   - Proposal reaches `MinimalApprovalThreshold`
   - `ToBeReleased` becomes `true`

3. **Release and Execute:**
   - Any miner calls `ReleaseCrossChainIndexingProposal([parent_chain_id])`
   - `RecordCrossChainData()` processes the fake data
   - Line 784: `blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes)` succeeds
   - Line 787: `UpdateConsensusInformation(bytes)` is called
   - Consensus contract updates `State.MainChainCurrentMinerList.Value` to {A1, A2, A3}
   - `DistributeResourceTokensToPreviousMiners()` sends tokens to A1, A2, A3

**Expected Result:** Transaction should revert with "Invalid parent chain block signature" or "ExtraData merkle proof verification failed"

**Actual Result:** Transaction succeeds, consensus miner list is replaced with attacker-controlled addresses, and tokens are distributed to attackers

**Success Condition:** Query `GetCurrentMinerList()` after attack and observe it returns [A1, A2, A3] instead of legitimate miners. Check token balances to confirm theft.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L309-322)
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
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L390-418)
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
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L455-463)
```csharp
    private void HandleIndexingProposal(Hash proposalId)
    {
        var crossChainIndexingController = GetCrossChainIndexingController();
        var proposal = GetCrossChainProposal(crossChainIndexingController, proposalId);
        Assert(proposal.ToBeReleased, "Not approved cross chain indexing proposal.");
        Context.SendInline(crossChainIndexingController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release),
            proposal.ProposalId); // release if ready
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L591-624)
```csharp
    private void CreateInitialOrganizationForInitialControllerAddress()
    {
        SetContractStateRequired(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
        var proposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = DefaultMinimalApprovalThreshold,
            MinimalVoteThreshold = DefaultMinimalVoteThresholdThreshold,
            MaximalAbstentionThreshold = DefaultMaximalAbstentionThreshold,
            MaximalRejectionThreshold = DefaultMaximalRejectionThreshold
        };
        State.ParliamentContract.CreateOrganizationBySystemContract.Send(
            new CreateOrganizationBySystemContractInput
            {
                OrganizationCreationInput = new Parliament.CreateOrganizationInput
                {
                    ProposalReleaseThreshold = proposalReleaseThreshold,
                    ProposerAuthorityRequired = false,
                    ParliamentMemberProposingAllowed = true
                },
                OrganizationAddressFeedbackMethod = nameof(SetInitialSideChainLifetimeControllerAddress)
            });

        State.ParliamentContract.CreateOrganizationBySystemContract.Send(
            new CreateOrganizationBySystemContractInput
            {
                OrganizationCreationInput = new Parliament.CreateOrganizationInput
                {
                    ProposalReleaseThreshold = proposalReleaseThreshold,
                    ProposerAuthorityRequired = true,
                    ParliamentMemberProposingAllowed = true
                },
                OrganizationAddressFeedbackMethod = nameof(SetInitialIndexingControllerAddress)
            });
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

**File:** protobuf/acs7.proto (L109-122)
```text
message ParentChainBlockData {
    // The height of parent chain.
    int64 height = 1;
    // The merkle tree root computing from side chain roots.
    CrossChainExtraData cross_chain_extra_data = 2;
    // The parent chain id.
    int32 chain_id = 3;
    // The merkle tree root computing from transactions status in parent chain block.
    aelf.Hash transaction_status_merkle_tree_root = 4;
    // Indexed block height from side chain and merkle path for this side chain block
    map<int64, aelf.MerklePath> indexed_merkle_path = 5;
    // Extra data map.
    map<string, bytes> extra_data = 6;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-63)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
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

**File:** src/AElf.Kernel.Core/Extensions/BlockExtensions.cs (L18-32)
```csharp
    public static bool VerifySignature(this IBlock block)
    {
        if (!block.Header.VerifyFields() || !block.Body.VerifyFields())
            return false;

        if (block.Header.Signature.IsEmpty)
            return false;

        var recovered = CryptoHelper.RecoverPublicKey(block.Header.Signature.ToByteArray(),
            block.GetHash().ToByteArray(), out var publicKey);
        if (!recovered)
            return false;

        return block.Header.SignerPubkey.ToByteArray().BytesEqual(publicKey);
    }
```
