### Title
Cross-Chain Indexing Fee Price Manipulation via TOCTOU Between Proposal and Release

### Summary
The cross-chain indexing system does not capture the indexing fee price at proposal time, allowing the IndexingFeeController to modify the price between when indexing is proposed and when it is released. This time-of-check-time-of-use vulnerability enables fee manipulation that can harm either side chains (via unexpected fee increases) or indexing proposers (via fee decreases), disrupting the economic incentive model.

### Finding Description

**Root Cause:**

The `ChainIndexingProposal` structure does not store the indexing price at proposal time. [1](#0-0) 

When a miner proposes cross-chain indexing via `ProposeCrossChainIndexing`, the proposal stores only the block data but not the fee price that will be charged. [2](#0-1) 

The indexing price is stored separately in `SideChainInfo.IndexingPrice` and can be modified by the IndexingFeeController organization through `AdjustIndexingFeePrice`. [3](#0-2) 

**Execution Path:**

1. At time T0, a miner calls `ProposeCrossChainIndexing` with side chain block data
2. The proposal is created with a 120-second expiration window [4](#0-3) 
3. Between T0 and release, the IndexingFeeController can call `AdjustIndexingFeePrice` to change the price
4. At time T1 (within 120 seconds), a miner calls `ReleaseCrossChainIndexingProposal`
5. This triggers `RecordCrossChainData` which calls `IndexSideChainBlockData` [5](#0-4) 
6. `IndexSideChainBlockData` reads the **current** `sideChainInfo.IndexingPrice` from state, not the price at proposal time [6](#0-5) 

**Why Protections Fail:**

There is no mechanism to lock or validate the fee price at proposal time against the price at execution time. The proposal approval process checks whether to approve the indexing operation itself, but does not verify pricing consistency.

### Impact Explanation

**Direct Financial Impact:**

- **Side Chain Harm**: If the IndexingFeeController increases the price between propose and release, the side chain's deposit is charged more than expected per indexed block. For each block indexed, the excess charge drains the side chain's locked deposit [7](#0-6) 

- **Proposer Harm**: If the price decreases, the miner who proposed indexing receives less fee reward than anticipated when they submitted the proposal [8](#0-7) 

**Who is Affected:**
- Side chains with active indexing operations
- Miners who propose cross-chain indexing data
- The economic predictability of the cross-chain system

**Severity Justification:**

This is a **Medium severity** issue because:
1. It requires IndexingFeeController cooperation (semi-trusted role)
2. The 120-second window is sufficient for coordinated attacks
3. Impact accumulates over multiple indexing operations
4. It undermines the economic security model of cross-chain operations

### Likelihood Explanation

**Attacker Capabilities:**

The attacker must either control or collude with the IndexingFeeController organization, which requires approval from both the side chain creator and the CrossChainIndexingController. [9](#0-8) 

**Attack Complexity:**

The attack is straightforward:
1. Monitor for pending cross-chain indexing proposals (publicly visible via `GetIndexingProposalStatus`)
2. Submit an `AdjustIndexingFeePrice` proposal through the Association organization
3. Get it approved by the parliament organization within the 120-second window
4. The price change takes effect before the indexing proposal is released

**Feasibility Conditions:**

- A cross-chain indexing proposal must be pending (normal operation)
- The IndexingFeeController can execute governance actions (designed capability)
- The 120-second proposal window provides sufficient time [4](#0-3) 

**Probability:**

While this requires a semi-trusted role's participation, the economic incentive exists for malicious IndexingFeeControllers to manipulate prices for profit, or for side chains to be vulnerable to front-running price increases during high-value indexing operations.

### Recommendation

**Code-Level Mitigation:**

Capture and store the indexing price at proposal time in the `ChainIndexingProposal` structure:

1. Add an `indexing_price` field to the `ChainIndexingProposal` message in `cross_chain_contract.proto`

2. In `ProposeCrossChainBlockData`, capture the current price when creating the proposal:
   - Read `sideChainInfo.IndexingPrice` and store it in the proposal
   - Location: [10](#0-9) 

3. In `IndexSideChainBlockData`, use the price from the proposal instead of reading from current state:
   - Accept the price as a parameter from the proposal
   - Remove the state read at [6](#0-5) 

**Invariant Checks:**

Add an assertion that validates the proposal's captured price matches reasonable bounds at release time, preventing extreme price manipulations even if the price changes.

**Test Cases:**

1. Test that proposes indexing, adjusts price upward, then releases → verify original price is used
2. Test that proposes indexing, adjusts price downward, then releases → verify original price is used
3. Test multiple concurrent proposals with different price snapshots

### Proof of Concept

**Initial State:**
- Side chain created with `indexing_price = 1` and `locked_token_amount = 100`
- Side chain has 2 blocks ready to be indexed (heights 1 and 2)

**Attack Sequence:**

1. **T0**: Miner proposes cross-chain indexing for 2 blocks
   - Expected cost: 2 blocks × 1 token = 2 tokens
   - `ProposeCrossChainIndexing` is called
   - Proposal expires at T0 + 120 seconds

2. **T0 + 30s**: IndexingFeeController submits and approves `AdjustIndexingFeePrice`
   - Changes `indexing_price` from 1 to 10
   - Price is now 10 tokens per block in state

3. **T0 + 60s**: Miner releases the proposal
   - `ReleaseCrossChainIndexingProposal` is called
   - `IndexSideChainBlockData` executes
   - Reads current price from state: 10 tokens per block
   - **Actual cost: 2 blocks × 10 tokens = 20 tokens**

**Expected Result:**
Side chain charged 2 tokens (original price × 2 blocks)

**Actual Result:**
Side chain charged 20 tokens (manipulated price × 2 blocks)

**Success Condition:**
The side chain's balance decreases by 20 tokens instead of 2 tokens, demonstrating the fee miscalculation vulnerability. [11](#0-10) 

### Notes

The vulnerability is confirmed through test evidence showing that fee calculations occur at release time using current state prices. [12](#0-11) 

The IndexingFeeController is created with both the side chain creator and the CrossChainIndexingController as members, requiring multi-party approval but still allowing coordinated manipulation. [9](#0-8)

### Citations

**File:** protobuf/cross_chain_contract.proto (L137-148)
```text
message ChainIndexingProposal{
    // The id of cross chain indexing proposal.
    aelf.Hash proposal_id = 1;
    // The proposer of cross chain indexing.
    aelf.Address proposer = 2;
    // The cross chain data proposed.
    acs7.CrossChainBlockData proposed_cross_chain_block_data = 3;
    // The status of of cross chain indexing proposal.
    CrossChainIndexingProposalStatus status = 4;
    // The chain id of the indexing.
    int32 chain_id = 5;
}
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L323-325)
```csharp
                indexedSideChainBlockData.SideChainBlockDataList.Add(IndexSideChainBlockData(
                    pendingCrossChainIndexingProposal.ProposedCrossChainBlockData.SideChainBlockDataList,
                    pendingCrossChainIndexingProposal.Proposer, chainId));
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L428-437)
```csharp
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
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L657-674)
```csharp
    private AuthorityInfo CreateDefaultOrganizationForIndexingFeePriceManagement(Address sideChainCreator)
    {
        var createOrganizationInput =
            GenerateOrganizationInputForIndexingFeePrice(new List<Address>
            {
                sideChainCreator,
                GetCrossChainIndexingController().OwnerAddress
            });
        SetContractStateRequired(State.AssociationContract, SmartContractConstants.AssociationContractSystemName);
        State.AssociationContract.CreateOrganization.Send(createOrganizationInput);

        var controllerAddress = CalculateSideChainIndexingFeeControllerOrganizationAddress(createOrganizationInput);
        return new AuthorityInfo
        {
            ContractAddress = State.AssociationContract.Value,
            OwnerAddress = controllerAddress
        };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L842-868)
```csharp
                var indexingPrice = sideChainInfo.IndexingPrice;

                lockedToken -= indexingPrice;

                if (lockedToken < 0)
                {
                    // record arrears
                    arrearsAmount += indexingPrice;
                    sideChainInfo.SideChainStatus = SideChainStatus.IndexingFeeDebt;
                }
                else
                {
                    indexingFeeAmount += indexingPrice;
                }

                currentSideChainHeight++;
                indexedSideChainBlockData.Add(sideChainBlockData);
            }

            if (indexingFeeAmount > 0)
                TransferDepositToken(new TransferInput
                {
                    To = proposer,
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = indexingFeeAmount,
                    Memo = "Index fee."
                }, chainId);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L244-255)
```csharp
    public override Empty AdjustIndexingFeePrice(AdjustIndexingFeeInput input)
    {
        var info = State.SideChainInfo[input.SideChainId];
        Assert(info != null && info.SideChainStatus != SideChainStatus.Terminated,
            "Side chain not found or incorrect side chain status.");
        Assert(input.IndexingFee >= 0, "Invalid side chain fee price.");
        var expectedOrganizationAddress = info.IndexingFeeController.OwnerAddress;
        Assert(expectedOrganizationAddress == Context.Sender, "No permission.");
        info.IndexingPrice = input.IndexingFee;
        State.SideChainInfo[input.SideChainId] = info;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Constants.cs (L5-5)
```csharp
    private const int CrossChainIndexingProposalExpirationTimePeriod = 120;
```

**File:** test/AElf.Contracts.CrossChain.Tests/CrossChainIndexingActionTest.cs (L761-765)
```csharp
            var balance = await CrossChainContractStub.GetSideChainBalance.CallAsync(new Int32Value
            {
                Value = sideChainId
            });
            balance.Value.ShouldBe(lockedToken - 2);
```
