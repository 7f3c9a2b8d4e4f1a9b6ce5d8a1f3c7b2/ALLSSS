### Title
Insufficient Bounds Validation in Side Chain Indexing Fee Adjustment Enables DoS and Economic Manipulation

### Summary
The `AdjustIndexingFeePrice` function lacks upper bound validation on the new indexing fee, only checking that it is non-negative. This allows the IndexingFeeController to set either zero fees (bypassing economic controls) or extremely high fees (causing permanent denial-of-service of side chain indexing operations). Once a side chain enters debt status due to an excessively high fee, recovery becomes practically impossible.

### Finding Description
The vulnerability exists in the `AdjustIndexingFeePrice` function which only validates that the new indexing fee is non-negative: [1](#0-0) 

This validation is insufficient compared to the initial creation validation which requires that locked token amount must be at least equal to the indexing price: [2](#0-1) 

During side chain block indexing, the indexing price is deducted from the locked token balance. When this balance becomes negative, the side chain enters debt status: [3](#0-2) 

To recover from debt status via recharge, the amount must cover all arrears plus at least one additional indexing fee. If the indexing fee is set to an extremely high value (e.g., near Int64.MaxValue), this requirement becomes impossible to satisfy: [4](#0-3) 

The IndexingFeeController is an Association organization created with two members (side chain creator and CrossChainIndexingController owner): [5](#0-4) 

### Impact Explanation
**High Severity** - Two distinct attack vectors with significant impact:

1. **Denial-of-Service Attack**: Setting IndexingPrice to extremely high values (e.g., 9,223,372,036,854,775,807 for Int64.MaxValue) causes immediate debt status on the next indexing attempt. The recharge requirement of `arrearsAmount + IndexingPrice` becomes mathematically impossible or causes overflow, permanently preventing further indexing of the side chain. This renders the side chain unusable for cross-chain operations.

2. **Economic Model Bypass**: Setting IndexingPrice to zero eliminates all indexing fees, allowing miners to propose side chain block data indexing without any economic cost. This breaks the incentive structure designed to prevent spam and ensure proper resource allocation, enabling potential abuse of the indexing mechanism.

Both attacks affect all users and contracts depending on the targeted side chain's cross-chain functionality.

### Likelihood Explanation
**Medium Likelihood** - The attack requires compromising the IndexingFeeController, which is an Association organization requiring approval from both:
- The side chain creator
- The CrossChainIndexingController owner address

While this requires governance-level access (two-party approval), the attack is straightforward once access is obtained:
1. Create a proposal to adjust indexing fee to extreme value (0 or Int64.MaxValue)
2. Obtain approvals from both Association members
3. Release the proposal to execute the fee adjustment
4. The vulnerability is immediately exploitable

The feasibility increases if there is governance compromise, collusion between the two parties, or social engineering. The attack leaves clear on-chain evidence but by the time it's detected, the damage (permanent DoS or zero-fee period) has occurred.

### Recommendation
Add comprehensive validation in the `AdjustIndexingFeePrice` function:

1. **Add upper bound check**: Implement a maximum reasonable indexing fee limit based on token economics. For example, limit to a percentage of total supply or a protocol-defined maximum.

2. **Add balance sufficiency check**: Verify that the current deposited balance can support at least a minimum number of blocks (e.g., 100 blocks) at the new price before allowing the adjustment:
   ```
   Assert(GetSideChainIndexingFeeDeposit(chainId) >= input.IndexingFee * MinimumBlockCount, 
          "Insufficient balance for new indexing fee.");
   ```

3. **Add rate-limit on fee increases**: Restrict how much the fee can increase in a single adjustment (e.g., maximum 200% of current fee) to prevent sudden price spikes.

4. **Prevent zero fees**: Add explicit check `Assert(input.IndexingFee > 0, "Indexing fee must be positive.")` to maintain economic model integrity.

5. **Add comprehensive test cases**: Test extreme values (0, Int64.MaxValue, negative via underflow), rapid fee adjustments, and recovery scenarios after fee changes.

### Proof of Concept
**Setup**: Side chain created with IndexingPrice = 1000 tokens, LockedTokenAmount = 100,000 tokens

**Attack Sequence**:
1. Side chain operates normally, indexing multiple blocks successfully
2. Attacker (with control of IndexingFeeController) creates Association proposal to call `AdjustIndexingFeePrice` with:
   - `side_chain_id`: [target chain ID]
   - `indexing_fee`: 9,223,372,036,854,775,807 (Int64.MaxValue)
3. Both Association members approve the proposal
4. Proposal is released and executed, setting IndexingPrice to Int64.MaxValue
5. Next miner attempts to index side chain block data via `ProposeCrossChainIndexing`
6. In `IndexSideChainBlockData` execution:
   - `indexingPrice` = 9,223,372,036,854,775,807
   - `lockedToken -= indexingPrice` results in large negative value
   - Side chain status changed to `SideChainStatus.IndexingFeeDebt`
   - `arrearsAmount` = 9,223,372,036,854,775,807 added to arrears
7. Any attempt to `Recharge` fails because required amount = arrearsAmount + IndexingPrice would overflow Int64 or exceed any practical token supply

**Expected Result**: Recharge succeeds and side chain returns to Active status
**Actual Result**: Recharge permanently fails; side chain stuck in debt status with no recovery path; cross-chain indexing operations halted indefinitely

**Success Condition**: Side chain cannot be indexed anymore and remains in permanent debt status, confirmed by `GetChainStatus` returning `INDEXING_FEE_DEBT` and all subsequent indexing attempts being blocked.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L206-208)
```csharp
            var originBalance = GetSideChainIndexingFeeDeposit(chainId);
            Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
                "Indexing fee recharging not enough.");
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L119-122)
```csharp
        Assert(
            sideChainCreationRequest.IndexingPrice >= 0 &&
            sideChainCreationRequest.LockedTokenAmount >= sideChainCreationRequest.IndexingPrice,
            "Invalid chain creation request.");
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L842-850)
```csharp
                var indexingPrice = sideChainInfo.IndexingPrice;

                lockedToken -= indexingPrice;

                if (lockedToken < 0)
                {
                    // record arrears
                    arrearsAmount += indexingPrice;
                    sideChainInfo.SideChainStatus = SideChainStatus.IndexingFeeDebt;
```
