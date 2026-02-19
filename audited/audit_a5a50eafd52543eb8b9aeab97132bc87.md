### Title
Insufficient Contract Address Validation in ChangeSideChainIndexingFeeController Allows Governance Bypass

### Summary
The `ChangeSideChainIndexingFeeController` function only validates that an organization exists via `ValidateAuthorityInfoExists`, but fails to restrict the controller's contract address to legitimate governance contracts (Parliament, Association, or Referendum). An attacker who gets a malicious proposal approved can change the controller to point to a malicious contract with a regular user address as owner, enabling unilateral control over indexing fee adjustments and bypassing all governance mechanisms.

### Finding Description

The vulnerability exists in the `ChangeSideChainIndexingFeeController` function where the validation is insufficient: [1](#0-0) 

At line 262, the function calls `ValidateAuthorityInfoExists(input.AuthorityInfo)` to validate the new controller. This validation implementation only checks if an organization exists by calling the contract specified in the input: [2](#0-1) 

The critical flaw is that this validation accepts ANY contract address that implements the `ValidateOrganizationExist` method and returns true. An attacker can deploy a malicious contract that implements this ACS3 interface method to always return true: [3](#0-2) 

The legitimate implementation checks if an organization exists in state, but a malicious implementation could simply return `true` unconditionally.

In stark contrast, `ChangeCrossChainIndexingController` properly restricts the contract address to only the Parliament contract: [4](#0-3) 

Line 66 explicitly validates `input.ContractAddress == State.ParliamentContract.Value`, preventing any malicious contract from being set. This protection is absent from `ChangeSideChainIndexingFeeController`.

### Impact Explanation

Once the controller is changed to a malicious contract setup, the attacker gains unilateral control over the `AdjustIndexingFeePrice` function: [5](#0-4) 

Line 251 checks that `Context.Sender == expectedOrganizationAddress` where `expectedOrganizationAddress` is the controller's `OwnerAddress`. With a malicious controller having `OwnerAddress` set to the attacker's regular address, they can call this function directly without any governance approval.

The `IndexingPrice` directly affects cross-chain economics in the indexing mechanism: [6](#0-5) 

At lines 842-855, the `IndexingPrice` is deducted from locked tokens for each indexed block and paid to miners. An attacker controlling this parameter can:

1. **Set to 0**: Miners receive no payment, leading to DoS as no one indexes the side chain
2. **Set extremely high**: Side chain immediately enters `IndexingFeeDebt` status (line 850), making recharge impossible: [7](#0-6) 

Line 207 requires recharge amounts to cover `arrearsAmount + IndexingPrice`, which becomes impossible with extreme values.

3. **Manipulate for gain**: If attacker is a miner, they can set high fees to extract locked tokens for themselves

This affects all cross-chain operations for the targeted side chain and undermines the entire governance model.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Deploy a malicious contract implementing `ValidateOrganizationExist` that returns true (feasible on testnets, requires governance on mainnet)
2. Create a proposal through the existing legitimate organization to change the controller
3. Get the proposal approved by current organization members

**Feasibility:**
- **Entry Point**: Public method `ChangeSideChainIndexingFeeController` accessible through governance proposals
- **Preconditions**: Must be initiated through current legitimate organization (initially Association with side chain creator and CrossChainIndexingController owner as members)
- **Social Engineering Vector**: Proposal parameters can be complex/obfuscated, making malicious intent difficult to detect for approvers
- **Insider Threat**: If attacker is already an organization member with voting power, they can push the proposal through
- **Test Environment**: Fully exploitable on networks without contract deployment restrictions

The default initial controller is created as: [8](#0-7) 

With only 2 members (side chain creator and indexing controller owner) and unanimous approval required, social engineering or compromise of one member makes this exploitable.

**Probability Assessment**: Medium to High depending on network configuration and member diligence in reviewing proposals.

### Recommendation

**Immediate Fix**: Add contract address validation to restrict the controller to legitimate governance contracts, following the pattern used in `ChangeCrossChainIndexingController`:

At line 262 in `CrossChainContract.cs`, replace the current validation with:

```
Assert(
    (input.AuthorityInfo.ContractAddress == State.ParliamentContract.Value ||
     input.AuthorityInfo.ContractAddress == State.AssociationContract.Value ||
     input.AuthorityInfo.ContractAddress == State.ReferendumContract.Value) &&
    ValidateAuthorityInfoExists(input.AuthorityInfo),
    "Invalid authority input.");
```

**Additional Hardening**:
1. Apply the same fix to `ChangeSideChainLifetimeController` at line 79, which has the identical vulnerability: [9](#0-8) 

2. Add regression tests that attempt to set controllers with non-governance contract addresses and verify they fail
3. Add integration tests that verify malicious contracts cannot bypass validation
4. Consider adding events that clearly log the old and new contract addresses for easier monitoring

### Proof of Concept

**Initial State:**
- Side chain created with default Association-based IndexingFeeController
- Controller members: SideChainCreator and CrossChainIndexingController.OwnerAddress

**Attack Steps:**

1. Attacker deploys malicious contract `MaliciousAuth.cs`:
```
public override BoolValue ValidateOrganizationExist(Address input) {
    return new BoolValue { Value = true };
}
```

2. Attacker creates Association proposal to call `ChangeSideChainIndexingFeeController`:
   - ChainId: target_side_chain_id
   - AuthorityInfo.ContractAddress: malicious_contract_address
   - AuthorityInfo.OwnerAddress: attacker_address (regular user, not organization)

3. Through social engineering or insider compromise, proposal gets approved by both members

4. Proposal is released, controller is changed

5. **Exploitation**: Attacker directly calls `AdjustIndexingFeePrice`:
   - SideChainId: target_side_chain_id
   - IndexingFee: 0 (or extremely high value)
   - Context.Sender: attacker_address
   - Check at line 251 passes because attacker_address == controller.OwnerAddress

**Expected Result**: Transaction fails with "Invalid authority input" due to malicious contract address

**Actual Result**: Transaction succeeds, controller is changed, attacker gains unilateral control over indexing fees without any governance oversight

**Success Condition**: After step 5, attacker can repeatedly adjust indexing fees to any value without requiring any proposals or approvals, effectively bypassing the governance system and disrupting cross-chain operations.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L61-74)
```csharp
    public override Empty ChangeCrossChainIndexingController(AuthorityInfo input)
    {
        AssertCrossChainIndexingControllerAuthority(Context.Sender);
        SetContractStateRequired(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
        Assert(
            input.ContractAddress == State.ParliamentContract.Value &&
            ValidateParliamentOrganization(input.OwnerAddress), "Invalid authority input.");
        State.CrossChainIndexingController.Value = input;
        Context.Fire(new CrossChainIndexingControllerChanged
        {
            AuthorityInfo = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L76-86)
```csharp
    public override Empty ChangeSideChainLifetimeController(AuthorityInfo input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);
        Assert(ValidateAuthorityInfoExists(input), "Invalid authority input.");
        State.SideChainLifetimeController.Value = input;
        Context.Fire(new SideChainLifetimeControllerChanged
        {
            AuthorityInfo = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L174-215)
```csharp
    public override Empty Recharge(RechargeInput input)
    {
        var chainId = input.ChainId;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null && sideChainInfo.SideChainStatus != SideChainStatus.Terminated,
            "Side chain not found or incorrect side chain status.");

        TransferFrom(new TransferFromInput
        {
            From = Context.Sender,
            To = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Symbol = Context.Variables.NativeSymbol,
            Amount = input.Amount,
            Memo = "Indexing fee recharging."
        });

        long arrearsAmount = 0;
        if (sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt)
        {
            // arrears
            foreach (var arrears in sideChainInfo.ArrearsInfo)
            {
                arrearsAmount += arrears.Value;
                TransferDepositToken(new TransferInput
                {
                    To = Address.Parser.ParseFrom(ByteString.FromBase64(arrears.Key)),
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = arrears.Value,
                    Memo = "Indexing fee recharging."
                }, chainId);
            }

            var originBalance = GetSideChainIndexingFeeDeposit(chainId);
            Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
                "Indexing fee recharging not enough.");
        }

        sideChainInfo.ArrearsInfo.Clear();
        sideChainInfo.SideChainStatus = SideChainStatus.Active;
        State.SideChainInfo[chainId] = sideChainInfo;
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L257-271)
```csharp
    public override Empty ChangeSideChainIndexingFeeController(ChangeSideChainIndexingFeeControllerInput input)
    {
        var sideChainInfo = State.SideChainInfo[input.ChainId];
        var authorityInfo = sideChainInfo.IndexingFeeController;
        Assert(authorityInfo.OwnerAddress == Context.Sender, "No permission.");
        Assert(ValidateAuthorityInfoExists(input.AuthorityInfo), "Invalid authority input.");
        sideChainInfo.IndexingFeeController = input.AuthorityInfo;
        State.SideChainInfo[input.ChainId] = sideChainInfo;
        Context.Fire(new SideChainIndexingFeeControllerChanged
        {
            ChainId = input.ChainId,
            AuthorityInfo = input.AuthorityInfo
        });
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L676-681)
```csharp
    private bool ValidateAuthorityInfoExists(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L809-893)
```csharp
    /// <summary>
    ///     Index side chain block data.
    /// </summary>
    /// <param name="sideChainBlockDataList">Side chain block data to be indexed.</param>
    /// <param name="proposer">Charge indexing fee for the one who proposed side chain block data.</param>
    /// <param name="chainId">Chain id of side chain to be indexed.</param>
    /// <returns>Valid side chain block data which are indexed.</returns>
    private List<SideChainBlockData> IndexSideChainBlockData(IList<SideChainBlockData> sideChainBlockDataList,
        Address proposer, int chainId)
    {
        var indexedSideChainBlockData = new List<SideChainBlockData>();

        {
            var formattedProposerAddress = proposer.ToByteString().ToBase64();
            long indexingFeeAmount = 0;

            var sideChainInfo = State.SideChainInfo[chainId];
            var currentSideChainHeight = State.CurrentSideChainHeight[chainId];
            long arrearsAmount = 0;
            var lockedToken = sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt
                ? 0
                : GetSideChainIndexingFeeDeposit(chainId);

            foreach (var sideChainBlockData in sideChainBlockDataList)
            {
                var target = currentSideChainHeight != 0
                    ? currentSideChainHeight + 1
                    : AElfConstants.GenesisBlockHeight;
                var sideChainHeight = sideChainBlockData.Height;
                if (target != sideChainHeight)
                    break;

                // indexing fee
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

            if (arrearsAmount > 0)
            {
                if (sideChainInfo.ArrearsInfo.TryGetValue(formattedProposerAddress, out var amount))
                    sideChainInfo.ArrearsInfo[formattedProposerAddress] = amount + arrearsAmount;
                else
                    sideChainInfo.ArrearsInfo[formattedProposerAddress] = arrearsAmount;
            }

            State.SideChainInfo[chainId] = sideChainInfo;
            State.CurrentSideChainHeight[chainId] = currentSideChainHeight;
            
            Context.Fire(new SideChainIndexed
            {
                ChainId = chainId,
                IndexedHeight = currentSideChainHeight
            });
        }

        if (indexedSideChainBlockData.Count > 0)
            Context.LogDebug(() =>
                $"Last indexed height {indexedSideChainBlockData.Last().Height} for side chain {chainId}");

        return indexedSideChainBlockData;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```
