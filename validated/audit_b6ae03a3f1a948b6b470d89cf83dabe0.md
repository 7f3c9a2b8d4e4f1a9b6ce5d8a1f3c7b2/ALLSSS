# Audit Report

## Title
Side Chain Disposal with Outstanding Debt Allows Indexing Fee Theft

## Summary
The `DisposeSideChain` function permits disposal of side chains in `IndexingFeeDebt` status without settling outstanding debts to indexers. The `UnlockTokenAndResource` helper returns remaining balance to the chain proposer while ignoring legitimate fee claims recorded in `ArrearsInfo`, causing permanent loss of funds owed to indexers.

## Finding Description

When a side chain's locked token balance depletes during indexing operations, the system transitions to `IndexingFeeDebt` status and records unpaid amounts in the `ArrearsInfo` mapping. [1](#0-0)  The status enum defines `INDEXING_FEE_DEBT = 2` as a valid intermediate state. [2](#0-1) 

The `DisposeSideChain` function only checks that status is not `Terminated`, allowing chains in `IndexingFeeDebt` status to proceed with disposal. [3](#0-2) 

During disposal, `UnlockTokenAndResource` retrieves the remaining balance and transfers it entirely to the proposer, but completely ignores any debts recorded in `ArrearsInfo`. [4](#0-3) 

The proper debt settlement pattern exists in the `Recharge` function, which iterates through `ArrearsInfo`, pays each creditor, and clears the debt records before restoring active status. [5](#0-4) 

The `ArrearsInfo` field stores creditor addresses (base64-encoded) mapped to debt amounts. [6](#0-5)  The total debt is calculated by summing all `ArrearsInfo` values. [7](#0-6) 

## Impact Explanation

**Direct Financial Loss:**
Indexers who proposed side chain block data permanently lose unpaid indexing fees recorded in `ArrearsInfo`. Each indexing operation performed after balance depletion creates debt that becomes unrecoverable once the chain is disposed. The impact equals the sum of all values in `ArrearsInfo`, with each indexed block during the debt period adding `IndexingPrice` to the total.

**Economic Model Violation:**
The cross-chain indexing system compensates miners per block indexed. When disposal erases debts without payment, it breaks the fundamental economic guarantee that indexers receive fees for work performed, undermining trust in the cross-chain system.

**Protocol Invariant Break:**
The contract maintains `ArrearsInfo` specifically to track legitimate claims. Allowing these claims to be erased without settlement violates the invariant that debt records must be honored before chain termination.

## Likelihood Explanation

**Execution Path:**
The vulnerability triggers through normal Parliament governance operations. A chain proposer creates a side chain with minimal locked tokens, operates until debt accumulates during indexing, then proposes disposal through standard governance channels.

**Realistic Preconditions:**
This scenario naturally occurs for underfunded side chains. The system is designed to allow chains to continue operating in debt status expecting eventual recharge. However, disposal is also a legitimate governance action for chains no longer needed.

**No Technical Barriers:**
All steps use public contract methods with appropriate authorization. The governance approval process is standard Parliament operation. No exploit techniques or special privileges are required beyond normal governance participation.

**Economic Feasibility:**
When accumulated debt exceeds the cost of side chain creation plus governance fees, avoiding debt through disposal becomes economically rational, creating a perverse incentive structure.

## Recommendation

Add a debt settlement check to `DisposeSideChain` before allowing disposal:

```csharp
public override Int32Value DisposeSideChain(Int32Value input)
{
    AssertSideChainLifetimeControllerAuthority(Context.Sender);

    var chainId = input.Value;
    var info = State.SideChainInfo[chainId];
    Assert(info != null, "Side chain not found.");
    Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");
    
    // ADD THIS CHECK:
    Assert(info.ArrearsInfo.Count == 0, "Cannot dispose chain with outstanding debt. Recharge required.");

    if (TryGetIndexingProposal(chainId, out _))
        ResetChainIndexingProposal(chainId);

    UnlockTokenAndResource(info);
    info.SideChainStatus = SideChainStatus.Terminated;
    State.SideChainInfo[chainId] = info;
    Context.Fire(new Disposed { ChainId = chainId });
    return new Int32Value { Value = chainId };
}
```

This ensures debts must be settled via `Recharge` before disposal is permitted.

## Proof of Concept

The existing test suite demonstrates the vulnerability conditions:

1. Test `Release_IndexingSideChain_IndexingFeeDebt` shows creation of debt status when balance depletes. [8](#0-7) 

2. A side chain with 2 locked tokens indexing 3 blocks (at 1 token each) transitions to `IndexingFeeDebt` status with 1 token of unpaid debt recorded in `ArrearsInfo`.

3. The disposal function accepts chains in this status and returns remaining balance to proposer without settling the recorded debt, as confirmed by the disposal logic flow.

## Notes

This vulnerability affects the cross-chain indexing economic model by allowing debt avoidance through disposal. The severity is compounded by the fact that `ArrearsInfo` exists specifically to track these legitimate claims, yet disposal ignores this critical state. Parliament governance must explicitly check for outstanding debts before approving disposal proposals to protect indexer compensation.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L73-86)
```csharp
    private void UnlockTokenAndResource(SideChainInfo sideChainInfo)
    {
        // unlock token
        var chainId = sideChainInfo.SideChainId;
        var balance = GetSideChainIndexingFeeDeposit(chainId);
        if (balance <= 0)
            return;
        TransferDepositToken(new TransferInput
        {
            To = sideChainInfo.Proposer,
            Amount = balance,
            Symbol = Context.Variables.NativeSymbol
        }, chainId);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L846-876)
```csharp
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
```

**File:** protobuf/cross_chain_contract.proto (L189-199)
```text
enum SideChainStatus
{
    // Currently no meaning.
    FATAL = 0;
    // The side chain is being indexed.
    ACTIVE = 1;
    // The side chain is in debt for indexing fee.
    INDEXING_FEE_DEBT = 2;
    // The side chain is disposed.
    TERMINATED = 3;
}
```

**File:** protobuf/cross_chain_contract.proto (L201-220)
```text
message SideChainInfo {
    // The proposer who propose to create the side chain.
    aelf.Address proposer = 1;
    // The status of side chain.
    SideChainStatus side_chain_status = 2;
    // The side chain id.
    int32 side_chain_id = 3;
    // The time of side chain created.
    google.protobuf.Timestamp creation_timestamp = 4;
    // The height of side chain created on parent chain.
    int64 creation_height_on_parent_chain = 5;
    // The price of indexing fee.
    int64 indexing_price = 6;
    // True if chain privilege needed, otherwise false.
    bool is_privilege_preserved = 7;
    // creditor and amounts for the chain indexing fee debt 
    map<string, int64> arrears_info = 8;
    // The controller of indexing fee.
    AuthorityInfo indexing_fee_controller = 9;
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L222-242)
```csharp
    public override Int32Value DisposeSideChain(Int32Value input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var chainId = input.Value;
        var info = State.SideChainInfo[chainId];
        Assert(info != null, "Side chain not found.");
        Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");

        if (TryGetIndexingProposal(chainId, out _))
            ResetChainIndexingProposal(chainId);

        UnlockTokenAndResource(info);
        info.SideChainStatus = SideChainStatus.Terminated;
        State.SideChainInfo[chainId] = info;
        Context.Fire(new Disposed
        {
            ChainId = chainId
        });
        return new Int32Value { Value = chainId };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L89-99)
```csharp
    public override Int64Value GetSideChainIndexingFeeDebt(Int32Value input)
    {
        var chainId = input.Value;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null, "Side chain not found.");

        return new Int64Value
        {
            Value = sideChainInfo.ArrearsInfo.Values.Sum()
        };
    }
```

**File:** test/AElf.Contracts.CrossChain.Tests/CrossChainIndexingActionTest.cs (L1131-1252)
```csharp
    public async Task Release_IndexingSideChain_IndexingFeeDebt()
    {
        var parentChainId = 123;
        long lockedToken = 2;
        long indexingPrice = 1;
        long parentChainHeightOfCreation = 10;

        // transfer token
        var transferTx = await TokenContractStub.Transfer.SendAsync(new TransferInput
        {
            Amount = 1000,
            Symbol = "ELF",
            To = AnotherSender
        });

        var sideChainId =
            await InitAndCreateSideChainAsync(parentChainHeightOfCreation, parentChainId, lockedToken,
                indexingPrice, AnotherKeyPair);

        var balanceBeforeIndexing = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = DefaultSender,
            Symbol = "ELF"
        });

        var fakeSideChainBlockHash = HashHelper.ComputeFrom("sideChainBlockHash");
        var fakeTxMerkleTreeRoot = HashHelper.ComputeFrom("txMerkleTreeRoot");
        var sideChainBlockData1 =
            CreateSideChainBlockData(fakeSideChainBlockHash, 1, sideChainId, fakeTxMerkleTreeRoot);
        var sideChainBlockData2 =
            CreateSideChainBlockData(fakeSideChainBlockHash, 2, sideChainId, fakeTxMerkleTreeRoot);
        var sideChainBlockData3 =
            CreateSideChainBlockData(fakeSideChainBlockHash, 3, sideChainId, fakeTxMerkleTreeRoot);

        var crossChainBlockData = new CrossChainBlockData
        {
            SideChainBlockDataList = { sideChainBlockData1, sideChainBlockData2, sideChainBlockData3 }
        };

        var txRes =
            await CrossChainContractStub.ProposeCrossChainIndexing.SendAsync(crossChainBlockData);
        txRes.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        var proposalId = ProposalCreated.Parser
            .ParseFrom(txRes.TransactionResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
            .ProposalId;
        Assert.NotNull(proposalId);
        await ApproveWithMinersAsync(proposalId);

        {
            var chainStatus = await CrossChainContractStub.GetChainStatus.CallAsync(new Int32Value
            {
                Value = sideChainId
            });
            chainStatus.Status.ShouldBe(SideChainStatus.Active);
        }

        var releaseResult = await CrossChainContractStub.ReleaseCrossChainIndexingProposal.SendAsync(
            new ReleaseCrossChainIndexingProposalInput
            {
                ChainIdList = { sideChainId }
            });
        releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        {
            var chainStatus = await CrossChainContractStub.GetChainStatus.CallAsync(new Int32Value
            {
                Value = sideChainId
            });
            chainStatus.Status.ShouldBe(SideChainStatus.IndexingFeeDebt);
        }

        var sideChainIndexedHeight =
            (await CrossChainContractStub.GetSideChainHeight.CallAsync(new Int32Value { Value = sideChainId }))
            .Value;
        sideChainIndexedHeight.ShouldBe(crossChainBlockData.SideChainBlockDataList.Last().Height);

        var balanceAfterIndexing = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = DefaultSender,
            Symbol = "ELF"
        });
        balanceAfterIndexing.Balance.ShouldBe(balanceBeforeIndexing.Balance + lockedToken);

        // recharge
        var arrearsAmount = crossChainBlockData.SideChainBlockDataList.Count - lockedToken;
        var rechargeAmount = arrearsAmount + indexingPrice;
        // approve allowance
        await ApproveBalanceAsync(rechargeAmount, AnotherKeyPair);

        var crossChainContractStub = GetCrossChainContractStub(AnotherKeyPair);

        {
            var rechargeTxFailed = await crossChainContractStub.Recharge.SendWithExceptionAsync(new RechargeInput
            {
                ChainId = sideChainId,
                Amount = rechargeAmount - 1
            });
            rechargeTxFailed.TransactionResult.Error.ShouldContain("Indexing fee recharging not enough.");
        }

        var rechargeTx = await crossChainContractStub.Recharge.SendAsync(new RechargeInput
        {
            ChainId = sideChainId,
            Amount = rechargeAmount
        });
        rechargeTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        var balanceAfterRecharge = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = DefaultSender,
            Symbol = "ELF"
        });
        balanceAfterRecharge.Balance.ShouldBe(balanceAfterIndexing.Balance + arrearsAmount);

        {
            var chainStatus = await CrossChainContractStub.GetChainStatus.CallAsync(new Int32Value
            {
                Value = sideChainId
            });
            chainStatus.Status.ShouldBe(SideChainStatus.Active);
        }
    }
```
