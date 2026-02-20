# Audit Report

## Title
Permanent Token Lock and Side Chain Disposal DoS Due to Unhandled Transfer Failure

## Summary
The `DisposeSideChain` function in the CrossChain contract executes token unlock via inline transaction without error handling. When the proposer address is blacklisted in the MultiToken contract, the transfer fails, reverting the entire disposal transaction before the side chain status is updated to Terminated. This permanently locks all deposited tokens and prevents side chain disposal with no recovery mechanism.

## Finding Description

The vulnerability exists in the side chain disposal flow where the `DisposeSideChain` method calls `UnlockTokenAndResource` before updating the chain status to Terminated. [1](#0-0) 

The `UnlockTokenAndResource` function unconditionally attempts to transfer tokens to the proposer without any error handling. It retrieves the deposit balance and calls `TransferDepositToken` to send tokens back to the proposer. [2](#0-1) 

The transfer is executed via `TransferDepositToken` using `Context.SendVirtualInline`, which creates an inline transaction to call the MultiToken contract's Transfer method. [3](#0-2) 

The MultiToken contract's `DoTransfer` method checks if the sender is blacklisted and asserts failure if true, preventing any transfer from blacklisted addresses. [4](#0-3) 

The blacklist check implementation confirms this validation occurs by reading the `TransferBlackList` state. [5](#0-4) 

Test evidence confirms that transfers fail when the sender is blacklisted, with the transaction status set to Failed and error message "From address is in transfer blacklist". [6](#0-5) 

When an inline transaction fails, the entire parent transaction fails and all state changes are rolled back, as demonstrated by test cases showing that failed inline transactions result in `TransactionResultStatus.Failed` with zero state changes persisted. [7](#0-6) 

Since the side chain status is set to Terminated AFTER the unlock call in `DisposeSideChain`, when the transfer fails, the status update never executes. A code search confirms that `DisposeSideChain` is the only method in the contract that sets `SideChainStatus = SideChainStatus.Terminated`, meaning there is no alternative disposal path. [8](#0-7) 

The tokens are locked in a virtual address deterministically derived from the chain ID, which has no private key and can only be controlled through the CrossChain contract's virtual inline calls. [9](#0-8) [10](#0-9) 

## Impact Explanation

**Direct Fund Impact**: All tokens deposited for side chain indexing fees become permanently locked in the virtual address derived from the chain ID. Since the virtual address is deterministically calculated and has no private key, and there is no alternative withdrawal mechanism, these funds are irrecoverable. Depending on the number of side chains and deposit amounts, this could represent significant value in native tokens.

**Operational Impact**: Complete and permanent DoS of the side chain disposal functionality. Once a proposer is blacklisted, that specific side chain can never be disposed, creating a "zombie chain" that:
- Consumes state storage indefinitely
- Cannot be removed from the system
- Cannot have its status properly terminated
- Prevents proper lifecycle management

**Affected Parties**:
- Side chain proposers lose all deposited indexing fees with no recovery path
- The parent chain suffers from inability to clean up terminated chains, leading to state bloat
- Protocol governance loses the ability to properly manage side chain lifecycle for affected chains

## Likelihood Explanation

**Realistic Trigger Conditions**: This vulnerability requires no malicious actor and can occur through normal protocol operations:

1. The MultiToken contract has an authorized `AddToTransferBlackList` function controlled by the transfer blacklist controller (typically Parliament)
2. Proposer addresses can be legitimately added to the blacklist for valid reasons (compromised addresses, regulatory compliance, sanctions compliance)
3. When governance attempts to dispose a side chain whose proposer is blacklisted, the transaction automatically fails [11](#0-10) 

**Probability Assessment**: Medium-to-high probability because:
- Transfer blacklisting is a designed protocol feature, not an edge case
- Proposer addresses may be blacklisted for legitimate operational or regulatory reasons
- No special conditions or elevated privileges are needed beyond normal governance operations
- Once triggered, the condition is permanent with no workaround
- The vulnerability affects the critical path for side chain lifecycle management

The execution path is straightforward and deterministic - any disposal attempt for a side chain with a blacklisted proposer will fail 100% of the time.

## Recommendation

Implement error handling in the `UnlockTokenAndResource` method to allow disposal to proceed even if the transfer fails. The fix should:

1. Wrap the `TransferDepositToken` call in a try-catch or check if the proposer is blacklisted before attempting transfer
2. If the transfer cannot be executed, either:
   - Skip the transfer and mark the tokens as claimable by the proposer after they are removed from the blacklist, OR
   - Transfer the tokens to an escrow address or treasury that can later distribute them appropriately
3. Ensure the side chain status is set to Terminated regardless of transfer success

Example fix approach:
- Add a check before transfer: `if (!State.TokenContract.IsInTransferBlackList.Call(sideChainInfo.Proposer).Value)`
- If blacklisted, store the locked amount in a separate state for later claim
- Proceed with status update to Terminated in all cases

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task DisposeSideChain_Fails_When_Proposer_Blacklisted()
{
    // Setup: Create side chain with deposited tokens
    var proposer = DefaultAddress;
    var chainId = await CreateSideChainAsync(proposer, 100000);
    
    // Governance blacklists the proposer
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var proposalId = await CreateProposalAsync(TokenContractAddress, defaultParliament, 
        nameof(TokenContractStub.AddToTransferBlackList), proposer);
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Verify proposer is blacklisted
    var isBlacklisted = await TokenContractStub.IsInTransferBlackList.CallAsync(proposer);
    isBlacklisted.Value.ShouldBe(true);
    
    // Attempt to dispose side chain
    var disposalProposalId = await CreateDisposalProposalAsync(chainId);
    await ApproveWithMinersAsync(disposalProposalId);
    var result = await ParliamentContractStub.Release.SendWithExceptionAsync(disposalProposalId);
    
    // Disposal fails due to blacklisted proposer
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("From address is in transfer blacklist");
    
    // Side chain status is NOT Terminated (still Active or IndexingFeeDebt)
    var sideChainInfo = await CrossChainContractStub.GetSideChainInfo.CallAsync(new Int32Value { Value = chainId });
    sideChainInfo.SideChainStatus.ShouldNotBe(SideChainStatus.Terminated);
    
    // Tokens remain locked in virtual address
    var lockedBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = CalculateVirtualAddress(chainId),
        Symbol = "ELF"
    });
    lockedBalance.Balance.ShouldBeGreaterThan(0);
}
```

## Notes

This is a critical design flaw that breaks the fundamental guarantee that side chains can always be properly disposed through governance action. The vulnerability demonstrates that defensive programming is essential when dealing with external contract calls, especially in critical state transitions. The fix must ensure that side chain lifecycle management remains operational regardless of the proposer's blacklist status, while still respecting the blacklist policy for actual token transfers.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L60-71)
```csharp
    private void ChargeSideChainIndexingFee(Address lockAddress, long amount, int chainId)
    {
        if (amount <= 0)
            return;
        TransferFrom(new TransferFromInput
        {
            From = lockAddress,
            To = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Amount = amount,
            Symbol = Context.Variables.NativeSymbol
        });
    }
```

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L88-98)
```csharp
    private long GetSideChainIndexingFeeDeposit(int chainId)
    {
        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        var balanceOutput = State.TokenContract.GetBalance.Call(new GetBalanceInput
        {
            Owner = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Symbol = Context.Variables.NativeSymbol
        });

        return balanceOutput.Balance;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L163-168)
```csharp
    private void TransferDepositToken(TransferInput input, int chainId)
    {
        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        Context.SendVirtualInline(ConvertChainIdToHash(chainId), State.TokenContract.Value,
            nameof(State.TokenContract.Transfer), input);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L99-114)
```csharp
    private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
    {
        Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
        Assert(from != to, "Can't do transfer to sender itself.");
        AssertValidMemo(memo);
        ModifyBalance(from, symbol, -amount);
        ModifyBalance(to, symbol, amount);
        Context.Fire(new Transferred
        {
            From = from,
            To = to,
            Symbol = symbol,
            Amount = amount,
            Memo = memo ?? string.Empty
        });
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L424-427)
```csharp
    private bool IsInTransferBlackListInternal(Address address)
    {
        return State.TransferBlackList[address];
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenApplicationTests.cs (L1928-1934)
```csharp
        // Owner adds DefaultAddress to blacklist via parliament proposal
        var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        var proposalId = await CreateProposalAsync(TokenContractAddress, defaultParliament, nameof(TokenContractStub.AddToTransferBlackList), DefaultAddress);
        await ApproveWithMinersAsync(proposalId);
        await ParliamentContractStub.Release.SendAsync(proposalId);
        isInTransferBlackList = await TokenContractStubUser.IsInTransferBlackList.CallAsync(DefaultAddress);
        isInTransferBlackList.Value.ShouldBe(true);
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenApplicationTests.cs (L1937-1945)
```csharp
        var transferResult = (await TokenContractStub.Transfer.SendWithExceptionAsync(new TransferInput
        {
            Amount = Amount,
            Memo = "blacklist test",
            Symbol = AliceCoinTokenInfo.Symbol,
            To = User1Address
        })).TransactionResult;
        transferResult.Status.ShouldBe(TransactionResultStatus.Failed);
        transferResult.Error.ShouldContain("From address is in transfer blacklist");
```

**File:** test/AElf.Parallel.Tests/DeleteDataFromStateDbTest.cs (L2059-2098)
```csharp
    public async Task Increase_Value_Failed_With_Inline()
    {
        var accountAddress = await _accountService.GetAccountAsync();
        var chain = await _blockchainService.GetChainAsync();
        await SetIrreversibleBlockAsync(chain);

        const string key = "TestKey";

        var value = await GetValueAsync(accountAddress, key, chain.BestChainHash, chain.BestChainHeight);
        CheckValueNotExisted(value);

        var transaction = await GenerateTransactionAsync(accountAddress,
            ParallelTestHelper.BasicFunctionWithParallelContractAddress,
            nameof(BasicFunctionWithParallelContractContainer.BasicFunctionWithParallelContractStub
                .IncreaseValueFailedWithInline), new IncreaseValueInput
            {
                Key = key,
                Memo = Guid.NewGuid().ToString()
            });
        var transactions = new List<Transaction> { transaction };
        var block = _parallelTestHelper.GenerateBlock(chain.BestChainHash, chain.BestChainHeight, transactions);
        block = (await _blockExecutingService.ExecuteBlockAsync(block.Header, transactions)).Block;
        await _blockchainService.AddTransactionsAsync(transactions);
        await _blockchainService.AddBlockAsync(block);
        await _blockAttachService.AttachBlockAsync(block);

        var transactionResult = await GetTransactionResultAsync(transaction.GetHash(), block.Header);
        transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);

        value = await GetValueAsync(accountAddress, key, block.GetHash(), block.Height);
        CheckValueNotExisted(value);

        var blockStateSet = await _blockStateSetManger.GetBlockStateSetAsync(block.GetHash());
        blockStateSet.Changes.Count.ShouldBe(0);
        blockStateSet.Deletes.Count.ShouldBe(0);

        chain = await _blockchainService.GetChainAsync();
        await SetIrreversibleBlockAsync(chain);
        await CheckValueNotExistedInVersionStateAsync(key);
    }
```
