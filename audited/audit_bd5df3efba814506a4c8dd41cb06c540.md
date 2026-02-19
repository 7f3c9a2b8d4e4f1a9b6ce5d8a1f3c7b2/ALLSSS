### Title
Missing Proposer Address Validation in UnlockTokenAndResource Causes Permanent Fund Lock on Side Chain Disposal

### Summary
The `UnlockTokenAndResource` function does not validate that `sideChainInfo.Proposer` is not the zero address before attempting to transfer the side chain's balance. If a side chain is created with a zero address as proposer (possible when `LockedTokenAmount` is zero), the disposal transaction will permanently fail, locking funds in the chain's virtual address forever.

### Finding Description

The `UnlockTokenAndResource` function transfers the side chain's deposited balance back to the proposer during disposal without validating the proposer address: [1](#0-0) 

The function only checks if balance is positive, then directly transfers to `sideChainInfo.Proposer` without verifying it's a valid non-zero address.

**Root Cause:** When a side chain is created via `CreateSideChain`, the proposer address from input is used without validation: [2](#0-1) 

The validation in `AssertValidSideChainCreationRequest` checks allowance but not address validity: [3](#0-2) 

If `LockedTokenAmount` is zero, `ChargeSideChainIndexingFee` returns early without executing any transfer: [4](#0-3) 

This allows a side chain to be created with a zero address proposer when `LockedTokenAmount = 0`.

**Execution Path:**
1. Governance approves `CreateSideChain` proposal with `input.Proposer = zero address` and `LockedTokenAmount = 0`
2. Side chain is successfully created with zero address as proposer
3. Side chain accumulates indexing fee deposits in its virtual address over time
4. When `DisposeSideChain` is called, it invokes `UnlockTokenAndResource`: [5](#0-4) 

5. The transfer to zero address fails due to token contract validation: [6](#0-5) 

6. The entire disposal transaction reverts, leaving funds permanently locked.

### Impact Explanation

**Direct Fund Impact:** All deposited indexing fees for the side chain become permanently locked in the chain's virtual address. The disposal operation cannot complete because the transfer to zero address always fails. Since disposal is the only mechanism to unlock these funds, they are lost forever.

**Operational Impact:** The side chain cannot be properly terminated. Its status remains non-terminated, and the indexing fee deposits remain inaccessible. This breaks the side chain lifecycle management.

**Affected Parties:** The original proposer (if they were legitimate) loses their locked tokens, and anyone who deposited indexing fees for that chain loses access to those funds.

**Severity Justification:** Medium severity because while the impact is high (permanent fund loss), it requires governance to approve a malicious or erroneous proposal, which has a lower probability. However, the vulnerability is concrete and exploitable.

### Likelihood Explanation

**Attacker Capabilities:** Requires ability to create and get approval for a governance proposal to the `SideChainLifetimeController` organization. This could occur through:
- Compromise of sufficient governance participants
- Social engineering of governance voters
- Accidental approval of a buggy proposal

**Attack Complexity:** Low once governance access is obtained. The proposal simply needs:
- `Proposer` field set to zero address
- `LockedTokenAmount` set to 0 (to bypass transfer checks)

**Feasibility Conditions:** 
- Governance organization must approve the malicious proposal
- The side chain must accumulate deposits before disposal attempt

**Probability Reasoning:** While governance compromise is generally assumed trusted in many systems, accidental or malicious creation of invalid proposals is a realistic threat model for Medium severity findings. The lack of basic address validation represents a defensive programming failure.

### Recommendation

Add explicit validation of the proposer address in `UnlockTokenAndResource` before attempting the transfer:

```csharp
private void UnlockTokenAndResource(SideChainInfo sideChainInfo)
{
    // unlock token
    var chainId = sideChainInfo.SideChainId;
    var balance = GetSideChainIndexingFeeDeposit(chainId);
    if (balance <= 0)
        return;
    
    // Validate proposer address
    Assert(sideChainInfo.Proposer != null && !sideChainInfo.Proposer.Value.IsNullOrEmpty(), 
        "Invalid proposer address.");
    
    TransferDepositToken(new TransferInput
    {
        To = sideChainInfo.Proposer,
        Amount = balance,
        Symbol = Context.Variables.NativeSymbol
    }, chainId);
}
```

Additionally, add validation in `CreateSideChain` to prevent creating chains with invalid proposers:

```csharp
// After line 124 in CreateSideChain
Assert(input.Proposer != null && !input.Proposer.Value.IsNullOrEmpty(), 
    "Invalid proposer address.");
```

**Test Cases:**
1. Test disposal of side chain with zero address proposer fails gracefully
2. Test CreateSideChain rejects zero address proposer
3. Test disposal of valid side chain succeeds and returns funds correctly

### Proof of Concept

**Initial State:**
- CrossChain contract initialized with governance
- Token contract with native tokens

**Attack Steps:**

1. **Malicious Proposal Creation:** Governance member creates proposal to `CreateSideChain` with:
   - `input.SideChainCreationRequest.LockedTokenAmount = 0`
   - `input.Proposer = Address.FromBase58("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")` (zero address)

2. **Proposal Approval:** Governance approves and releases the proposal

3. **Side Chain Created:** Transaction succeeds because:
   - Allowance check passes (0 >= 0)
   - ChargeSideChainIndexingFee returns early
   - SideChainInfo stored with zero proposer

4. **Accumulate Deposits:** Side chain receives indexing fee deposits over time in its virtual address

5. **Attempt Disposal:** Governance calls `DisposeSideChain` for the chain

**Expected Result:** Disposal completes successfully, funds returned to proposer

**Actual Result:** Transaction fails with "Invalid input address" error from token contract. Funds remain permanently locked in the side chain's virtual address. The side chain cannot be disposed of, violating the cross-chain lifecycle invariant.

**Success Condition:** The side chain exists with deposits but cannot be disposed, and `GetSideChainBalance` shows locked funds that cannot be recovered.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L100-122)
```csharp
    private void AssertValidSideChainCreationRequest(SideChainCreationRequest sideChainCreationRequest,
        Address proposer)
    {
        var proposedRequest = State.ProposedSideChainCreationRequestState[Context.Sender];
        Assert(proposedRequest == null || Context.CurrentBlockTime >= proposedRequest.ExpiredTime,
            "Request side chain creation failed.");

        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        var allowance = State.TokenContract.GetAllowance.Call(new GetAllowanceInput
        {
            Owner = proposer,
            Spender = Context.Self,
            Symbol = Context.Variables.NativeSymbol
        }).Allowance;

        Assert(
            allowance >= sideChainCreationRequest.LockedTokenAmount,
            "Allowance not enough.");

        Assert(
            sideChainCreationRequest.IndexingPrice >= 0 &&
            sideChainCreationRequest.LockedTokenAmount >= sideChainCreationRequest.IndexingPrice,
            "Invalid chain creation request.");
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L143-154)
```csharp
        var sideChainInfo = new SideChainInfo
        {
            Proposer = input.Proposer,
            SideChainId = chainId,
            SideChainStatus = SideChainStatus.Active,
            IndexingPrice = sideChainCreationRequest.IndexingPrice,
            IsPrivilegePreserved = sideChainCreationRequest.IsPrivilegePreserved,
            CreationTimestamp = Context.CurrentBlockTime,
            CreationHeightOnParentChain = Context.CurrentHeight,
            IndexingFeeController = CreateDefaultOrganizationForIndexingFeePriceManagement(input.Proposer)
        };
        State.SideChainInfo[chainId] = sideChainInfo;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L234-234)
```csharp
        UnlockTokenAndResource(info);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```
