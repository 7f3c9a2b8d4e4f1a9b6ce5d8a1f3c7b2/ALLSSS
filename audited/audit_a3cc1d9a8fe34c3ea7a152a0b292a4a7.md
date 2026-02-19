### Title
NFT Contract SetMethodFee Stub Implementation Enables Governance Resource Waste Through No-Op Proposals

### Summary
The NFT contract's `SetMethodFee()` function is implemented as a no-op stub that always returns success without persisting any fee changes or performing any state modifications. This allows malicious or misguided governance proposals to pass through Parliament's full approval process, execute successfully, but accomplish nothing, wasting governance resources including voting time, proposer effort, and transaction fees.

### Finding Description

The NFT contract implements the ACS1 standard's `SetMethodFee()` method as an empty stub that immediately returns `Empty` without any logic: [1](#0-0) 

Similarly, `ChangeMethodFeeController()` is also a no-op: [2](#0-1) 

The root cause is that the NFT contract's state definition completely lacks the required state variables for method fee management. All other system contracts implementing ACS1 include a `MappedState<string, MethodFees> TransactionFees` state variable for storing fees, as shown in the proper implementation: [3](#0-2) 

The NFT contract state only contains NFT-specific variables and lacks both `TransactionFees` and `MethodFeeController` state mappings: [4](#0-3) 

In contrast, a proper ACS1 implementation validates input, checks authorization against the controller, and persists fees to state: [5](#0-4) 

The NFT contract's `GetMethodFee()` also ignores any potential SetMethodFee calls and returns hardcoded values (100 ELF for "Create", empty for others): [6](#0-5) 

**Execution Path:**
1. Attacker (or misguided user) creates a Parliament proposal to call `NFTContract.SetMethodFee()`
2. Proposal goes through normal voting process, consuming governance resources
3. After approval threshold is met, proposer calls `Release()` 
4. Parliament executes the proposal via `SendVirtualInlineBySystemContract`: [7](#0-6) 

5. NFT contract's `SetMethodFee()` executes and returns `Empty` (success)
6. Proposal is marked as released and removed from state
7. **However, no fees were actually changed** - the contract still uses hardcoded values
8. Subsequent calls to `GetMethodFee()` return the same hardcoded fees as before

### Impact Explanation

**Operational Impact - Governance Resource Waste:**

This vulnerability enables wastage of governance resources through proposals that execute successfully but accomplish nothing:

1. **Voting Power Waste**: Parliament members (miners/validators) spend voting power approving proposals that have zero effect on the protocol
2. **Time Waste**: The proposal lifecycle (creation, voting period, threshold checking, release) consumes time during which this governance slot could be used for legitimate proposals
3. **Gas Fee Waste**: Transaction fees are paid for proposal creation, voting, and release operations that produce no state changes
4. **Opportunity Cost**: Limited governance bandwidth is consumed on ineffective proposals instead of meaningful protocol improvements
5. **False Sense of Governance**: The successful execution (return Empty) misleads participants into believing fees were changed when they were not

**Who is Affected:**
- Parliament members who vote on these proposals
- Proposal proposers who waste their proposer privileges
- The protocol governance system as a whole, as its efficiency is degraded
- Users who may be confused about actual fee configuration vs proposed configuration

**Severity Justification (Medium):**
While this doesn't directly steal funds or break consensus, it creates a governance DoS vector where bad actors or misinformed users can waste limited governance resources. Given that governance is a critical protocol function and Parliament has finite capacity (limited by approval thresholds and voting periods), repeated exploitation could significantly degrade governance efficiency. The impact is operational rather than financial, but governance degradation can indirectly affect protocol security and upgrade capability.

### Likelihood Explanation

**Reachable Entry Point:** ✓ 
The `SetMethodFee()` method is public and callable through Parliament proposals.

**Feasible Preconditions:** ✓
- Attacker needs ability to create Parliament proposals (typically open to any account)
- No special privileges required beyond normal proposal creation
- Proposal must achieve approval threshold (typically 2/3 of Parliament members), but this is feasible for seemingly legitimate fee adjustment proposals

**Execution Practicality:** ✓
- The attack is trivially executable: create proposal → vote → release
- Parliament's release mechanism blindly executes successful calls regardless of actual state changes
- No validation exists to detect that the method is a no-op before or after execution

**Economic Rationality:** ✓
- Attack cost is minimal (just proposal creation and release gas fees)
- No tokens at risk for the attacker
- Could be executed accidentally by legitimate users who don't realize the implementation is a stub
- Repeated attacks are economically viable

**Detection/Operational Constraints:**
- Difficult to detect proactively since the transaction succeeds
- No events or logs indicate the no-op nature
- Requires manual verification that fees didn't actually change
- Could be mistaken for intentional behavior

**Probability Assessment:**
HIGH - This is likely to occur either through:
1. Malicious actors deliberately wasting governance resources
2. Legitimate users who don't understand the stub implementation and create proposals expecting them to work
3. Automated governance tools that don't verify method implementations before proposing

The fact that no tests exist for NFT contract's ACS1 implementation suggests this may be undocumented intended behavior, but it still creates the vulnerability regardless of intent.

### Recommendation

**Immediate Fix - Option 1 (Full Implementation):**
Add proper state variables to `NFTContractState.cs`:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

Implement `SetMethodFee()` following the standard ACS1 pattern with:
- Input validation using `AssertValidFeeToken`
- Authorization check against `MethodFeeController`
- State persistence: `State.TransactionFees[input.MethodName] = input`

Update `GetMethodFee()` to read from state:
```csharp
var fees = State.TransactionFees[input.Value];
if (fees != null) return fees;
// Fall back to hardcoded values for backwards compatibility
```

**Alternative Fix - Option 2 (Explicit Rejection):**
If method fees should remain hardcoded, make `SetMethodFee()` explicitly reject calls:
```csharp
public override Empty SetMethodFee(MethodFees input)
{
    Assert(false, "NFT contract uses fixed method fees and cannot be changed.");
    return new Empty();
}
```

This prevents proposals from executing successfully and wasting resources.

**Invariant Checks to Add:**
- Test that `SetMethodFee()` either persists changes to state OR explicitly fails
- Verify that `GetMethodFee()` returns the fees that were set (if implementation allows changes)
- Add integration test for Parliament proposal → SetMethodFee → verify actual fee change

**Test Cases to Prevent Regression:**
1. Test creating and releasing a Parliament proposal to change NFT contract fees
2. Verify that after successful Release, calling GetMethodFee returns the new fees
3. Test that a second SetMethodFee call with different values updates the stored fees
4. Add negative test showing rejection if SetMethodFee should not be allowed

### Proof of Concept

**Initial State:**
- NFT contract deployed with hardcoded Create method fee of 100 ELF
- Parliament contract initialized with default organization

**Attack Sequence:**

1. **Query current fees:**
   - Call: `NFTContract.GetMethodFee("Create")`
   - Result: Returns 100 ELF (hardcoded)

2. **Create proposal to change fees:**
   - Proposer creates Parliament proposal with:
     - `ToAddress`: NFT Contract Address
     - `MethodName`: "SetMethodFee"
     - `Params`: `MethodFees { MethodName = "Create", Fees = [{ Symbol = "ELF", BasicFee = 200_00000000 }] }`

3. **Approve proposal:**
   - 2/3 of Parliament members vote to approve
   - `IsReleaseThresholdReached` returns true

4. **Release proposal:**
   - Proposer calls `Parliament.Release(proposalId)`
   - Parliament executes: `SendVirtualInlineBySystemContract(..., NFTContract, "SetMethodFee", ...)`
   - NFT contract's `SetMethodFee` executes and returns `Empty`
   - Transaction succeeds, proposal is removed from state

5. **Verify fees unchanged:**
   - Call: `NFTContract.GetMethodFee("Create")`
   - **Expected (if properly implemented):** Returns 200 ELF
   - **Actual Result:** Still returns 100 ELF (hardcoded value)

**Success Condition (Attack Succeeds):**
The proposal releases successfully (transaction succeeds), but querying the method fee shows no change from the hardcoded value, proving the governance action wasted resources without achieving its stated purpose.

**Evidence of Waste:**
- Proposal creation transaction fee: consumed
- Multiple approval votes: consumed  
- Release transaction fee: consumed
- Voting period time: consumed
- Governance bandwidth: consumed
- **Actual state change: NONE**

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L8-11)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L13-16)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L20-37)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(Create))
            return new MethodFees
            {
                MethodName = input.Value,
                Fees =
                {
                    new MethodFee
                    {
                        Symbol = Context.Variables.NativeSymbol,
                        BasicFee = 100_00000000
                    }
                }
            };

        return new MethodFees();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState_ChargeFee.cs (L10-10)
```csharp
    internal MappedState<string, MethodFees> TransactionFees { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L6-46)
```csharp
public partial class NFTContractState : ContractState
{
    public Int64State NftProtocolNumberFlag { get; set; }
    public Int32State CurrentSymbolNumberLength { get; set; }
    public MappedState<long, bool> IsCreatedMap { get; set; }

    /// <summary>
    ///     Symbol -> Addresses have permission to mint this token
    /// </summary>
    public MappedState<string, MinterList> MinterListMap { get; set; }

    public MappedState<Hash, NFTInfo> NftInfoMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Balance
    /// </summary>
    public MappedState<Hash, Address, long> BalanceMap { get; set; }

    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }

    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }

    public MappedState<string, string> NFTTypeShortNameMap { get; set; }
    public MappedState<string, string> NFTTypeFullNameMap { get; set; }

    public SingletonState<Address> ParliamentDefaultAddress { get; set; }

    public SingletonState<NFTTypes> NFTTypes { get; set; }

    /// <summary>
    ///     Symbol (Protocol) -> Owner Address -> Operator Address List
    /// </summary>
    public MappedState<string, Address, AddressList> OperatorMap { get; set; }
}
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L13-22)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");

        State.TransactionFees[input.MethodName] = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L138-140)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
```
