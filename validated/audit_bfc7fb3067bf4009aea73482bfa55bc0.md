# Audit Report

## Title
Unbounded State Storage Growth via Unauthorized Delegation Entry Creation

## Summary
The MultiToken contract's delegation methods allow any user to create delegation entries for arbitrary addresses without authorization checks. Combined with the absence of ACS8 implementation (no per-write WRITE token charges), this enables economically viable state bloat attacks where attackers pay only transaction size fees to create unlimited permanent state entries across arbitrary delegator addresses.

## Finding Description

The MultiToken contract provides two public methods for managing transaction fee delegations that contain a critical authorization flaw. The `SetTransactionFeeDelegations` method accepts any `delegator_address` as input and only validates that the address is not null, without verifying that the transaction sender has authorization from that delegator. [1](#0-0)  The validation function `AssertValidInputAddress` merely checks address format. [2](#0-1) 

Similarly, `SetTransactionFeeDelegateInfos` accepts arbitrary delegator addresses without authorization verification. [3](#0-2) 

These methods create permanent state entries in two mappings: `TransactionFeeDelegateesMap` indexed by delegator address, and `TransactionFeeDelegateInfoMap` indexed by delegator → contract → method. [4](#0-3) 

While each combination is limited to 24 delegatees via `DELEGATEE_MAX_COUNT`, [5](#0-4)  there are no global limits on the number of delegator addresses or (contract, method) combinations that can be created. An attacker can generate N arbitrary delegator addresses and create state entries for each, multiplied by M contracts and K methods for method-specific delegations.

The economic feasibility stems from the MultiToken contract implementing only ACS1 and ACS2, not ACS8. [6](#0-5)  The `ResourceConsumptionPostExecutionPlugin` checks for ACS8 implementation and returns an empty transaction list when ACS8 is not present, meaning no WRITE resource token charges are applied. [7](#0-6) 

Attackers pay only transaction size fees based on input size, not per-state-write charges, while each state entry persists permanently and can approach the 128KB state size limit. [8](#0-7) 

## Impact Explanation

This vulnerability enables HIGH severity impact through:

**Permanent State Bloat**: Unlimited delegation entries persist permanently in blockchain state. For method-specific delegations, the attack surface is delegator_count × contract_count × method_count combinations, each storing up to 24 delegatees with associated delegation data.

**Infrastructure Burden**: All validators must store and maintain the bloated state. New nodes face extended synchronization times as state grows. Storage requirements increase indefinitely without cleanup mechanisms.

**Performance Degradation**: As state size grows, blockchain performance degrades network-wide. State access operations become slower, affecting all network participants equally.

**Economic Asymmetry**: The fee model creates exploitable imbalance. Attackers pay only transaction size fees (proportional to input bytes), while the impact (permanent storage across all validators) far exceeds the cost. The absence of per-write WRITE token charges means state write costs are not properly internalized.

## Likelihood Explanation

This vulnerability has HIGH likelihood of exploitation:

**Attack Complexity: LOW** - The attack requires only repeated calls to public methods with generated addresses. No special permissions, complex transaction ordering, or insider access is needed.

**Attacker Requirements: MINIMAL** - Address generation is trivial. Transaction fees per call are minimal compared to permanent state impact. No compromised keys or special privileges required.

**Feasibility: HIGH** - Entry points are unrestricted public methods. The attack is easily reproducible and leaves traceable evidence, but distinguishing malicious from legitimate delegations is difficult without additional context.

**Economic Viability: STRONG** - Transaction size fees are substantially lower than the perpetual storage cost imposed on all validators. The cost-benefit analysis favors attackers seeking to harm network infrastructure.

## Recommendation

Implement proper authorization checks in delegation methods:

```csharp
public override SetTransactionFeeDelegationsOutput SetTransactionFeeDelegations(
    SetTransactionFeeDelegationsInput input)
{
    AssertValidInputAddress(input.DelegatorAddress);
    
    // Add authorization check
    Assert(Context.Sender == input.DelegatorAddress, 
        "Only the delegator can set their own delegations.");
    
    Assert(input.Delegations != null, "Delegations cannot be null!");
    // ... rest of implementation
}
```

Additionally, consider:
1. Implementing ACS8 to charge per-write WRITE tokens for state modifications
2. Adding global limits on total delegation entries per address
3. Implementing time-based expiration for unused delegation entries
4. Adding delegation cleanup mechanisms for inactive entries

## Proof of Concept

```csharp
[Fact]
public async Task StateBloa_UnauthorizedDelegationCreation_Test()
{
    // Attacker generates arbitrary victim addresses
    var victimAddress1 = Address.FromPublicKey(GenerateKeyPair().PublicKey);
    var victimAddress2 = Address.FromPublicKey(GenerateKeyPair().PublicKey);
    
    // Attacker calls delegation method with victim addresses
    var result1 = await TokenContractStub.SetTransactionFeeDelegations.SendAsync(
        new SetTransactionFeeDelegationsInput
        {
            DelegatorAddress = victimAddress1,
            Delegations = { { "ELF", 1000 } }
        });
    
    var result2 = await TokenContractStub.SetTransactionFeeDelegations.SendAsync(
        new SetTransactionFeeDelegationsInput
        {
            DelegatorAddress = victimAddress2,
            Delegations = { { "ELF", 1000 } }
        });
    
    // Verify unauthorized delegation entries were created
    var delegatees1 = await TokenContractStub.GetTransactionFeeDelegatees.CallAsync(
        new GetTransactionFeeDelegateesInput { DelegatorAddress = victimAddress1 });
    var delegatees2 = await TokenContractStub.GetTransactionFeeDelegatees.CallAsync(
        new GetTransactionFeeDelegateesInput { DelegatorAddress = victimAddress2 });
    
    // State entries created for addresses attacker doesn't control
    delegatees1.DelegateeAddresses.Count.ShouldBeGreaterThan(0);
    delegatees2.DelegateeAddresses.Count.ShouldBeGreaterThan(0);
}
```

This test demonstrates that any user can create delegation entries for addresses they don't control, enabling unbounded state bloat without authorization checks.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L12-16)
```csharp
    public override SetTransactionFeeDelegationsOutput SetTransactionFeeDelegations(
        SetTransactionFeeDelegationsInput input)
    {
        AssertValidInputAddress(input.DelegatorAddress);
        Assert(input.Delegations != null, "Delegations cannot be null!");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L198-201)
```csharp
    public override Empty SetTransactionFeeDelegateInfos(SetTransactionFeeDelegateInfosInput input)
    {
        Assert(input.DelegatorAddress != null && input.DelegateInfoList.Count > 0,
            "Delegator address and delegate info cannot be null.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L64-69)
```csharp
    public MappedState<Address, TransactionFeeDelegatees> TransactionFeeDelegateesMap { get; set; }
    
    /// <summary>
    /// delegator address -> contract address -> method name -> delegatee info
    /// </summary>
    public MappedState<Address, Address, string, TransactionFeeDelegatees> TransactionFeeDelegateInfoMap { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L18-18)
```csharp
    public const int DELEGATEE_MAX_COUNT = 24;
```

**File:** protobuf/token_contract_impl.proto (L24-26)
```text
    option (aelf.base) = "acs1.proto";
    option (aelf.base) = "acs2.proto";
    option (aelf.base) = "token_contract.proto";
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/ResourceConsumptionPostExecutionPlugin.cs (L39-43)
```csharp
    public async Task<IEnumerable<Transaction>> GetPostTransactionsAsync(
        IReadOnlyList<ServiceDescriptor> descriptors, ITransactionContext transactionContext)
    {
        if (!HasApplicableAcs(descriptors)) return new List<Transaction>();

```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```
