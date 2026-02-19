# Audit Report

## Title
Unbounded Iteration Over AutoDistributeThreshold Causes DoS in RegisterForProfits

## Summary
An attacker can create a TokenHolder scheme with AutoDistributeThreshold containing thousands of token symbol entries. When users attempt to register for profits on this scheme, the RegisterForProfits function performs an unbounded iteration over all entries, making multiple method calls per entry, causing the transaction to exceed AElf's ExecutionCallThreshold of 15,000 and fail permanently.

## Finding Description

The vulnerability exists in the TokenHolder contract's RegisterForProfits function, which fails to validate or limit the size of the AutoDistributeThreshold map during scheme creation and performs unbounded iteration during profit registration.

**CreateScheme accepts unbounded map:** The CreateScheme function accepts AutoDistributeThreshold without validating the number of entries. [1](#0-0) 

**Protobuf defines unbounded map:** The AutoDistributeThreshold is defined as an unbounded map in the protobuf specification. [2](#0-1) 

**RegisterForProfits has unbounded iteration:** During profit registration, a foreach loop iterates over all AutoDistributeThreshold entries without any size check or pagination. [3](#0-2) 

**Each iteration makes cross-contract call:** Within the loop, each iteration performs a cross-contract call to TokenContract.GetBalance. [4](#0-3) 

**Cross-contract call involves multiple method calls:** The GetBalance call internally invokes additional methods including GetActualTokenSymbol and AssertValidInputAddress. [5](#0-4) [6](#0-5) 

**State size limit allows sufficient entries:** While AElf enforces a 128KB state size limit, this allows approximately 5,000-5,500 map entries (each entry ~23 bytes), which is more than enough to exceed the ExecutionCallThreshold. [7](#0-6) 

**ExecutionCallThreshold is exceeded:** Each iteration makes approximately 5 method calls (cross-contract call + internal methods). With 3,500 entries, this results in ~17,500 calls, exceeding the ExecutionCallThreshold of 15,000. [8](#0-7) 

## Impact Explanation

This is a **Medium severity** DoS vulnerability with the following impacts:

1. **Permanent operational DoS**: Any scheme created with thousands of AutoDistributeThreshold entries becomes permanently unusable. The RegisterForProfits function will always fail with RuntimeCallThresholdExceededException.

2. **Affected functionality**: 
   - Users cannot register for profits on the poisoned scheme
   - The auto-distribute mechanism becomes non-functional
   - The scheme manager cannot use the auto-distribute feature
   
3. **No direct fund loss**: While this doesn't directly steal funds, it permanently breaks a core protocol feature for affected schemes.

4. **Recovery cost**: Recovery requires creating an entirely new scheme, losing existing configuration and potentially requiring governance actions to migrate users.

The severity is Medium rather than High because it affects availability of a specific scheme rather than causing direct fund loss or affecting the entire protocol.

## Likelihood Explanation

The likelihood of this vulnerability being exploited is **High**:

1. **No special privileges required**: Any address can call CreateScheme - it's a public function with no authorization checks.

2. **Low attack cost**: Single transaction with standard gas fees. The attacker only needs to craft a CreateScheme call with a large AutoDistributeThreshold map.

3. **Guaranteed success**: The attack is deterministic. With 3,500+ entries:
   - State size: 3,500 × 23 bytes ≈ 80KB (well within 128KB limit)
   - Method calls: 3,500 × 5 ≈ 17,500 (exceeds 15,000 threshold)

4. **No detection mechanisms**: There are no checks or monitoring for AutoDistributeThreshold size during CreateScheme.

5. **Permanent effect**: Once created, the malicious scheme persists in state and remains permanently unusable.

## Recommendation

Implement size validation on AutoDistributeThreshold during scheme creation:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation for AutoDistributeThreshold size
    const int MaxAutoDistributeThresholdEntries = 10; // Conservative limit
    Assert(input.AutoDistributeThreshold == null || 
           input.AutoDistributeThreshold.Count <= MaxAutoDistributeThresholdEntries,
           $"AutoDistributeThreshold cannot exceed {MaxAutoDistributeThresholdEntries} entries.");
    
    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    // ... rest of the function
}
```

Alternative or additional mitigations:
1. Add pagination to the AutoDistributeThreshold check in RegisterForProfits
2. Implement a governance-controlled maximum threshold size
3. Add early exit conditions in the iteration loop

## Proof of Concept

```csharp
[Fact]
public async Task RegisterForProfits_DoS_With_Large_AutoDistributeThreshold()
{
    // Setup: Initialize contracts and accounts
    var tokenHolder = GetTokenHolderContract(BootMinerKeyPair);
    var attacker = SampleAccount.Accounts[0].KeyPair;
    
    // Attack: Create scheme with 4000 entries (exceeds ExecutionCallThreshold)
    var maliciousAutoDistributeThreshold = new Dictionary<string, long>();
    for (int i = 0; i < 4000; i++)
    {
        maliciousAutoDistributeThreshold[$"TOKEN{i}"] = 1000;
    }
    
    // Create malicious scheme
    await tokenHolder.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100,
        AutoDistributeThreshold = { maliciousAutoDistributeThreshold }
    });
    
    // Victim attempts to register for profits
    var result = await tokenHolder.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            SchemeManager = attacker.Address,
            Amount = 1000
        });
    
    // Assert: Transaction fails with RuntimeCallThresholdExceededException
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("RuntimeCallThresholdExceededException");
}
```

## Notes

The vulnerability is confirmed by examining the complete call chain:
1. Each foreach iteration triggers a cross-contract GetBalance call
2. GetBalance internally calls GetActualTokenSymbol, private GetBalance, AssertValidInputAddress, and another GetActualTokenSymbol
3. Each of these is a method call that increments the ExecutionObserver call counter
4. With 4,000 entries × ~5 calls per entry = ~20,000 total calls, exceeding the 15,000 ExecutionCallThreshold
5. The state size limit of 128KB allows approximately 5,500 entries, providing ample room for the attack

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L179-206)
```csharp
        if (scheme.AutoDistributeThreshold != null && scheme.AutoDistributeThreshold.Any())
        {
            var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
            var virtualAddress = originScheme.VirtualAddress;
            Profit.DistributeProfitsInput distributedInput = null;
            foreach (var threshold in scheme.AutoDistributeThreshold)
            {
                var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = virtualAddress,
                    Symbol = threshold.Key
                }).Balance;
                if (balance < threshold.Value) continue;
                if (distributedInput == null)
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
                distributedInput.AmountsMap[threshold.Key] = 0;
                break;
            }

            if (distributedInput == null) return new Empty();
            State.ProfitContract.DistributeProfits.Send(distributedInput);
            scheme.Period = scheme.Period.Add(1);
            State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        }
```

**File:** protobuf/token_holder_contract.proto (L69-69)
```text
    map<string, int64> auto_distribute_threshold = 3;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L39-47)
```csharp
    public override GetBalanceOutput GetBalance(GetBalanceInput input)
    {
        var symbol = GetActualTokenSymbol(input.Symbol);
        return new GetBalanceOutput
        {
            Symbol = input.Symbol,
            Owner = input.Owner,
            Balance = GetBalance(input.Owner, symbol)
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L166-172)
```csharp
    private long GetBalance(Address address, string symbol)
    {
        AssertValidInputAddress(address);
        var actualSymbol = GetActualTokenSymbol(symbol);
        Assert(!string.IsNullOrWhiteSpace(actualSymbol), "Invalid symbol.");
        return State.Balances[address][actualSymbol];
    }
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```
