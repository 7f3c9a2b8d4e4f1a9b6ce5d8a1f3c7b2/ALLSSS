### Title
NFT Contract Governance Fee Changes Silently Ignored Due to Missing State Management

### Summary
The NFT contract's `SetMethodFee()` and `ChangeMethodFeeController()` methods are non-functional stubs that discard all inputs without storing them to state. This creates a critical governance disconnect where fee adjustment proposals pass and execute successfully, but have zero effect on actual fee enforcement. Users continue paying hard-coded fees (100 ELF for the Create method) regardless of governance decisions, making fee governance entirely ineffective.

### Finding Description

The NFT contract implements the ACS1 transaction fee standard but critically fails to store fee configurations or controller authority. 

**Missing State Variables:**
The `NFTContractState` class lacks the required state mappings that all other ACS1-compliant system contracts define [1](#0-0) . Proper implementations define `MappedState<string, MethodFees> TransactionFees` and `SingletonState<AuthorityInfo> MethodFeeController` [2](#0-1) .

**Non-Functional SetMethodFee:**
The `SetMethodFee()` method receives fee input but immediately returns empty without any state mutation [3](#0-2) . Compare this to proper implementations that validate tokens, check authorization, and persist fees via `State.TransactionFees[input.MethodName] = input` [4](#0-3) .

**Hard-Coded Fee Enforcement:**
The `GetMethodFee()` method returns hard-coded fees (100 ELF for Create method) instead of retrieving stored values [5](#0-4) . During transaction execution, the fee charging system calls this method to determine what to charge users [6](#0-5) .

**Fee Enforcement Path:**
Pre-execution plugins generate a `ChargeTransactionFees` call before each transaction [7](#0-6) . This mechanism queries the target contract's `GetMethodFee()` to determine charges, making the hard-coded return values the actual enforced fees regardless of governance settings.

**Non-Functional Controller Management:**
Similarly, `ChangeMethodFeeController()` discards controller updates [8](#0-7) , and `GetMethodFeeController()` returns an empty authority structure [9](#0-8) .

**Deviation from Documented Standard:**
The AElf documentation explicitly recommends using `MappedState` for transaction fees and storing values in `SetMethodFee` implementations [10](#0-9) .

### Impact Explanation

**Governance Dysfunction:**
When governance creates proposals to adjust NFT contract fees (e.g., reducing Create fee from 100 ELF to 1 ELF due to token appreciation), the proposals execute successfully but produce no effect. Governance participants have no indication their decisions are being ignored, creating institutional distrust and operational confusion.

**Economic Harm to Users:**
Users are locked into paying fixed fees that cannot adapt to market conditions:
- If ELF appreciates 100x, the 100 ELF Create fee becomes economically prohibitive ($10,000+ at realistic token prices)
- If ELF depreciates, fees remain unchanged despite potentially needing increases
- No mechanism exists to adjust fees except full contract upgrade

**Protocol Availability Risk:**
As market conditions change, fixed fees can render critical functionality unusable. The Create method, which establishes new NFT protocols on the mainchain, becomes inaccessible when fees are disproportionate to economic value, effectively DoS'ing the NFT protocol creation functionality [11](#0-10) .

**Silent Failure Mode:**
The contract presents a misleading interface suggesting fee governance is supported. External systems, governance participants, and users have no indication that fee changes are impossible without examining contract implementation, violating the principle of interface transparency.

### Likelihood Explanation

**High Likelihood - Normal Governance Operations:**
Fee adjustments are routine governance activities. All other AElf system contracts support dynamic fee management via governance proposals. The NFT contract appearing to support this interface makes governance attempts inevitable as market conditions evolve.

**Zero Attack Complexity:**
No attack is required - this is a design flaw affecting normal operations. Any governance actor following standard procedures to adjust fees will encounter this issue. The execution path is straightforward: create proposal → approve → release → call SetMethodFee → observe no effect.

**Feasible Preconditions:**
Only requires normal governance capabilities (creating and passing proposals) available to legitimate governance participants. No special privileges or exotic conditions needed.

**Economic Inevitability:**
Token price volatility makes fee adjustments economically necessary over the contract's lifetime. Market forces guarantee this issue will manifest as either fees become too expensive (limiting usage) or potentially too cheap (if that were governable, which it isn't).

**No Detection Mechanism:**
The transaction succeeds with no error, no event indicating failure, and no state change that can be queried. Governance participants receive false positive confirmation that their proposal executed successfully.

### Recommendation

**1. Add Required State Variables:**
Define fee storage in `NFTContractState.cs`:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**2. Implement SetMethodFee with Authorization:**
Replace the stub implementation with proper validation and storage logic [12](#0-11) :
- Validate token symbols against available tokens
- Check sender authority against MethodFeeController
- Store fees: `State.TransactionFees[input.MethodName] = input;`
- Initialize default controller if unset (Parliament default organization)

**3. Update GetMethodFee to Read from State:**
Retrieve stored fees instead of returning hard-coded values:
```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    return State.TransactionFees[input.Value] ?? new MethodFees();
}
```

**4. Implement ChangeMethodFeeController:**
Add authority validation and state persistence [13](#0-12) .

**5. Add Test Coverage:**
Create test cases validating:
- SetMethodFee via governance proposal successfully changes fees
- GetMethodFee returns updated values
- Unauthorized SetMethodFee calls are rejected
- ChangeMethodFeeController updates authority correctly
- Fee enforcement matches configured values

**6. Migration Path:**
Consider initializing TransactionFees with current hard-coded values (100 ELF for Create) during contract upgrade to maintain fee continuity.

### Proof of Concept

**Initial State:**
- NFT contract deployed with current implementation
- Create method charges 100 ELF (hard-coded)

**Exploitation Steps:**

1. **Governance Proposal Creation:**
   Parliament/governance creates proposal to reduce Create fee to 1 ELF via `SetMethodFee`
   
2. **Proposal Approval and Execution:**
   Proposal passes governance vote and is released, executing `SetMethodFee(new MethodFees { MethodName = "Create", Fees = { new MethodFee { Symbol = "ELF", BasicFee = 1_00000000 } } })`
   
3. **Transaction Returns Success:**
   SetMethodFee returns Empty (success), governance participants believe fee was updated

4. **User Attempts Create:**
   User calls NFT Create method expecting to pay 1 ELF

5. **Actual vs Expected Result:**
   - **Expected:** User charged 1 ELF as per governance decision
   - **Actual:** User charged 100 ELF (hard-coded value unchanged)
   - Fee charging system calls GetMethodFee, receives hard-coded 100 ELF [14](#0-13) 
   - Pre-execution plugin enforces the 100 ELF charge [15](#0-14) 

6. **Verify Governance Failure:**
   Query `GetMethodFee("Create")` - still returns 100 ELF
   No state was modified by the governance proposal

**Success Condition for Exploit:**
Governance proposal executes successfully (no revert) but produces zero effect on fee enforcement, proving silent failure of governance fee management.

### Citations

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

**File:** contract/AElf.Contracts.Association/AssociationState.cs (L11-12)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L39-42)
```csharp
    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        return new AuthorityInfo();
    }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L10-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L21-30)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-39)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L91-96)
```csharp
            var chargeTransactionFeesInput = new ChargeTransactionFeesInput
            {
                MethodName = transactionContext.Transaction.MethodName,
                ContractAddress = transactionContext.Transaction.To,
                TransactionSizeFee = txCost
            };
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L123-129)
```csharp
    public bool IsStopExecuting(ByteString txReturnValue, out string preExecutionInformation)
    {
        var chargeTransactionFeesOutput = new ChargeTransactionFeesOutput();
        chargeTransactionFeesOutput.MergeFrom(txReturnValue);
        preExecutionInformation = chargeTransactionFeesOutput.ChargingInformation;
        return !chargeTransactionFeesOutput.Success;
    }
```

**File:** docs-sphinx/reference/acs/acs1.rst (L279-296)
```text
A more recommended implementation needs to define an ``MappedState`` in
the State file for the contract:

.. code:: c#

   public MappedState<string, MethodFees> TransactionFees { get; set; }

Modify the ``TransactionFees`` data structure in the ``SetMethodFee``
method, and return the value in the ``GetMethodFee`` method.

In this solution, the implementation of GetMethodFee is very easy:

.. code:: c#

   public override MethodFees GetMethodFee(StringValue input)
       return State.TransactionFees[input.Value];
   }

```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-73)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
        var tokenExternalInfo = GetTokenExternalInfo(input);
        var creator = input.Creator ?? Context.Sender;
        var tokenCreateInput = new MultiToken.CreateInput
        {
            Symbol = symbol,
            Decimals = 0, // Fixed
            Issuer = creator,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId,
            TokenName = input.ProtocolName,
            TotalSupply = input.TotalSupply,
            ExternalInfo = tokenExternalInfo
        };
        State.TokenContract.Create.Send(tokenCreateInput);

        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;

        var protocolInfo = new NFTProtocolInfo
        {
            Symbol = symbol,
            BaseUri = input.BaseUri,
            TotalSupply = tokenCreateInput.TotalSupply,
            Creator = tokenCreateInput.Issuer,
            Metadata = new Metadata { Value = { tokenExternalInfo.Value } },
            ProtocolName = tokenCreateInput.TokenName,
            IsTokenIdReuse = input.IsTokenIdReuse,
            IssueChainId = tokenCreateInput.IssueChainId,
            IsBurnable = tokenCreateInput.IsBurnable,
            NftType = input.NftType
        };
        State.NftProtocolMap[symbol] = protocolInfo;

        Context.Fire(new NFTProtocolCreated
        {
            Symbol = tokenCreateInput.Symbol,
            Creator = tokenCreateInput.Issuer,
            IsBurnable = tokenCreateInput.IsBurnable,
            IssueChainId = tokenCreateInput.IssueChainId,
            ProtocolName = tokenCreateInput.TokenName,
            TotalSupply = tokenCreateInput.TotalSupply,
            Metadata = protocolInfo.Metadata,
            BaseUri = protocolInfo.BaseUri,
            IsTokenIdReuse = protocolInfo.IsTokenIdReuse,
            NftType = protocolInfo.NftType
        });

        return new StringValue
        {
            Value = symbol
        };
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
