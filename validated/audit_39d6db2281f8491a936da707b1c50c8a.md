# Audit Report

## Title
Hardcoded Election Lock Amount Causes DoS or Incorrect Economic Security When Native Token Decimals Differ from 8

## Summary
The Election contract uses a hardcoded lock amount that assumes the native token has exactly 8 decimal places, while the system explicitly allows configurable decimals from 0 to 18. This mismatch causes complete denial-of-service of the election system when decimals are less than 8, or severely reduces economic security when decimals exceed 8.

## Finding Description

The Election contract defines a hardcoded constant representing the lock amount required to announce candidacy [1](#0-0) . This constant value of `100_000_00000000` is designed to represent 100,000 tokens with 8 decimal places.

This constant is used directly when locking tokens during election announcement [2](#0-1)  and when refunding tokens during quit election [3](#0-2) .

However, the native token decimals are fully configurable during economic system initialization [4](#0-3) . The token creation validates only that decimals are between 0 and 18 [5](#0-4) , with no enforcement that the native token must have exactly 8 decimals.

When a transfer amount exceeds the available balance, the transaction fails with an "Insufficient balance" error [6](#0-5) . The transfer validation flow checks allowances and balances through the `DoTransferFrom` and `ModifyBalance` methods [7](#0-6) .

## Impact Explanation

**Critical DoS Scenario (decimals < 8):**
When decimals = 2, the hardcoded amount `100_000_00000000` represents 1,000,000,000,000 tokens (1 trillion). Given the typical total supply of 1 billion tokens [8](#0-7) , this amount exceeds the entire token supply by 1000x. No user can possess this amount, causing all election announcement attempts to fail with "Insufficient balance". This results in a complete denial-of-service of the governance system, as no candidates can register.

**High Security Reduction (decimals > 8):**
When decimals = 10, the same hardcoded amount represents only 10,000 tokens instead of the intended 100,000 tokens - a 90% reduction in the economic barrier to candidacy. This severely undermines the election security model by making it 10 times cheaper to announce candidacy, lowering the cost of potential governance attacks.

**Additional DoS Scenario (decimals = 6):**
With 6 decimals, the amount represents 100,000,000 tokens (100 million) - 1000 times the intended amount. This effectively blocks all election participation unless candidates hold an unrealistically large portion of the total supply.

## Likelihood Explanation

The vulnerability is triggered through the public methods `AnnounceElection` [9](#0-8)  and `AnnounceElectionFor` [10](#0-9) , both callable by any user without special privileges.

The precondition is that the chain must be initialized with native token decimals different from 8. This is explicitly supported by the system - decimals are configurable through the initialization input [11](#0-10)  and test code demonstrates native tokens with 2 decimals are valid configurations [12](#0-11) .

While the default configuration uses 8 decimals, side chains or custom deployments may legitimately choose different decimals for compatibility with existing tokens or specific precision requirements. There is no validation preventing this configuration, making the likelihood medium for any non-standard deployment scenario.

## Recommendation

The Election contract should dynamically calculate the lock amount based on the native token's actual decimal configuration rather than using a hardcoded value. The recommended fix is:

1. Query the native token's decimals from the TokenContract during initialization or when needed
2. Calculate the lock amount as: `100_000 * (10 ^ decimals)`
3. Store this calculated value in state or compute it dynamically

Alternatively, add validation during economic system initialization that requires native token decimals to be exactly 8, though this reduces flexibility for side chains and custom deployments.

## Proof of Concept

```csharp
// Scenario: Chain initialized with decimals = 2
// Total Supply: 100_000_00 (1 million tokens with 2 decimals)
// Expected lock: 100_000_00 (100,000 tokens with 2 decimals)
// Actual lock: 100_000_00000000 (1 trillion tokens - exceeds total supply)

// Test demonstrating the vulnerability:
[Fact]
public async Task AnnounceElection_With_NonStandard_Decimals_Causes_DoS()
{
    // Setup: Initialize native token with 2 decimals instead of 8
    const long totalSupply = 1_000_000_00; // 1 million tokens with 2 decimals
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ELF",
        Decimals = 2,  // Non-standard decimals
        TotalSupply = totalSupply,
        Issuer = DefaultAddress
    });
    
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ELF",
        Amount = totalSupply,
        To = CandidateAddress
    });
    
    // Attempt to announce election
    // This will fail because LockTokenForElection = 100_000_00000000
    // which exceeds the total supply of 1_000_000_00
    var result = await ElectionContractStub.AnnounceElection.SendWithExceptionAsync(
        new Address());
    
    // Assert: Transaction fails due to insufficient balance
    result.TransactionResult.Error.ShouldContain("Insufficient balance");
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-119)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;

        LockCandidateNativeToken();

        AddCandidateAsOption(pubkey);

        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-142)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
        var admin = input.Admin ?? Context.Sender;
        State.CandidateAdmins[pubkey] = admin;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
        LockCandidateNativeToken();
        AddCandidateAsOption(pubkey);
        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L177-195)
```csharp
    private void LockCandidateNativeToken()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Lock the token from sender for deposit of announce election
        var lockId = Context.OriginTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        var sponsorAddress = Context.Sender;
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = sponsorAddress,
            To = lockVirtualAddress,
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Lock for announcing election."
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L239-249)
```csharp
        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L42-68)
```csharp
    private void CreateNativeToken(InitialEconomicSystemInput input)
    {
        var lockWhiteListBackups = new List<Address>
        {
            Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName)
        };
        var lockWhiteList = lockWhiteListBackups.Where(address => address != null).ToList();
        State.TokenContract.Create.Send(new CreateInput
        {
            Symbol = input.NativeTokenSymbol,
            TokenName = "Native Token",
            TotalSupply = input.NativeTokenTotalSupply,
            Decimals = input.NativeTokenDecimals,
            IsBurnable = input.IsNativeTokenBurnable,
            Issuer = Context.Self,
            LockWhiteList = { lockWhiteList },
            Owner = Context.Self
        });

        State.TokenContract.SetPrimaryTokenSymbol.Send(new SetPrimaryTokenSymbolInput
            { Symbol = input.NativeTokenSymbol });
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-283)
```csharp
    private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
    {
        Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
               && input.Symbol.Length > 0
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

        CheckSymbolLength(input.Symbol, symbolType);
        if (symbolType == SymbolType.Nft) return;
        CheckTokenAndCollectionExists(input.Symbol);
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L69-95)
```csharp
    private void DoTransferFrom(Address from, Address to, Address spender, string symbol, long amount, string memo)
    {
        AssertValidInputAddress(from);
        AssertValidInputAddress(to);
        
        // First check allowance.
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }

        DoTransfer(from, to, symbol, amount, memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput()
            { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
    }
```

**File:** src/AElf.OS.Core/EconomicOptions.cs (L8-8)
```csharp
    public long TotalSupply { get; set; } = 1_000_000_000_00000000;
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenEconomicTests.cs (L13-23)
```csharp
            await TokenContractStub.Create.SendAsync(new CreateInput
            {
                Symbol = DefaultSymbol,
                Decimals = 2,
                IsBurnable = true,
                TokenName = "elf token",
                TotalSupply = totalSupply,
                Issuer = DefaultAddress,
                LockWhiteList = { TreasuryContractAddress },
                Owner = DefaultAddress
            });
```
