# Audit Report

## Title
Indefinite Symbol Reservation via Unbounded SEED NFT Expiration Time

## Summary
The `CreateNFTInfo()` and `ExtendSeedExpirationTime()` functions lack upper bound validation on expiration times, allowing SEED NFT owners to reserve token symbols indefinitely (e.g., until year 9999). This enables permanent namespace squatting attacks that prevent legitimate users from creating tokens with reserved symbols, causing a denial-of-service on the token creation system.

## Finding Description

**Root Cause - No Upper Bound Validation:**

In `CreateNFTInfo()`, expiration time validation only enforces a lower bound with no maximum limit: [1](#0-0) 

The validation merely checks `Context.CurrentBlockTime.Seconds <= expirationTimeLong`, permitting astronomically large timestamp values representing year 9999 or beyond.

Similarly, `ExtendSeedExpirationTime()` allows SEED NFT owners to update expiration times without any upper bound validation: [2](#0-1) 

The function only validates sender ownership but imposes no limits on the new expiration value when updating the token's external info.

**Symbol Reservation Mechanism:**

When a SEED NFT is created, it reserves a symbol in the state mapping: [3](#0-2) 

The `CheckSymbolSeed()` function prevents creating new SEED NFTs for symbols that are already reserved by unexpired SEEDs: [4](#0-3) 

The assertion fails if an existing SEED reserves the symbol and hasn't expired (`Context.CurrentBlockTime.Seconds > symbolSeedExpireTime` must be true).

**Attack Execution Path:**

1. Attacker obtains a SEED NFT (as SEED-0 collection owner or through transfer)
2. Attacker calls `ExtendSeedExpirationTime()` with `ExpirationTime = 253402300799` (December 31, 9999)
3. The symbol remains reserved in `State.SymbolSeedMap` until year 9999
4. Token creation attempts fail for ALL users:
   - **Non-whitelisted users** must provide a valid SEED NFT via `CheckSeedNFT()` during token creation: [5](#0-4) 
   - **Whitelisted addresses** must also pass `CheckSymbolSeed()` validation: [6](#0-5) 

**No Remediation Mechanism:**

No governance function or admin control exists to forcibly clear `SymbolSeedMap` entries or override expired SEED NFT reservations. The only way for a symbol to become available is natural expiration when `Context.CurrentBlockTime.Seconds > symbolSeedExpireTime`, which could be thousands of years in the future.

## Impact Explanation

**Concrete Harm:**
- **Symbol Namespace DoS**: Attackers can permanently block desirable token symbols (e.g., "BTC", "ETH", "USD") from being created by legitimate projects
- **Griefing Attack**: Malicious actors can squat on hundreds or thousands of valuable symbol names at minimal cost
- **Economic Damage**: Projects unable to use their intended symbols face branding issues, user confusion, and potential business losses
- **Ecosystem Degradation**: The token namespace utility degrades over time as more symbols get permanently locked

**Affected Parties:**
- All future token creators (both whitelisted and non-whitelisted)
- The broader AElf ecosystem's token namespace availability
- Projects requiring specific symbol names for branding/interoperability

**Severity Justification:**
Medium severity is appropriate because:
- Impact is operational (namespace DoS) rather than direct fund theft
- Attack requires obtaining SEED NFTs, though this is achievable through ownership or secondary market
- Once obtained, execution is trivial (single transaction) and effects are permanent
- No governance mechanism exists to override or remediate the attack
- The vulnerability enables indefinite resource exhaustion of the symbol namespace

## Likelihood Explanation

**Attacker Capabilities:**
- Must own a SEED NFT to call `ExtendSeedExpirationTime()`
- SEED NFTs can be obtained by being the SEED-0 collection owner or receiving them via transfer
- Once in possession, can extend expiration arbitrarily with no restrictions

**Attack Complexity:**
- Very low: Single function call with two parameters (symbol and far-future timestamp)
- No special preconditions beyond SEED NFT ownership
- Attack is immediately effective and irreversible
- Can be repeated for multiple symbols if attacker has multiple SEED NFTs

**Economic Rationality:**
- Attack cost: Single transaction fee for `ExtendSeedExpirationTime()` call (negligible)
- Potential gain: Control over valuable namespace, potential speculation/ransom opportunities
- Risk: None - no penalty mechanism exists for setting far-future expiration times

**Feasibility Conditions:**
- SEED NFTs must be distributed to users (via SEED-0 owner issuance or transfers)
- If SEED-0 owner is governance-controlled and restrictive, attack surface is reduced
- However, SEED NFTs are transferable, and new owners can extend expiration times
- The mechanism is fully functional with no protective limits

**Probability Assessment:**
Medium likelihood - depends on SEED distribution model, but the mechanism is unprotected once SEEDs enter circulation. The attack is economically rational for speculation or griefing purposes.

## Recommendation

Implement an upper bound validation for SEED NFT expiration times:

1. **Define Maximum Expiration Period**: Add a constant for reasonable maximum expiration (e.g., 10 years from current time)
2. **Validate in CreateNFTInfo()**: Add upper bound check when creating SEED NFTs
3. **Validate in ExtendSeedExpirationTime()**: Add upper bound check when extending expiration
4. **Add Governance Override**: Implement a governance-controlled function to forcibly clear expired or abusive SEED reservations from `SymbolSeedMap`

Example fix for `ExtendSeedExpirationTime()`:
```csharp
public override Empty ExtendSeedExpirationTime(ExtendSeedExpirationTimeInput input)
{
    var tokenInfo = GetTokenInfo(input.Symbol);
    Assert(tokenInfo != null, "Seed NFT does not exist.");
    Assert(tokenInfo.Owner == Context.Sender, "Sender is not Seed NFT owner.");
    
    // Add maximum expiration validation
    var maxExpirationTime = Context.CurrentBlockTime.AddYears(10).Seconds;
    Assert(input.ExpirationTime <= maxExpirationTime, "Expiration time exceeds maximum allowed period.");
    
    tokenInfo.ExternalInfo.Value[TokenContractConstants.SeedExpireTimeExternalInfoKey] = 
        input.ExpirationTime.ToString();
    State.TokenInfos[input.Symbol] = tokenInfo;
    // ... rest of function
}
```

## Proof of Concept

```csharp
[Fact]
public async Task IndefiniteSymbolReservation_Attack_Test()
{
    // Step 1: Create a SEED NFT for symbol "ATTACK"
    var seedSymbol = "SEED-1";
    var targetSymbol = "ATTACK";
    var farFutureTimestamp = 253402300799L; // December 31, 9999
    
    var seedInput = new CreateInput
    {
        Symbol = seedSymbol,
        TokenName = "Seed Token",
        TotalSupply = 1,
        Decimals = 0,
        Issuer = DefaultAddress,
        Owner = DefaultAddress,
        IsBurnable = true,
        ExternalInfo = new ExternalInfo()
    };
    seedInput.ExternalInfo.Value["__seed_owned_symbol"] = targetSymbol;
    seedInput.ExternalInfo.Value["__seed_exp_time"] = TimestampHelper.GetUtcNow().AddDays(1).Seconds.ToString();
    
    await TokenContractStub.Create.SendAsync(seedInput);
    
    // Step 2: Extend expiration to year 9999
    var extendInput = new ExtendSeedExpirationTimeInput
    {
        Symbol = seedSymbol,
        ExpirationTime = farFutureTimestamp
    };
    
    var result = await TokenContractStub.ExtendSeedExpirationTime.SendAsync(extendInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Verify symbol is permanently blocked - attempt to create new SEED for same symbol fails
    var newSeedInput = new CreateInput
    {
        Symbol = "SEED-2",
        TokenName = "New Seed Token",
        TotalSupply = 1,
        Decimals = 0,
        Issuer = DefaultAddress,
        Owner = DefaultAddress,
        IsBurnable = true,
        ExternalInfo = new ExternalInfo()
    };
    newSeedInput.ExternalInfo.Value["__seed_owned_symbol"] = targetSymbol;
    newSeedInput.ExternalInfo.Value["__seed_exp_time"] = TimestampHelper.GetUtcNow().AddDays(1).Seconds.ToString();
    
    var failedResult = await TokenContractStub.Create.SendWithExceptionAsync(newSeedInput);
    failedResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    failedResult.TransactionResult.Error.ShouldContain("OwnedSymbol has been created");
    
    // Symbol "ATTACK" is now reserved until year 9999 with no remediation mechanism
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L42-45)
```csharp
            Assert(input.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                       out var expirationTime)
                   && long.TryParse(expirationTime, out var expirationTimeLong) &&
                   Context.CurrentBlockTime.Seconds <= expirationTimeLong, "Invalid ownedSymbol.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L51-51)
```csharp
            State.SymbolSeedMap[ownedSymbol.ToUpper()] = input.Symbol;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L57-67)
```csharp
    private void CheckSymbolSeed(string ownedSymbol)
    {
        var oldSymbolSeed = State.SymbolSeedMap[ownedSymbol.ToUpper()];

        Assert(oldSymbolSeed == null || !GetTokenInfo(oldSymbolSeed).ExternalInfo.Value
                   .TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                       out var oldSymbolSeedExpireTime) ||
               !long.TryParse(oldSymbolSeedExpireTime, out var symbolSeedExpireTime)
               || Context.CurrentBlockTime.Seconds > symbolSeedExpireTime,
            "OwnedSymbol has been created");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-65)
```csharp
            if (!IsAddressInCreateWhiteList(Context.Sender) &&
                input.Symbol != TokenContractConstants.SeedCollectionSymbol)
            {
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L695-722)
```csharp
    public override Empty ExtendSeedExpirationTime(ExtendSeedExpirationTimeInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo == null)
        {
            throw new AssertionException("Seed NFT does not exist.");
        }

        Assert(tokenInfo.Owner == Context.Sender, "Sender is not Seed NFT owner.");
        var oldExpireTimeLong = 0L;
        if (tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                out var oldExpireTime))
        {
            long.TryParse(oldExpireTime, out oldExpireTimeLong);
        }

        tokenInfo.ExternalInfo.Value[TokenContractConstants.SeedExpireTimeExternalInfoKey] =
            input.ExpirationTime.ToString();
        State.TokenInfos[input.Symbol] = tokenInfo;
        Context.Fire(new SeedExpirationTimeUpdated
        {
            ChainId = tokenInfo.IssueChainId,
            Symbol = input.Symbol,
            OldExpirationTime = oldExpireTimeLong,
            NewExpirationTime = input.ExpirationTime
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L282-282)
```csharp
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
```
