# Audit Report

## Title
Indefinite Symbol Reservation via Unbounded SEED NFT Expiration Time

## Summary
The `CreateNFTInfo()` and `ExtendSeedExpirationTime()` functions lack upper bound validation on expiration times, allowing SEED NFT owners to reserve token symbols indefinitely (e.g., until year 9999). This enables permanent namespace squatting attacks that prevent legitimate users from creating tokens with reserved symbols, causing a denial-of-service on the token creation system.

## Finding Description

**Root Cause - Missing Upper Bound Validation:**

The `CreateNFTInfo()` function validates SEED NFT expiration times but only enforces a lower bound without any maximum limit. [1](#0-0)  The validation merely checks that the current block time is less than or equal to the expiration time, permitting astronomically large timestamp values.

Similarly, `ExtendSeedExpirationTime()` allows SEED NFT owners to update expiration times without any upper bound validation. [2](#0-1)  The function only validates sender ownership but imposes no limits on the new expiration value when updating the token's external info.

**Symbol Reservation Mechanism:**

When a SEED NFT is created, it reserves a symbol in the state mapping. [3](#0-2) 

The `CheckSymbolSeed()` function prevents creating new SEED NFTs for symbols that are already reserved by unexpired SEEDs. [4](#0-3)  The assertion fails if an existing SEED reserves the symbol and hasn't expired, requiring that `Context.CurrentBlockTime.Seconds > symbolSeedExpireTime` be true.

**Attack Execution Path:**

Token creation is blocked for ALL users when an unexpired SEED exists:

1. **Non-whitelisted users** must provide a valid SEED NFT during token creation. [5](#0-4)  The `CheckSeedNFT` function validates the SEED's expiration time. [6](#0-5) 

2. **Whitelisted addresses** (system contracts only per hardcoded check) must also pass `CheckSymbolSeed()` validation during input validation. [7](#0-6)  The whitelist check itself only includes four system contract addresses. [8](#0-7) 

**No Remediation Mechanism:**

The `SymbolSeedMap` state variable stores symbol reservations, [9](#0-8)  but no governance function or admin control exists to forcibly clear entries or override SEED NFT reservations. The only way for a symbol to become available is natural expiration when `Context.CurrentBlockTime.Seconds > symbolSeedExpireTime`, which could be thousands of years in the future if set to values like year 9999.

## Impact Explanation

**Concrete Harm:**
- **Symbol Namespace DoS**: Attackers can permanently block desirable token symbols (e.g., "BTC", "ETH", "USD") from being created by legitimate projects
- **Griefing Attack**: Malicious actors can squat on hundreds or thousands of valuable symbol names at minimal cost
- **Economic Damage**: Projects unable to use their intended symbols face branding issues, user confusion, and potential business losses
- **Ecosystem Degradation**: The token namespace utility degrades over time as more symbols get permanently locked

**Affected Parties:**
- All future token creators (both whitelisted system contracts and non-whitelisted users)
- The broader AElf ecosystem's token namespace availability
- Projects requiring specific symbol names for branding/interoperability

**Severity Justification:**
Medium to High severity is appropriate because:
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
Medium to High likelihood - depends on SEED distribution model, but the mechanism is unprotected once SEEDs enter circulation. The attack is economically rational for speculation or griefing purposes.

## Recommendation

Implement upper bound validation on expiration times in both functions:

1. **Add maximum expiration time constant** (e.g., 10 years from current time)
2. **Validate in `CreateNFTInfo()`**: Add assertion that `expirationTimeLong <= Context.CurrentBlockTime.Seconds + MaxExpirationPeriod`
3. **Validate in `ExtendSeedExpirationTime()`**: Add assertion that `input.ExpirationTime <= Context.CurrentBlockTime.Seconds + MaxExpirationPeriod`
4. **Add governance override**: Implement a Parliament-controlled function to clear expired or abusive `SymbolSeedMap` entries

Example fix for `ExtendSeedExpirationTime()`:
```csharp
public override Empty ExtendSeedExpirationTime(ExtendSeedExpirationTimeInput input)
{
    var tokenInfo = GetTokenInfo(input.Symbol);
    Assert(tokenInfo != null, "Seed NFT does not exist.");
    Assert(tokenInfo.Owner == Context.Sender, "Sender is not Seed NFT owner.");
    
    // Add upper bound validation
    const long MaxExpirationPeriodSeconds = 315360000; // 10 years
    Assert(input.ExpirationTime <= Context.CurrentBlockTime.Seconds + MaxExpirationPeriodSeconds,
        "Expiration time exceeds maximum allowed period.");
    
    // ... rest of function
}
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Create a SEED NFT (e.g., SEED-1) that owns symbol "TEST"
2. Call `ExtendSeedExpirationTime("SEED-1", 253402300799)` (December 31, 9999)
3. Verify that `SymbolSeedMap["TEST"]` returns "SEED-1"
4. Attempt to create a token with symbol "TEST" as a regular user
   - Expected: Transaction fails because CheckSeedNFT requires valid unexpired SEED
5. Attempt to create a token with symbol "TEST" as a whitelisted system contract
   - Expected: Transaction fails because CheckSymbolSeed detects unexpired SEED reservation
6. Verify that symbol "TEST" remains blocked until year 9999

The attack succeeds because no validation prevents setting expiration times to far-future values, and no governance mechanism exists to override these reservations.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L118-131)
```csharp
    private void CheckSeedNFT(string symbolSeed, String symbol)
    {
        Assert(!string.IsNullOrEmpty(symbolSeed), "Seed NFT does not exist.");
        var tokenInfo = GetTokenInfo(symbolSeed);
        Assert(tokenInfo != null, "Seed NFT does not exist.");
        Assert(State.Balances[Context.Sender][symbolSeed] > 0, "Seed NFT balance is not enough.");
        Assert(tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.SeedOwnedSymbolExternalInfoKey, out var ownedSymbol) && ownedSymbol == symbol,
            "Invalid OwnedSymbol.");
        Assert(tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                   out var expirationTime)
               && long.TryParse(expirationTime, out var expirationTimeLong) &&
               Context.CurrentBlockTime.Seconds <= expirationTimeLong, "OwnedSymbol is expired.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L259-265)
```csharp
    private bool IsAddressInCreateWhiteList(Address address)
    {
        return address == Context.GetZeroSmartContractAddress() ||
               address == GetDefaultParliamentController().OwnerAddress ||
               address == Context.GetContractAddressByName(SmartContractConstants.EconomicContractSystemName) ||
               address == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L18-18)
```csharp
    public MappedState<string, string> SymbolSeedMap { get; set; }
```
