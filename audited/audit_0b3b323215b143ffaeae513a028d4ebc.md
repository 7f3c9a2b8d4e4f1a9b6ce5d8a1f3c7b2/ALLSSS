### Title
Treasury Contract Lacks Validation Logic to Detect Malicious Referenced Contract Upgrades

### Summary
The Treasury contract references six critical system contracts (Profit, Token, AEDPoS, TokenConverter, Election, Parliament) but implements no validation logic to detect if these contracts are upgraded to malicious or incompatible implementations. When contract addresses are cached during initialization, Treasury blindly trusts all subsequent calls to these addresses, creating a single point of failure if any referenced contract is compromised through governance or code review bypass.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** Treasury caches contract addresses once during initialization and uses them throughout its lifetime without any validation mechanism: [2](#0-1) [3](#0-2) [4](#0-3) 

**Why Protections Fail:**

1. **No Event Listening**: Treasury does not listen to `CodeUpdated` events emitted when contracts are upgraded [5](#0-4) 

2. **No Return Value Validation**: Critical operations trust return values without bounds checking or sanity validation:
   - Profit distributions [6](#0-5) 
   - Token transfers [7](#0-6) 
   - Miner information [8](#0-7) 

3. **Address Immutability**: Contract addresses remain constant during upgrades (only code changes), so cached addresses continue pointing to upgraded (potentially malicious) implementations [9](#0-8) 

4. **No Contract Verification**: Treasury has no mechanism to verify contract code hash, version, or behavioral compatibility after initialization.

### Impact Explanation

**Direct Financial Impact:**
- **Fund Theft**: A malicious TokenContract could redirect Treasury fund transfers to attacker addresses during donation processing [7](#0-6)  or token conversions [10](#0-9) 
  
- **Reward Manipulation**: A malicious ProfitContract could manipulate distribution calculations, stealing rewards meant for miners/citizens [11](#0-10) 

- **Profit Scheme Corruption**: Malicious profit scheme management could drain Treasury virtual address balance [12](#0-11) 

**Governance Impact:**
- A malicious ParliamentContract could approve unauthorized Treasury configuration changes [13](#0-12) 

**Consensus Impact:**
- A malicious AEDPoSContract could forge miner lists or term information, corrupting reward distributions [14](#0-13) 

**Affected Parties:** All Treasury stakeholders including miners, voters, token holders, and the entire AElf ecosystem relying on correct economic incentives.

**Severity Justification:** HIGH - Treasury manages the entire economic reward system (20% of total supply). Compromise of any referenced contract could result in complete Treasury fund drainage or reward system corruption.

### Likelihood Explanation

**Attack Prerequisites:**
1. Attacker must successfully upgrade one of the six referenced contracts to a malicious implementation
2. This requires either:
   - Compromising both ContractDeploymentController (Parliament) AND CodeCheckController governance
   - OR bypassing code review through sophisticated hidden malicious code (supply chain attack, obfuscated logic)

**Attack Complexity:** HIGH initially (requires governance compromise or code review bypass), but ZERO complexity post-upgrade since Treasury has no detection mechanisms.

**Feasibility Conditions:**
- Governance compromise is possible though difficult (requires controlling sufficient Parliament members)
- Code review bypass is realistic for subtle bugs or well-obfuscated malicious code
- Historical precedent: Many blockchain projects have suffered from governance attacks or code review failures

**Detection Constraints:** 
- Treasury provides NO detection capability
- Attack would only be discovered through:
  - External monitoring of CodeUpdated events
  - Post-compromise forensic analysis
  - User reports of incorrect distributions

**Probability Assessment:** MEDIUM likelihood (governance compromise is non-trivial but feasible; code review bypass has precedent in industry)

### Recommendation

**1. Implement Contract Upgrade Validation:**
```
Add event listener for CodeUpdated events or implement periodic validation:
- Check contract code hash against expected values
- Verify contract version increments are expected
- Validate contract still implements required interfaces
```

**2. Add Return Value Validation:**
```
For critical operations in TreasuryContract.cs, add bounds checking:
- Validate profit distribution amounts are within expected ranges
- Verify token transfer success and balance changes match expectations
- Check miner list sizes and membership against consensus rules
- Validate election data consistency
```

**3. Implement Circuit Breaker:**
```
Add emergency pause mechanism when:
- Referenced contract behavior deviates from historical patterns
- Return values exceed statistical thresholds
- Cross-contract data becomes inconsistent
```

**4. Add Contract Attestation:**
```
Store expected code hashes for referenced contracts in state
Periodically verify actual code hash matches expected
Require governance approval to update expected code hashes
```

**Test Cases:**
- Test Treasury behavior when ProfitContract returns malicious distribution amounts
- Test Treasury response when TokenContract transfer returns false success
- Test Treasury handling of forged miner lists from AEDPoSContract
- Verify circuit breaker triggers on anomalous return values

### Proof of Concept

**Initial State:**
- Treasury is initialized with references to six system contracts
- Contract addresses are cached in TreasuryContractState [1](#0-0) 

**Attack Sequence:**

**Step 1:** Attacker compromises governance and proposes malicious ProfitContract upgrade
```
ProposeUpdateContract(ProfitContract.Address, MaliciousCode)
→ Passes Parliament approval
→ Passes CodeCheck approval (hidden malicious logic)
→ ReleaseCodeCheckedContract executed
```

**Step 2:** Malicious ProfitContract is deployed at same address [9](#0-8) 

**Step 3:** Treasury continues using cached address without detection
```
Treasury.Release() calls State.ProfitContract.DistributeProfits()
→ Malicious ProfitContract redirects funds to attacker
→ Treasury has NO validation of distribution correctness
→ Returns success even though funds were stolen
```

**Expected Result:** Treasury should detect incompatible/malicious behavior and reject the call

**Actual Result:** Treasury blindly trusts malicious contract, allowing fund theft or reward manipulation with zero detection capability

**Success Condition:** Malicious contract can steal Treasury funds or manipulate distributions without Treasury detecting or preventing the attack

### Citations

**File:** contract/AElf.Contracts.Treasury/ContractsReferences.cs (L13-18)
```csharp
    internal ProfitContractContainer.ProfitContractReferenceState ProfitContract { get; set; }
    internal TokenContractContainer.TokenContractReferenceState TokenContract { get; set; }
    internal AEDPoSContractContainer.AEDPoSContractReferenceState AEDPoSContract { get; set; }
    internal TokenConverterContractContainer.TokenConverterContractReferenceState TokenConverterContract { get; set; }
    internal ElectionContractContainer.ElectionContractReferenceState ElectionContract { get; set; }
    internal ParliamentContractContainer.ParliamentContractReferenceState ParliamentContract { get; set; }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L46-47)
```csharp
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L60-67)
```csharp
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
                // Distribution of Citizen Welfare will delay one period.
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L129-134)
```csharp
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.TreasuryHash.Value,
            Period = input.PeriodNumber,
            AmountsMap = { State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L) }
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L136-143)
```csharp
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });

        var currentMinerList = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(p => p.ToHex()).ToList();
        var maybeNewElectedMiners = new List<string>();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L178-179)
```csharp
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L195-202)
```csharp
            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = Context.Sender,
                To = Context.Self,
                Symbol = input.Symbol,
                Amount = input.Amount,
                Memo = "Donate to treasury."
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L669-680)
```csharp
        State.TokenContract.Approve.Send(new ApproveInput
        {
            Spender = State.TokenConverterContract.Value,
            Symbol = symbol,
            Amount = amount
        });

        State.TokenConverterContract.Sell.Send(new SellInput
        {
            Symbol = symbol,
            Amount = amount
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L708-734)
```csharp
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.RewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.ReElectionRewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.BasicRewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L737-741)
```csharp
    private void RequireAEDPoSContractStateSet()
    {
        if (State.AEDPoSContract.Value == null)
            State.AEDPoSContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L947-955)
```csharp
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L98-111)
```csharp
    private void UpdateSmartContract(Address contractAddress, byte[] code, Address author, bool isUserContract)
    {
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        Assert(author == info.Author, "No permission.");

        var oldCodeHash = info.CodeHash;
        var newCodeHash = HashHelper.ComputeFrom(code);
        Assert(oldCodeHash != newCodeHash, "Code is not changed.");
        AssertContractNotExists(newCodeHash);

        info.CodeHash = newCodeHash;
        info.IsUserContract = isUserContract;
        info.Version++;
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L134-141)
```csharp
        Context.Fire(new CodeUpdated
        {
            Address = contractAddress,
            OldCodeHash = oldCodeHash,
            NewCodeHash = newCodeHash,
            Version = info.Version,
            ContractVersion = info.ContractVersion
        });
```
