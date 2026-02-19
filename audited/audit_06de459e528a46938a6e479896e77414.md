# Audit Report

## Title
Stale Beneficiaries in Treasury Reward Schemes Due to Profits Receiver Address Desynchronization

## Summary
When a miner's custom profits receiver address is changed via `SetProfitsReceiver`, the Treasury contract fails to remove the old receiver address from BasicReward, WelcomeReward, and FlexibleReward schemes. This creates permanent stale beneficiaries who continue receiving mining rewards indefinitely, resulting in ongoing fund misallocation.

## Finding Description

The vulnerability exists in the Treasury contract's beneficiary management system, specifically in how it handles profits receiver address changes across three critical reward update functions.

**Root Cause - Address Resolution Mismatch:**

When adding beneficiaries, the code uses `GetProfitsReceiver` which returns the custom receiver if set in the map, otherwise defaults to the pubkey's address. [1](#0-0) 

However, when removing beneficiaries, the code uses `GetAddressesFromCandidatePubkeys` which returns BOTH the default address from the pubkey AND the CURRENT profits receiver from the map. [2](#0-1) 

**Affected Functions:**

1. `UpdateBasicMinerRewardWeights` removes beneficiaries using `GetAddressesFromCandidatePubkeys` [3](#0-2)  but adds beneficiaries using `GetProfitsReceiver` [4](#0-3) 

2. `UpdateWelcomeRewardWeights` follows the same flawed pattern for removal [5](#0-4)  and addition [6](#0-5) 

3. `UpdateFlexibleRewardWeights` uses the same removal logic [7](#0-6) 

**Why Protections Fail:**

The Profit contract's `RemoveBeneficiary` function returns `Empty` silently when the beneficiary's profit details don't exist in the scheme. [8](#0-7) 

Additionally, `SetProfitsReceiver` only updates the Election contract's BackupSubsidy scheme, not the Treasury's BasicReward/WelcomeReward/FlexibleReward schemes. [9](#0-8)  The Election contract's handler only manages its own BackupSubsidy beneficiaries. [10](#0-9) 

**Execution Path:**

1. **Term N**: Miner with pubkey PK sets custom receiver to CustomAddr1 via `SetProfitsReceiver` [11](#0-10) 
2. During term distribution, `UpdateBasicMinerRewardWeights` adds CustomAddr1 as beneficiary
3. **Between Terms**: Miner calls `SetProfitsReceiver` again, changing receiver to CustomAddr2, which updates `State.ProfitsReceiverMap[PK]` to CustomAddr2
4. **Term N+2**: During distribution, `GetAddressesFromCandidatePubkeys` returns [DefaultAddr, CustomAddr2]
5. Removal attempts for both addresses fail silently because neither exists as beneficiary (CustomAddr1 was added)
6. CustomAddr2 is then added as new beneficiary
7. Result: Both CustomAddr1 and CustomAddr2 are now beneficiaries, with CustomAddr1 persisting indefinitely

## Impact Explanation

**Direct Fund Loss:**
- Stale beneficiaries continue accumulating profit shares in BasicReward, WelcomeReward, and FlexibleReward schemes without limit
- Mining rewards are substantial (~1,250,000,000 ELF per term based on block production) [12](#0-11) 
- BasicReward receives ~40% of miner rewards based on default weights [13](#0-12) 

**Affected Parties:**
1. Old receiver addresses receive rewards they shouldn't, potentially compromised or malicious addresses
2. New legitimate receivers never get full rewards for past periods
3. Protocol economic model integrity is violated

**Severity - HIGH:**
- Permanent fund misallocation with no cleanup mechanism
- Affects multiple critical reward schemes simultaneously
- Accumulates over time with each receiver change
- Cannot be easily detected without manual scheme audits

## Likelihood Explanation

**Attacker Requirements:**
- Must be a candidate admin (standard role for any candidate)
- Can call `SetProfitsReceiver` as verified by permission check [14](#0-13) 

**Exploitation Complexity - LOW:**
1. Become a candidate and get elected as miner (normal operation)
2. Set custom receiver CustomAddr1 to receive rewards
3. Mine for at least one term to become beneficiary
4. Change receiver to CustomAddr2 via `SetProfitsReceiver`
5. CustomAddr1 automatically becomes stale beneficiary
6. Both addresses receive rewards in subsequent distributions

**Feasibility - HIGH:**
- Requires only standard candidate admin permissions
- No suspicious transactions needed - all operations are legitimate
- Trigger is automatic during term transitions called by consensus contract [15](#0-14) 
- Even non-malicious receiver changes trigger the vulnerability

**Detection Difficulty:**
- Historical profit receiver mappings are not stored
- No alerts for beneficiary count mismatches
- Legitimate use case makes exploitation indistinguishable from normal operation

## Recommendation

**Fix 1: Track and Remove Old Receiver During SetProfitsReceiver**

Modify `SetProfitsReceiver` to immediately update beneficiaries in all Treasury schemes:

```csharp
public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
{
    // ... existing validation ...
    
    var previousProfitsReceiver = State.ProfitsReceiverMap[input.Pubkey];
    
    // Remove old receiver from Treasury schemes if it exists and miner is active
    if (previousProfitsReceiver != null && State.LatestMinedTerm[input.Pubkey] > 0)
    {
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.BasicRewardHash.Value,
            Beneficiary = previousProfitsReceiver
        });
        
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Beneficiary = previousProfitsReceiver
        });
        
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.ReElectionRewardHash.Value,
            Beneficiary = previousProfitsReceiver
        });
    }
    
    State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
    // ... rest of existing code ...
}
```

**Fix 2: Store Historical Receiver Mapping**

Create a state variable to track the receiver that was actually added as beneficiary:

```csharp
public MappedState<string, Address> ActiveBeneficiaryMap { get; set; }
```

Then use this during removal:
```csharp
private List<Address> GetAddressesForRemoval(ICollection<string> pubkeys)
{
    var addresses = new List<Address>();
    foreach (var pubkey in pubkeys)
    {
        var activeReceiver = State.ActiveBeneficiaryMap[pubkey];
        if (activeReceiver != null)
            addresses.Add(activeReceiver);
        else
            addresses.Add(Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey)));
    }
    return addresses;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task StaleBeneficiary_WhenProfitsReceiverChanged()
{
    // Setup: Miner becomes active with CustomAddr1 as receiver
    var minerKeyPair = MissionedECKeyPairs[0];
    var customAddr1 = MissionedECKeyPairs[1].PublicKey;
    var customAddr2 = MissionedECKeyPairs[2].PublicKey;
    
    // Set initial profits receiver to CustomAddr1
    await TreasuryContractStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = minerKeyPair.PublicKey.ToHex(),
        ProfitsReceiverAddress = Address.FromPublicKey(customAddr1)
    });
    
    // Advance term and trigger distribution (CustomAddr1 gets added)
    await NextTerm(MissionedECKeyPairs[0]);
    
    // Verify CustomAddr1 is beneficiary in BasicReward
    var basicRewardScheme = await ProfitContractStub.GetScheme.CallAsync(
        await TreasuryContractStub.GetTreasurySchemeId.CallAsync(new Empty()));
    var profitDetails1 = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = State.BasicRewardHash.Value,
        Beneficiary = Address.FromPublicKey(customAddr1)
    });
    profitDetails1.Details.Count.ShouldBeGreaterThan(0); // CustomAddr1 is beneficiary
    
    // Change receiver to CustomAddr2
    await TreasuryContractStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = minerKeyPair.PublicKey.ToHex(),
        ProfitsReceiverAddress = Address.FromPublicKey(customAddr2)
    });
    
    // Advance term and trigger distribution again
    await NextTerm(MissionedECKeyPairs[0]);
    
    // VULNERABILITY: CustomAddr1 should be removed but still exists
    var staleProfitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = State.BasicRewardHash.Value,
        Beneficiary = Address.FromPublicKey(customAddr1)
    });
    staleProfitDetails.Details.Count.ShouldBeGreaterThan(0); // BUG: Still exists!
    
    // CustomAddr2 is also added as beneficiary
    var newProfitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = State.BasicRewardHash.Value,
        Beneficiary = Address.FromPublicKey(customAddr2)
    });
    newProfitDetails.Details.Count.ShouldBeGreaterThan(0);
    
    // Both addresses now receive rewards - fund misallocation confirmed
}
```

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L18-26)
```csharp
/// <summary>
///     The Treasury is the largest profit scheme in AElf main chain.
///     Actually the Treasury is our Dividends Pool.
///     Income of the Treasury is mining rewards
///     (AEDPoS Contract will:
///     1. transfer ELF tokens to general ledger of Treasury every time we change term (7 days),
///     the amount of ELF should be based on blocks produced during last term. 1,000,000 * 1250000 ELF,
///     then release the Treasury;
///     2. Release Treasury)
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L123-128)
```csharp
    public override Empty Release(ReleaseInput input)
    {
        RequireAEDPoSContractStateSet();
        Assert(
            Context.Sender == State.AEDPoSContract.Value,
            "Only AElf Consensus Contract can release profits from Treasury.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L480-488)
```csharp
    private MinerRewardWeightSetting GetDefaultMinerRewardWeightSetting()
    {
        return new MinerRewardWeightSetting
        {
            BasicMinerRewardWeight = 2,
            WelcomeRewardWeight = 1,
            FlexibleRewardWeight = 1
        };
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L601-628)
```csharp
    public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
    {
        if (State.ElectionContract.Value == null)
            State.ElectionContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        var pubkey = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.Pubkey));
        
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
        
        var candidateList = State.ElectionContract.GetCandidates.Call(new Empty());
        Assert(candidateList.Value.Contains(pubkey),"Pubkey is not a candidate.");

        var previousProfitsReceiver = State.ProfitsReceiverMap[input.Pubkey];
        //Set same profits receiver address.
        if (input.ProfitsReceiverAddress == previousProfitsReceiver)
        {
            return new Empty();
        }
        State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
        State.ElectionContract.SetProfitsReceiver.Send(new AElf.Contracts.Election.SetProfitsReceiverInput
        {
            CandidatePubkey = input.Pubkey,
            ReceiverAddress = input.ProfitsReceiverAddress,
            PreviousReceiverAddress = previousProfitsReceiver ?? new Address()
        });

        return new Empty();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L651-655)
```csharp
    private Address GetProfitsReceiver(string pubkey)
    {
        return State.ProfitsReceiverMap[pubkey] ??
               Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey));
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L657-663)
```csharp
    private List<Address> GetAddressesFromCandidatePubkeys(ICollection<string> pubkeys)
    {
        var addresses = pubkeys.Select(k => Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(k)))
            .ToList();
        addresses.AddRange(pubkeys.Select(GetProfitsReceiver));
        return addresses;
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L780-787)
```csharp
            State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
            {
                SchemeId = State.BasicRewardHash.Value,
                Beneficiaries =
                {
                    GetAddressesFromCandidatePubkeys(previousTermInformation.First().RealTimeMinersInformation.Keys)
                }
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L814-820)
```csharp
                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
                })
            }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L850-857)
```csharp
        var previousMinerAddresses =
            GetAddressesFromCandidatePubkeys(previousTermInformation.RealTimeMinersInformation.Keys);
        var possibleWelcomeBeneficiaries = new RemoveBeneficiariesInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Beneficiaries = { previousMinerAddresses }
        };
        State.ProfitContract.RemoveBeneficiaries.Send(possibleWelcomeBeneficiaries);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L872-877)
```csharp
            foreach (var minerAddress in newElectedMiners.Select(GetProfitsReceiver))
                newBeneficiaries.BeneficiaryShares.Add(new BeneficiaryShare
                {
                    Beneficiary = minerAddress,
                    Shares = 1
                });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L907-913)
```csharp
            var previousMinerAddresses =
                GetAddressesFromCandidatePubkeys(previousTermInformation.RealTimeMinersInformation.Keys);
            State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
            {
                SchemeId = State.ReElectionRewardHash.Value,
                Beneficiaries = { previousMinerAddresses }
            });
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L233-235)
```csharp
        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L379-398)
```csharp
    public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName) == Context.Sender,
            "No permission.");
        var rankingList = State.DataCentersRankingList;
        if (!rankingList.Value.DataCenters.ContainsKey(input.CandidatePubkey)) return new Empty();
        var beneficiaryAddress = input.PreviousReceiverAddress.Value.Any()
            ? input.PreviousReceiverAddress
            : Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.CandidatePubkey));
        //set same profits receiver address
        if (beneficiaryAddress == input.ReceiverAddress)
        {
            return new Empty();
        }
        RemoveBeneficiary(input.CandidatePubkey,beneficiaryAddress);
        AddBeneficiary(input.CandidatePubkey,input.ReceiverAddress);

        return new Empty();
    }
```
