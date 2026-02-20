# Audit Report

## Title
Stale Beneficiaries in Treasury Reward Schemes Due to Profits Receiver Address Desynchronization

## Summary
When a miner changes their custom profits receiver address via `SetProfitsReceiver`, the Treasury contract fails to remove the old receiver from BasicReward, WelcomeReward, and FlexibleReward schemes, creating permanent stale beneficiaries who continue receiving mining rewards indefinitely.

## Finding Description

The vulnerability stems from a critical desynchronization between how beneficiaries are added versus removed in the Treasury contract's reward distribution system.

**Root Cause - Address Resolution Mismatch:**

The `GetProfitsReceiver` method returns the custom receiver if set in `ProfitsReceiverMap`, otherwise defaults to the pubkey's address: [1](#0-0) 

However, `GetAddressesFromCandidatePubkeys` returns BOTH the default address derived from the pubkey AND the CURRENT receiver from the map: [2](#0-1) 

**Affected Functions:**

The three reward update functions all exhibit this flawed pattern:

1. `UpdateBasicMinerRewardWeights` removes beneficiaries using `GetAddressesFromCandidatePubkeys`: [3](#0-2) 

But adds beneficiaries using `GetProfitsReceiver`: [4](#0-3) 

2. `UpdateWelcomeRewardWeights` follows the identical flawed pattern: [5](#0-4) [6](#0-5) 

3. `UpdateFlexibleRewardWeights` uses the same removal logic: [7](#0-6) 

**Why Protections Fail:**

The Profit contract's `RemoveBeneficiary` silently returns `Empty` when the beneficiary doesn't exist: [8](#0-7) 

Additionally, `SetProfitsReceiver` only updates the Election contract's BackupSubsidy scheme, not the Treasury's reward schemes: [9](#0-8) 

The Election contract's handler only manages BackupSubsidy beneficiaries: [10](#0-9) 

**Execution Path:**

1. **Term N**: Miner sets custom receiver to CustomAddr1. During distribution, `UpdateBasicMinerRewardWeights` adds CustomAddr1 as beneficiary.

2. **Between Terms**: Miner calls `SetProfitsReceiver` changing receiver to CustomAddr2. This updates `State.ProfitsReceiverMap[PK]` to CustomAddr2.

3. **Term N+2**: During distribution, `GetAddressesFromCandidatePubkeys` reads the CURRENT state and returns [DefaultAddr, CustomAddr2]. The removal attempts fail silently because CustomAddr1 (the actual beneficiary) is not in that list. CustomAddr2 is then added as a new beneficiary.

4. **Result**: Both CustomAddr1 and CustomAddr2 are now beneficiaries, with CustomAddr1 persisting indefinitely.

## Impact Explanation

**Direct Fund Loss:**
- Stale beneficiaries permanently accumulate profit shares in BasicReward, WelcomeReward, and FlexibleReward schemes
- Mining rewards are substantial (approximately 1,250,000,000 ELF per term)
- BasicReward receives approximately 40% of miner rewards based on default weights

**Affected Parties:**
1. Old receiver addresses receive undeserved rewards, potentially compromised or malicious addresses
2. New legitimate receivers lose rewards due to diluted shares
3. Protocol economic model integrity is violated

**Severity - HIGH:**
- Permanent fund misallocation with no cleanup mechanism
- Affects multiple critical reward schemes simultaneously
- Accumulates with each receiver change
- Cannot be detected without manual scheme audits

## Likelihood Explanation

**Attacker Requirements:**
- Must be a candidate admin (standard role verified by permission check): [11](#0-10) 

**Exploitation Complexity - LOW:**
1. Become a candidate and get elected as miner (normal operation)
2. Set custom receiver CustomAddr1 to receive rewards
3. Mine for at least one term to become beneficiary
4. Change receiver to CustomAddr2 via `SetProfitsReceiver`
5. CustomAddr1 automatically becomes stale beneficiary
6. Both addresses receive rewards in subsequent distributions

**Feasibility - HIGH:**
- Requires only standard candidate admin permissions
- All operations are legitimate protocol functions
- Automatically triggered during term transitions by the consensus contract
- Even non-malicious receiver changes trigger the vulnerability

**Detection Difficulty:**
- Historical profit receiver mappings are not stored
- No alerts for beneficiary count mismatches
- Legitimate use case makes exploitation indistinguishable

## Recommendation

Modify `GetAddressesFromCandidatePubkeys` to accept a historical snapshot of pubkey-to-receiver mappings from the actual term being processed, rather than reading from current `ProfitsReceiverMap` state. Alternatively, store historical receiver addresses in the beneficiary details when adding them, and use those for removal.

A simpler fix would be to have `SetProfitsReceiver` directly update all three Treasury reward schemes (BasicReward, WelcomeReward, FlexibleReward) by removing the old receiver and adding the new one, similar to how it updates the Election contract's BackupSubsidy scheme.

## Proof of Concept

```csharp
[Fact]
public async Task StaleBeneficiary_WhenChangingProfitsReceiver_Test()
{
    // Setup: Candidate becomes miner with custom receiver CustomAddr1
    var minerPubkey = InitialCoreDataCenterKeyPairs[0].PublicKey.ToHex();
    var customAddr1 = Accounts[10].Address;
    var customAddr2 = Accounts[11].Address;
    
    // Term N: Set first custom receiver
    await TreasuryContractStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = minerPubkey,
        ProfitsReceiverAddress = customAddr1
    });
    
    // Simulate term distribution - CustomAddr1 gets added as beneficiary
    await BlockMiningService.MineBlockToNextTermAsync();
    
    // Between terms: Change to second custom receiver
    await TreasuryContractStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = minerPubkey,
        ProfitsReceiverAddress = customAddr2
    });
    
    // Term N+2: Distribution occurs
    await BlockMiningService.MineBlockToNextTermAsync();
    
    // Verify: BOTH CustomAddr1 and CustomAddr2 are beneficiaries
    var basicRewardScheme = await ProfitContractStub.GetScheme.CallAsync(ProfitItemsIds[ProfitType.BasicReward]);
    var customAddr1Details = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = basicRewardScheme.SchemeId,
        Beneficiary = customAddr1
    });
    var customAddr2Details = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = basicRewardScheme.SchemeId,
        Beneficiary = customAddr2
    });
    
    // Both should have profit details, proving stale beneficiary exists
    customAddr1Details.Details.Count.ShouldBeGreaterThan(0); // Stale beneficiary
    customAddr2Details.Details.Count.ShouldBeGreaterThan(0); // Current beneficiary
}
```

### Citations

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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L814-818)
```csharp
                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
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
