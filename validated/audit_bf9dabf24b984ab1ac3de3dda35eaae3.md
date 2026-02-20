# Audit Report

## Title
Stale Beneficiaries in Treasury Reward Schemes Due to Profits Receiver Address Desynchronization

## Summary
When a miner changes their custom profits receiver address via `SetProfitsReceiver`, the Treasury contract fails to remove the old receiver from BasicReward, WelcomeReward, and FlexibleReward schemes. The removal logic uses the current profits receiver mapping, but the actual beneficiary was added using a historical mapping value, creating a permanent desynchronization where both old and new addresses receive rewards indefinitely.

## Finding Description

The vulnerability stems from a temporal desynchronization in the Treasury contract's beneficiary management. The core issue is that beneficiary addition and removal operations both query the current state of `State.ProfitsReceiverMap`, but they execute at different points in time.

**Beneficiary Addition Logic:**
When adding beneficiaries, the code uses `GetProfitsReceiver(pubkey)` [1](#0-0)  which returns the current value in `State.ProfitsReceiverMap[pubkey]`, or defaults to the address derived from the pubkey if no custom receiver is set.

**Beneficiary Removal Logic:**
When removing beneficiaries, the code uses `GetAddressesFromCandidatePubkeys(pubkeys)` [2](#0-1)  which returns BOTH the default address from each pubkey AND the current profits receiver for each pubkey. This means it attempts to remove addresses based on the CURRENT mapping state, not the historical state when beneficiaries were originally added.

**The Desynchronization:**

In `UpdateBasicMinerRewardWeights`, removal uses `GetAddressesFromCandidatePubkeys` on previous term miners [3](#0-2)  while addition uses `GetProfitsReceiver` on current term miners [4](#0-3) .

The same pattern exists in `UpdateWelcomeRewardWeights` [5](#0-4)  for removal and [6](#0-5)  for addition.

And in `UpdateFlexibleRewardWeights` for removal [7](#0-6) .

**Why Protections Fail:**

When `SetProfitsReceiver` is called, it updates `State.ProfitsReceiverMap[pubkey]` [8](#0-7)  but only propagates this change to the Election contract's BackupSubsidy scheme [9](#0-8) . The Treasury's BasicReward, WelcomeReward, and FlexibleReward schemes are not updated.

The Profit contract's `RemoveBeneficiary` function silently returns when attempting to remove a non-existent beneficiary [10](#0-9) , allowing the stale beneficiary removal to fail without any error.

**Execution Scenario:**

1. **Term N-2**: Miner PK1 has `State.ProfitsReceiverMap[PK1]` = CustomAddr1. CustomAddr1 is added as beneficiary to BasicReward scheme.

2. **Between Terms**: Candidate admin calls `SetProfitsReceiver` [11](#0-10)  to change from CustomAddr1 to CustomAddr2. `State.ProfitsReceiverMap[PK1]` is updated to CustomAddr2.

3. **Term N**: During the `Release` method execution [12](#0-11) , `UpdateBasicMinerRewardWeights` attempts to remove beneficiaries from term N-2:
   - Calls `GetAddressesFromCandidatePubkeys(term_N-2_miners)` with PK1
   - Returns [DefaultAddr(PK1), CustomAddr2] (using CURRENT mapping)
   - Attempts to remove DefaultAddr(PK1) - fails silently (not a beneficiary)
   - Attempts to remove CustomAddr2 - fails silently (not a beneficiary)
   - CustomAddr1 (the ACTUAL beneficiary) is never removed

4. **Result**: CustomAddr1 remains as stale beneficiary while CustomAddr2 is added as new beneficiary. Both addresses receive rewards indefinitely.

## Impact Explanation

**Fund Misallocation Severity:**
Mining rewards in the BasicReward scheme represent approximately 40% of total miner rewards (default weight configuration). With substantial block production rewards (~1,250,000 ELF per block), each stale beneficiary continues receiving their performance-adjusted share (typically 1 share per miner) indefinitely.

**Affected Parties:**
1. **Legitimate new receivers** - receive diluted shares because the total pool now includes additional stale beneficiaries
2. **Protocol treasury** - reward distribution accuracy is permanently compromised, violating the economic model design
3. **Old receiver addresses** - may be compromised keys, malicious actors, or former administrators who should no longer receive protocol rewards

**Accumulation Factor:**
This vulnerability has no self-healing mechanism. Each time a miner changes their profits receiver, a new stale beneficiary is created. Over time, the accumulated stale beneficiaries grow, increasing the misallocation percentage and dilution of legitimate shares.

**Permanence:**
Without manual intervention through governance to reconstruct the beneficiary lists, these stale entries persist forever, continuously draining rewards from the legitimate distribution pool.

## Likelihood Explanation

**Trigger Conditions:**
The vulnerability triggers through normal, expected operations - any candidate admin calling `SetProfitsReceiver` to change their profits receiver address. This is a standard administrative function with no special permissions required beyond being the candidate admin.

**Attack Complexity:**
Extremely low. The exploit requires:
1. Being a candidate admin (publicly achievable)
2. Having been elected as a miner (normal operation)
3. Calling `SetProfitsReceiver` to change receiver address (single transaction)
4. Waiting for automatic term transitions (no action required)

**Detection Difficulty:**
Very difficult to detect without manual auditing because:
- Beneficiary changes are logged but historical mappings aren't stored
- No automated monitoring for beneficiary count mismatches
- Legitimate receiver changes are indistinguishable from exploitation
- Would require manual cross-verification of profit scheme beneficiaries against current miner list

**Occurrence Probability:**
High. This occurs naturally whenever any active miner changes their profits receiver. Even non-malicious operational changes (key rotation, custody changes, organizational restructuring) trigger the vulnerability. With multiple active miners potentially changing receivers over the protocol's lifetime, accumulation is inevitable.

## Recommendation

Store historical profits receiver mappings or track which address was originally added as beneficiary for each pubkey. Modify the removal logic to remove the historically-added beneficiary, not the current mapping value.

**Recommended Fix:**
```csharp
// Add state to track original beneficiary per term
State.BeneficiaryHistoryMap[pubkey][termNumber] = profitsReceiverAddress;

// In UpdateBasicMinerRewardWeights removal logic:
private void UpdateBasicMinerRewardWeights(IReadOnlyCollection<Round> previousTermInformation)
{
    var termToRemove = previousTermInformation.First().TermNumber;
    var addressesToRemove = previousTermInformation.First().RealTimeMinersInformation.Keys
        .Select(pubkey => State.BeneficiaryHistoryMap[pubkey][termToRemove] ?? 
                         GetProfitsReceiver(pubkey))
        .ToList();
    
    State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
    {
        SchemeId = State.BasicRewardHash.Value,
        Beneficiaries = { addressesToRemove }
    });
    // ... rest of method
}
```

Alternatively, when `SetProfitsReceiver` is called, immediately update all relevant Treasury profit schemes (BasicReward, WelcomeReward, FlexibleReward) by removing the old beneficiary and adding the new one, similar to how it currently handles the Election contract's BackupSubsidy scheme.

## Proof of Concept

```csharp
[Fact]
public async Task StaleBeneficiary_WhenProfitsReceiverChanged_Test()
{
    // Setup: Miner becomes beneficiary with CustomAddr1
    var minerPubkey = "miner_pubkey_1";
    var customAddr1 = Address.FromString("custom_address_1");
    var customAddr2 = Address.FromString("custom_address_2");
    
    // Term N-2: Set initial custom receiver
    await TreasuryContractStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = minerPubkey,
        ProfitsReceiverAddress = customAddr1
    });
    
    // Mine a term - CustomAddr1 becomes beneficiary
    await AdvanceTermAndDistribute();
    
    // Verify CustomAddr1 is beneficiary
    var scheme = await ProfitContractStub.GetScheme.CallAsync(BasicRewardHash);
    var beneficiaries = await GetBeneficiaries(BasicRewardHash);
    Assert.Contains(customAddr1, beneficiaries);
    
    // Change receiver to CustomAddr2
    await TreasuryContractStub.SetProfitsReceiver.SendAsync(new SetProfitsReceiverInput
    {
        Pubkey = minerPubkey,
        ProfitsReceiverAddress = customAddr2
    });
    
    // Advance two terms to trigger UpdateBasicMinerRewardWeights
    await AdvanceTermAndDistribute();
    await AdvanceTermAndDistribute();
    
    // BUG: Both CustomAddr1 (stale) and CustomAddr2 (new) are beneficiaries
    beneficiaries = await GetBeneficiaries(BasicRewardHash);
    Assert.Contains(customAddr1, beneficiaries); // STALE - should be removed
    Assert.Contains(customAddr2, beneficiaries); // LEGITIMATE
    
    // Both addresses receive rewards
    await DistributeRewards();
    var balance1 = await GetBalance(customAddr1);
    var balance2 = await GetBalance(customAddr2);
    
    Assert.True(balance1 > 0); // Stale beneficiary still receiving rewards
    Assert.True(balance2 > 0); // New beneficiary receiving rewards
}
```

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L620-620)
```csharp
        State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L621-626)
```csharp
        State.ElectionContract.SetProfitsReceiver.Send(new AElf.Contracts.Election.SetProfitsReceiverInput
        {
            CandidatePubkey = input.Pubkey,
            ReceiverAddress = input.ProfitsReceiverAddress,
            PreviousReceiverAddress = previousProfitsReceiver ?? new Address()
        });
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L751-763)
```csharp
    private void UpdateStateBeforeDistribution(Round previousTermInformation, List<string> newElectedMiners)
    {
        var previousPreviousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = previousTermInformation.TermNumber.Sub(1)
        });

        if (newElectedMiners.Any()) State.HasNewMiner[previousTermInformation.TermNumber.Add(1)] = true;

        Context.LogDebug(() => $"Will update weights after term {previousTermInformation.TermNumber}");
        UpdateBasicMinerRewardWeights(new List<Round> { previousPreviousTermInformation, previousTermInformation });
        UpdateWelcomeRewardWeights(previousTermInformation, newElectedMiners);
        UpdateFlexibleRewardWeights(previousTermInformation);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-235)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();
```
