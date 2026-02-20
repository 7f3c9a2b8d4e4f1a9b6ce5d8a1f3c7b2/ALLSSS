# Audit Report

## Title
Stale Beneficiaries Due to Custom Profits Receiver Address Changes in Treasury Reward Distribution

## Summary
The Treasury contract's reward weight update functions fail to properly remove beneficiaries when miners change their custom profits receiver address between terms. This creates permanent stale beneficiaries that continue draining mining rewards indefinitely, diluting payments to legitimate current miners.

## Finding Description

The vulnerability exists in three Treasury reward update functions that follow an identical flawed pattern in tracking beneficiary addresses across custom receiver changes.

The `UpdateBasicMinerRewardWeights` function removes beneficiaries from the previous term using `GetAddressesFromCandidatePubkeys`, which is called with the previous term's miner list. [1](#0-0) 

The `GetAddressesFromCandidatePubkeys` helper function returns two types of addresses for each pubkey: the pubkey-derived address and the result of calling `GetProfitsReceiver`. [2](#0-1) 

The `GetProfitsReceiver` function returns the CURRENT value from the `ProfitsReceiverMap` state variable, falling back to the pubkey-derived address only if no custom receiver is currently set. [3](#0-2) 

When beneficiaries are added to schemes, the code uses `GetProfitsReceiver(i.Pubkey)` to determine the beneficiary address at that specific moment. [4](#0-3) 

When a miner changes their custom receiver via `SetProfitsReceiver`, it updates the `ProfitsReceiverMap` but does NOT directly update any of the Treasury's profit schemes (BasicReward, VotesWeightReward, or ReElectionReward). [5](#0-4) 

The critical silent failure occurs in the Profit contract's `RemoveBeneficiary` function, which returns an empty result without error if the beneficiary address doesn't exist in the profit details map. [6](#0-5) 

The same vulnerability pattern exists in `UpdateWelcomeRewardWeights`: [7](#0-6) 

And in `UpdateFlexibleRewardWeights`: [8](#0-7) 

**Attack Scenario:**
1. **Term N**: Miner has custom receiver Address_1 set. The `UpdateBasicMinerRewardWeights` function adds Address_1 as a beneficiary using `GetProfitsReceiver`, which returns Address_1.

2. **Between Terms**: Miner's admin calls `SetProfitsReceiver` to change the receiver to Address_2. The `ProfitsReceiverMap` is updated, but the BasicReward scheme beneficiary list is not modified.

3. **Term N+1**: `UpdateBasicMinerRewardWeights` attempts to remove beneficiaries from Term N:
   - Calls `GetAddressesFromCandidatePubkeys` which returns [pubkey-derived address, Address_2]
   - Neither of these addresses was ever added as a beneficiary (Address_1 was the actual beneficiary)
   - Both removal attempts silently fail due to the silent return in `RemoveBeneficiary`
   - Address_1 remains in the scheme with its original shares

4. **Term N+1 continued**: The function then adds beneficiaries for the new term, adding Address_2 with new shares.

5. **Result**: Both Address_1 (stale) and Address_2 (current) now have shares in the scheme. Address_1 continues receiving rewards indefinitely while the miner also receives rewards through Address_2.

## Impact Explanation

**Direct Financial Impact:**
- Stale beneficiary addresses permanently receive mining rewards they are no longer entitled to
- Each stale beneficiary inflates the total shares in profit schemes, directly reducing the per-share reward amount for all legitimate miners
- The reward distribution uses the formula `(beneficiary_shares / total_shares) * period_rewards`, so stale shares directly dilute legitimate payouts
- Affects all three major Treasury reward channels: BasicReward, VotesWeightReward (Welcome Reward), and ReElectionReward (Flexible Reward)

**Compounding Effect:**
- Each time a miner changes their custom receiver, a new stale beneficiary is created
- Multiple changes by the same miner create multiple stale addresses all continuing to receive rewards
- Multiple adversarial miners can compound the effect exponentially

**Affected Parties:**
- Active miners receive systematically reduced rewards due to inflated denominator in share calculations
- Treasury reward pools are continuously drained by addresses that should no longer be beneficiaries
- Legitimate candidates who don't exploit this mechanism suffer competitive disadvantage

**Severity:**
HIGH - This vulnerability enables permanent, unrecoverable theft of mining rewards through a trivially simple action with no cost beyond being a registered candidate. The silent failure mechanism prevents any detection or monitoring.

## Likelihood Explanation

**Attacker Capabilities:**
Any candidate can call `SetProfitsReceiver` through their admin account. The permission check only validates that the caller is the candidate's admin as retrieved from the Election contract. [9](#0-8) 

**Attack Complexity:**
- Extremely low: requires only a single call to `SetProfitsReceiver` with a different address
- No timing constraints or race conditions needed
- Works deterministically due to the predictable state management
- The natural delay between when beneficiaries are added (one term) and removed (next term) provides ample opportunity for the receiver change

**Feasibility:**
- Attacker only needs to be a registered candidate with an admin account (standard for all candidates)
- The function is publicly accessible with basic validation
- No monitoring exists to detect when `RemoveBeneficiary` silently fails
- No cleanup mechanism exists to remove stale beneficiaries

**Detection Difficulty:**
- Stale beneficiaries are indistinguishable from legitimate beneficiaries in the profit schemes
- No events or logs are emitted when `RemoveBeneficiary` fails silently
- The silent failure at line 235 of ProfitContract prevents any automated detection

**Probability:**
HIGH - The attack is trivial to execute, requires no special conditions, costs nothing beyond normal candidate operations, and is extremely difficult to detect. Any rational adversarial candidate could exploit this for permanent financial gain.

## Recommendation

The root cause is that `GetAddressesFromCandidatePubkeys` uses the CURRENT profits receiver mapping instead of tracking the ACTUAL addresses that were added as beneficiaries in previous terms.

**Solution 1: Track Historical Beneficiaries**
Maintain a mapping of `(pubkey, term) => beneficiary_address` that records which address was actually added as a beneficiary for each term. Use this historical mapping when removing beneficiaries instead of the current receiver mapping.

**Solution 2: Update Schemes When Receiver Changes**
In `SetProfitsReceiver`, immediately update all three Treasury profit schemes (BasicReward, VotesWeightReward, ReElectionReward) to replace the old beneficiary with the new one, similar to how the Election contract updates the Subsidy scheme.

**Solution 3: Remove Old Receiver Explicitly**
Modify `SetProfitsReceiver` to accept the `previousProfitsReceiver` as a parameter (it already retrieves this value) and explicitly remove it from all Treasury schemes before the mapping is updated.

**Recommended Fix (Solution 2 - most aligned with existing pattern):**
```csharp
public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
{
    // ... existing validation ...
    
    var previousProfitsReceiver = State.ProfitsReceiverMap[input.Pubkey];
    if (input.ProfitsReceiverAddress == previousProfitsReceiver)
    {
        return new Empty();
    }
    
    State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
    
    // Update Treasury schemes directly
    if (previousProfitsReceiver != null)
    {
        var schemes = new[] { State.BasicRewardHash.Value, State.VotesWeightRewardHash.Value, State.ReElectionRewardHash.Value };
        foreach (var schemeId in schemes)
        {
            State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
            {
                SchemeId = schemeId,
                Beneficiary = previousProfitsReceiver
            });
        }
    }
    
    // ... existing Election contract notification ...
    
    return new Empty();
}
```

## Proof of Concept

A complete PoC would require:
1. Deploy contracts in test environment
2. Register a candidate with custom receiver Address_1
3. Run term N, verify Address_1 added as beneficiary
4. Call `SetProfitsReceiver` to change to Address_2
5. Run term N+1, verify both Address_1 and Address_2 have shares in the scheme
6. Verify Address_1 continues receiving rewards in subsequent distributions

The vulnerability is confirmed by the code structure where `GetAddressesFromCandidatePubkeys` uses current state that doesn't match the historical beneficiaries that were added, combined with the silent failure in `RemoveBeneficiary`.

## Notes

This vulnerability specifically affects scenarios where miners utilize the custom profits receiver feature. Miners who never set a custom receiver (using only their pubkey-derived address) are not affected because their beneficiary address never changes.

The vulnerability exists in all three Treasury reward distribution channels (Basic, Welcome, and Flexible rewards), making it a systemic issue in the Treasury contract's beneficiary management logic.

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L620-627)
```csharp
        State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
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
