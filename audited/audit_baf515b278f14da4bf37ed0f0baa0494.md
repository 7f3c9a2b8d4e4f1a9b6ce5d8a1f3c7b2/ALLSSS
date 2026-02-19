### Title
Missing Upper Bound Validation on Interest Parameter Enables Voting System DoS

### Summary
The `SetVoteWeightInterest()` function only validates that Interest is positive but lacks upper bound checks. [1](#0-0)  If the controller (Parliament) sets extreme Interest values, the compound interest calculation in `GetVotesWeight()` will cause decimal overflow, throwing `OverflowException` and blocking all voting attempts with long lock periods. This creates a complete denial-of-service on the voting mechanism through either malicious configuration or accidental misconfiguration.

### Finding Description

**Location**: `SetVoteWeightInterest()` in `contract/AElf.Contracts.Election/ElectionContract_Elector.cs`

**Root Cause**: The validation logic only enforces `info.Interest > 0` without an upper bound [2](#0-1) , allowing arbitrarily large Interest values to be set by the Vote Weight Interest Controller (defaulting to Parliament governance). [3](#0-2) 

**Execution Path**:
1. Controller calls `SetVoteWeightInterest()` with extreme values (e.g., Interest = 2,147,483,647, Capital = 1) [4](#0-3) 
2. Configuration is stored without bounds validation [5](#0-4) 
3. User attempts to vote via `Vote()` with long lock period (e.g., 365 days) [6](#0-5) 
4. `GetVotesWeight()` is called to calculate vote weight [7](#0-6) 
5. The calculation computes `initBase = 1 + (Interest / Capital)` resulting in astronomically large base value [8](#0-7) 
6. `Pow(initBase, lockDays)` performs repeated decimal multiplication [9](#0-8)  using the exponentiation algorithm [10](#0-9) 
7. With `CheckForOverflowUnderflow` enabled (required by contract deployment rules), [11](#0-10)  the multiplication overflows decimal capacity (max ~7.9×10^28)
8. `OverflowException` is thrown, causing transaction failure
9. All subsequent voting attempts with matching lock periods fail

**Why Existing Protections Fail**: The default values use small interest rates (e.g., Interest=1, Capital=1000 yielding 0.1% daily rate), [12](#0-11)  but the validation assumes any positive Interest is acceptable. Even moderately large ratios like Interest=1000/Capital=1 (1000% daily rate) will cause overflow for 365-day locks.

### Impact Explanation

**Harm**: Complete denial-of-service on the voting functionality, preventing users from participating in miner elections and governance.

**Affected Parties**: 
- All users attempting to vote with lock periods in the affected interest tier
- Candidates who cannot receive votes
- The entire consensus mechanism relying on staked voting

**Severity Justification**: 
- **Critical Operational Impact**: Voting is a core mechanism for AElf's AEDPoS consensus and governance system
- **Wide Scope**: Affects all voters system-wide, not isolated to specific users
- **Unrecoverable Without Governance**: Requires new Parliament proposal to fix configuration, creating circular dependency if voting is needed for governance
- **Cascading Effects**: Disrupts profit distribution via welfare scheme [13](#0-12) , candidate rankings [14](#0-13) , and consensus validator selection

Even without malicious intent, accidental misconfiguration (e.g., setting Interest=1000 instead of 1) would trigger this vulnerability.

### Likelihood Explanation

**Attacker Capabilities**: Requires control of the Vote Weight Interest Controller, which defaults to Parliament governance. [15](#0-14) 

**Attack Complexity**: Extremely low - single transaction calling `SetVoteWeightInterest()` with crafted parameters.

**Feasibility Conditions**:
- **Malicious Scenario**: If Parliament is compromised or acts maliciously
- **Accidental Scenario**: Configuration error (unit confusion, typo, copy-paste error) during legitimate parameter updates - this is the MORE LIKELY scenario

**Detection/Operational Constraints**: 
- The issue is deterministic and immediate upon voting attempts
- No economic cost barriers once controller access is obtained
- Tests only validate positive values, missing edge cases [16](#0-15) 

**Probability Reasoning**: While requiring governance control, **accidental misconfiguration is a realistic threat** separate from malicious compromise. Parliamentary governance changes are regular operational activities, and parameter validation is a defense-in-depth measure against human error. The lack of bounds checking creates unnecessary risk for a critical system parameter.

### Recommendation

**Code-Level Mitigation**:

Add maximum bound validation in `SetVoteWeightInterest()` after line 198:

```csharp
foreach (var info in input.VoteWeightInterestInfos)
{
    Assert(info.Capital > 0, "invalid input");
    Assert(info.Day > 0, "invalid input");
    Assert(info.Interest > 0, "invalid input");
    // Add upper bounds to prevent overflow in GetVotesWeight calculation
    Assert(info.Interest <= 10000, "Interest too large"); 
    Assert(info.Capital >= 100, "Capital too small");
    // Validate interest rate ratio to prevent compound overflow
    var maxRate = (decimal)info.Interest / info.Capital;
    Assert(maxRate <= 1, "Interest rate ratio cannot exceed 100%");
}
```

**Invariant Checks**:
- Interest/Capital ratio must result in safe compound calculations for maximum lock period
- For 3-year max lock (1095 days), ensure `Pow(1 + Interest/Capital, 1095)` stays within decimal bounds
- Consider implementing pre-calculation validation that tests the Pow result for max lock days

**Test Cases**:
- Test with Interest = int32.MaxValue expecting rejection
- Test with Interest = 10000, Capital = 1 expecting rejection
- Test with valid high values near boundary (Interest = 100, Capital = 10000)
- Test overflow scenario attempting vote after setting extreme values
- Test accidental misconfiguration scenarios (e.g., Interest=1000 instead of 1)

### Proof of Concept

**Initial State**: 
- Election contract deployed with default Vote Weight Interest Controller (Parliament)
- Users ready to vote with various lock periods

**Attack Sequence**:

1. **Configuration Change** (via Parliament proposal):
   ```
   Call: SetVoteWeightInterest({
     VoteWeightInterestInfos: [{
       Day: 365,
       Interest: 2147483647,  // max int32
       Capital: 1
     }]
   })
   ```
   Result: Transaction succeeds, configuration updated

2. **User Attempts Vote**:
   ```
   Call: Vote({
     CandidatePubkey: "valid_candidate",
     Amount: 10000,
     EndTimestamp: CurrentTime + 365 days
   })
   ```
   
**Expected vs Actual**:
    - **Expected**: Vote succeeds, weight calculated properly
    - **Actual**: 
  - GetVotesWeight calculates initBase = 1 + 2147483647/1 = 2147483648
  - Pow(2147483648, 365) attempts calculation
  - Decimal multiplication overflows (2147483648^365 >> 10^28)
  - OverflowException thrown
  - Transaction fails with error
  - **Result**: Complete voting DoS for all 365+ day lock periods

**Success Condition**: Any user attempting to vote with lock period ≥ 365 days receives transaction failure due to arithmetic overflow, confirming the vulnerability enables denial-of-service on the voting mechanism.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L189-208)
```csharp
    public override Empty SetVoteWeightInterest(VoteWeightInterestList input)
    {
        AssertPerformedByVoteWeightInterestController();
        Assert(input.VoteWeightInterestInfos.Count > 0, "invalid input");
        // ReSharper disable once PossibleNullReferenceException
        foreach (var info in input.VoteWeightInterestInfos)
        {
            Assert(info.Capital > 0, "invalid input");
            Assert(info.Day > 0, "invalid input");
            Assert(info.Interest > 0, "invalid input");
        }

        Assert(input.VoteWeightInterestInfos.GroupBy(x => x.Day).Count() == input.VoteWeightInterestInfos.Count,
            "repeat day input");
        var orderList = input.VoteWeightInterestInfos.OrderBy(x => x.Day).ToArray();
        input.VoteWeightInterestInfos.Clear();
        input.VoteWeightInterestInfos.AddRange(orderList);
        State.VoteWeightInterestList.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L226-252)
```csharp
    private VoteWeightInterestList GetDefaultVoteWeightInterest()
    {
        return new VoteWeightInterestList
        {
            VoteWeightInterestInfos =
            {
                new VoteWeightInterest
                {
                    Day = 365,
                    Interest = 1,
                    Capital = 1000
                },
                new VoteWeightInterest
                {
                    Day = 730,
                    Interest = 15,
                    Capital = 10000
                },
                new VoteWeightInterest
                {
                    Day = 1095,
                    Interest = 2,
                    Capital = 1000
                }
            }
        };
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L369-383)
```csharp
    private void AddBeneficiaryToVoter(long votesWeight, long lockSeconds, Hash voteId)
    {
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = votesWeight
            },
            EndPeriod = GetEndPeriod(lockSeconds),
            // one vote, one profit detail, so voteId equals to profitDetailId
            ProfitDetailId = voteId
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L385-391)
```csharp
    private void AssertPerformedByVoteWeightInterestController()
    {
        if (State.VoteWeightInterestController.Value == null)
            State.VoteWeightInterestController.Value = GetDefaultVoteWeightInterestController();

        Assert(Context.Sender == State.VoteWeightInterestController.Value.OwnerAddress, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L393-400)
```csharp
    private AuthorityInfo GetDefaultVoteWeightInterestController()
    {
        return new AuthorityInfo
        {
            ContractAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName),
            OwnerAddress = GetParliamentDefaultAddress()
        };
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L421-467)
```csharp
    public override Hash Vote(VoteMinerInput input)
    {
        // Check candidate information map instead of candidates. 
        var targetInformation = State.CandidateInformationMap[input.CandidatePubkey];
        AssertValidCandidateInformation(targetInformation);

        var electorPubkey = Context.RecoverPublicKey();

        var lockSeconds = (input.EndTimestamp - Context.CurrentBlockTime).Seconds;
        AssertValidLockSeconds(lockSeconds);

        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
        State.LockTimeMap[voteId] = lockSeconds;

        UpdateElectorInformation(electorPubkey, input.Amount, voteId);

        var candidateVotesAmount = UpdateCandidateInformation(input.CandidatePubkey, input.Amount, voteId);

        LockTokensOfVoter(input.Amount, voteId);
        TransferTokensToVoter(input.Amount);
        CallVoteContractVote(input.Amount, input.CandidatePubkey, voteId);
        AddBeneficiaryToVoter(GetVotesWeight(input.Amount, lockSeconds), lockSeconds, voteId);

        var rankingList = State.DataCentersRankingList.Value;
        if (rankingList.DataCenters.ContainsKey(input.CandidatePubkey))
        {
            rankingList.DataCenters[input.CandidatePubkey] =
                rankingList.DataCenters[input.CandidatePubkey].Add(input.Amount);
            State.DataCentersRankingList.Value = rankingList;
        }
        else
        {
            if (rankingList.DataCenters.Count < GetValidationDataCenterCount())
            {
                State.DataCentersRankingList.Value.DataCenters.Add(input.CandidatePubkey,
                    candidateVotesAmount);
                AddBeneficiary(input.CandidatePubkey);
            }
            else
            {
                TryToBecomeAValidationDataCenter(input, candidateVotesAmount, rankingList);
            }
        }

        return voteId;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L583-583)
```csharp
            var initBase = 1 + (decimal)instMap.Interest / instMap.Capital;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L584-585)
```csharp
            return ((long)(Pow(initBase, (uint)lockDays) * votesAmount)).Add(votesAmount
                .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L594-610)
```csharp
    private static decimal Pow(decimal x, uint y)
    {
        if (y == 1)
            return (long)x;
        var a = 1m;
        if (y == 0)
            return a;
        var e = new BitArray(y.ToBytes(false));
        var t = e.Count;
        for (var i = t - 1; i >= 0; --i)
        {
            a *= a;
            if (e[i]) a *= x;
        }

        return a;
    }
```

**File:** docs-sphinx/architecture/smart-contract/restrictions/project.md (L20-30)
```markdown
- It is required to enable `CheckForOverflowUnderflow` for both Release and Debug mode so that your contract will use arithmetic operators that will throw `OverflowException` if there is any overflow. This is to ensure that execution will not continue in case of an overflow in your contract and result with unpredictable output.

```xml
<PropertyGroup Condition=" '$(Configuration)' == 'Debug' ">
  <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
</PropertyGroup>

<PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
  <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
</PropertyGroup>
```
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L1290-1349)
```csharp
    public async Task Election_VoteWeightInterestSetting_With_Invalid_Input_Test()
    {
        // argument <= 0
        {
            var newSetting = new VoteWeightInterestList
            {
                VoteWeightInterestInfos =
                {
                    new VoteWeightInterest
                    {
                        Capital = 0,
                        Interest = 4,
                        Day = 0
                    }
                }
            };
            var settingRet = await ExecuteProposalForParliamentTransactionWithException(BootMinerAddress,
                ElectionContractAddress,
                nameof(ElectionContractStub.SetVoteWeightInterest), newSetting);
            settingRet.Status.ShouldBe(TransactionResultStatus.Failed);
            settingRet.Error.ShouldContain("invalid input");
        }

        // interest count == 0
        {
            var newSetting = new VoteWeightInterestList();
            var settingRet = await ExecuteProposalForParliamentTransactionWithException(BootMinerAddress,
                ElectionContractAddress,
                nameof(ElectionContractStub.SetVoteWeightInterest), newSetting);
            settingRet.Status.ShouldBe(TransactionResultStatus.Failed);
            settingRet.Error.ShouldContain("invalid input");
        }

        // repeat day
        {
            var newSetting = new VoteWeightInterestList
            {
                VoteWeightInterestInfos =
                {
                    new VoteWeightInterest
                    {
                        Capital = 1,
                        Interest = 2,
                        Day = 3
                    },
                    new VoteWeightInterest
                    {
                        Capital = 1,
                        Interest = 2,
                        Day = 3
                    }
                }
            };
            var settingRet = await ExecuteProposalForParliamentTransactionWithException(BootMinerAddress,
                ElectionContractAddress,
                nameof(ElectionContractStub.SetVoteWeightInterest), newSetting);
            settingRet.Status.ShouldBe(TransactionResultStatus.Failed);
            settingRet.Error.ShouldContain("repeat day");
        }
    }
```
