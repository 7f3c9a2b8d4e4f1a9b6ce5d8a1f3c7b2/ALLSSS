### Title
Governance Bypass via Unvalidated Controller Contract Address in Vote Weight Interest Controller

### Summary
The `ChangeVoteWeightInterestController` function fails to validate that the new controller's `ContractAddress` is a legitimate governance contract (Parliament, Association, or Referendum). An attacker who obtains initial Parliamentary approval can set the controller to a malicious contract that always passes authorization checks, enabling permanent bypass of governance requirements for critical vote weight parameter changes.

### Finding Description

The root cause is in the `CheckOrganizationExist` validation function which accepts an arbitrary contract address without verification: [1](#0-0) 

When `ChangeVoteWeightInterestController` is called, it only checks that the organization exists by calling `ValidateOrganizationExist` on the provided `ContractAddress`: [2](#0-1) 

The validation makes a cross-contract call to `authorityInfo.ContractAddress` (controlled by the attacker) without verifying this address is one of the three legitimate governance contracts. An attacker can deploy a malicious contract that implements `ValidateOrganizationExist` to always return `true`, bypassing the intended authorization model.

The only legitimate governance contracts that should be allowed are:
- Parliament: [3](#0-2) 
- Association: [4](#0-3)   
- Referendum: [5](#0-4) 

Once the malicious controller is installed, the attacker gains direct control over:
- `SetVoteWeightInterest`: [6](#0-5) 
- `SetVoteWeightProportion`: [7](#0-6) 

These functions only verify the sender matches the controller's `OwnerAddress`: [8](#0-7) 

### Impact Explanation

The compromised controller can manipulate vote weight calculations used in `GetVotesWeight`: [9](#0-8) 

**Concrete Impact:**
1. **Election Manipulation**: Attacker can inflate their own vote weight or deflate competitors' weights by modifying `VoteWeightInterestList` and `VoteWeightProportion`, directly affecting miner election outcomes
2. **Consensus Disruption**: Manipulated elections can place malicious actors as consensus miners, compromising chain security
3. **Permanent Backdoor**: Unlike requiring Parliament approval for each change, this creates persistent control that survives Parliament membership changes
4. **Governance Bypass**: Converts "requires ongoing governance approval" into "no approval needed" for critical parameters

The vulnerability violates the defense-in-depth principle by allowing a single compromised governance action to create permanent unauthorized access to critical system parameters.

### Likelihood Explanation

**Attack Complexity:** Moderate
- Requires initial Parliament approval (social engineering/governance attack)
- Attacker must deploy a malicious contract with `ValidateOrganizationExist` method
- After setup, execution is trivial (direct function calls)

**Feasibility Conditions:**
- Parliament must approve a proposal that appears legitimate but contains malicious controller address
- Realistic in complex governance environments where proposals aren't thoroughly code-reviewed
- The malicious contract address could be obfuscated or presented as a "new governance organization"

**Detection Constraints:**
- The governance proposal would show a controller change, but verifying the contract code requires technical expertise
- Once installed, subsequent unauthorized changes leave no governance trail
- Harder to detect than repeated malicious proposals

**Probability:** While requiring initial governance approval is a significant barrier, this represents a **privilege escalation vulnerability** where temporary access becomes permanent, which is a recognized security flaw pattern.

### Recommendation

**Immediate Fix:** Add validation that `ContractAddress` must be one of the three legitimate governance contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate ContractAddress is a legitimate governance contract
    var parliamentAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        authorityInfo.ContractAddress == parliamentAddress ||
        authorityInfo.ContractAddress == associationAddress ||
        authorityInfo.ContractAddress == referendumAddress,
        "Controller contract address must be Parliament, Association, or Referendum.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Test Cases:**
1. Attempt to set controller with arbitrary contract address → should fail
2. Attempt to set controller with legitimate governance contract but non-existent organization → should fail  
3. Set controller with valid governance contract and valid organization → should succeed

### Proof of Concept

**Initial State:**
- VoteWeightInterestController is set to Parliament default organization
- Attacker has deployed MaliciousContract with `ValidateOrganizationExist` always returning `true`

**Attack Steps:**
1. Attacker creates Parliament proposal calling `ChangeVoteWeightInterestController`:
   - Input: `AuthorityInfo { ContractAddress = MaliciousContract, OwnerAddress = AttackerAddress }`
   
2. Parliament approves proposal (social engineering: "updating to new governance structure")

3. Proposal executed:
   - `CheckOrganizationExist` calls `MaliciousContract.ValidateOrganizationExist(AttackerAddress)` → returns `true`
   - Controller changed to attacker's address
   
4. Attacker directly calls `SetVoteWeightInterest` with malicious parameters:
   - No Parliament approval needed
   - Manipulates vote weight calculations
   
5. In subsequent elections, attacker's votes have artificially inflated weight

**Expected Result:** Controller change should fail due to invalid contract address
**Actual Result:** Controller change succeeds, granting permanent unauthorized access

**Success Condition:** Attacker can call `SetVoteWeightInterest` without governance approval after initial setup

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_ACS1_TransactionFeeProvider.cs (L67-72)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L210-216)
```csharp
    public override Empty SetVoteWeightProportion(VoteWeightProportion input)
    {
        AssertPerformedByVoteWeightInterestController();
        Assert(input.TimeProportion > 0 && input.AmountProportion > 0, "invalid input");
        State.VoteWeightProportion.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L218-224)
```csharp
    public override Empty ChangeVoteWeightInterestController(AuthorityInfo input)
    {
        AssertPerformedByVoteWeightInterestController();
        Assert(CheckOrganizationExist(input), "Invalid authority input.");
        State.VoteWeightInterestController.Value = input;
        return new Empty();
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L573-592)
```csharp
    private long GetVotesWeight(long votesAmount, long lockTime)
    {
        var lockDays = lockTime.Div(DaySec);
        var timeAndAmountProportion = GetVoteWeightProportion();
        if (State.VoteWeightInterestList.Value == null)
            State.VoteWeightInterestList.Value = GetDefaultVoteWeightInterest();
        foreach (var instMap in State.VoteWeightInterestList.Value.VoteWeightInterestInfos)
        {
            if (lockDays > instMap.Day)
                continue;
            var initBase = 1 + (decimal)instMap.Interest / instMap.Capital;
            return ((long)(Pow(initBase, (uint)lockDays) * votesAmount)).Add(votesAmount
                .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
        }

        var maxInterestInfo = State.VoteWeightInterestList.Value.VoteWeightInterestInfos.Last();
        var maxInterestBase = 1 + (decimal)maxInterestInfo.Interest / maxInterestInfo.Capital;
        return ((long)(Pow(maxInterestBase, (uint)lockDays) * votesAmount)).Add(votesAmount
            .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
    }
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L18-19)
```csharp
    public static readonly Hash ParliamentContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Parliament");
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L32-33)
```csharp
    public static readonly Hash ReferendumContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Referendum");
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L35-36)
```csharp
    public static readonly Hash AssociationContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Association");
```
