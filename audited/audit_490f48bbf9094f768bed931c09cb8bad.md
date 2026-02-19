### Title
Unrestricted Contract Proposal Creation Enables Governance DoS Attack

### Summary
The Genesis contract's `ProposeNewContract` and `ProposeUpdateContract` methods lack access control and rate limiting, allowing any user to flood the governance system with unlimited contract proposals. Each proposal consumes a 72-hour expiration period and requires Block Producer review, enabling attackers to create a persistent backlog that delays or obscures legitimate urgent proposals such as security patches.

### Finding Description

The vulnerability exists in the contract proposal creation flow with multiple contributing factors:

**1. Missing Access Control:**
The `ProposeNewContract` method has its authorization check commented out, allowing unrestricted proposal creation. [1](#0-0) 

**2. Ineffective Rate Limiting:**
The `RegisterContractProposingData` method only prevents re-proposing proposals with identical input hashes. An attacker can bypass this by creating proposals with slightly different contract code, each generating a unique hash. [2](#0-1) 

**3. No Concurrent Proposal Limits:**
The proposal storage system uses unbounded `ConcurrentDictionary` without capacity constraints, allowing unlimited simultaneous active proposals. [3](#0-2) 

**4. Long Expiration Period:**
Each proposal has a 72-hour (259,200 seconds) expiration window. [4](#0-3) 

**5. Minimal Cost Barrier:**
Method fees are optional and not set by default. The transaction fee charging logic only applies base fees if explicitly configured via `SetMethodFee`, otherwise only minimal size fees apply. [5](#0-4) 

**Execution Path:**
1. Attacker calls `ProposeNewContract` with varying contract code
2. Each call generates unique hash via `CalculateHashFromInput` [6](#0-5) 
3. Proposal stored in `ContractProposingInputMap` with 72-hour expiration [7](#0-6) 
4. Governance proposal created in Parliament requiring BP review [8](#0-7) 
5. Process repeats indefinitely without restriction

### Impact Explanation

**Operational Governance DoS:**
- Block Producers must manually review each proposal to identify legitimate vs. malicious submissions
- Legitimate urgent proposals (security patches, critical upgrades) become buried in spam, causing delayed response to security incidents
- Governance bottleneck persists for 72 hours per spam proposal wave

**Resource Exhaustion:**
- Unbounded storage consumption in proposal tracking systems
- Parliament contract state bloat from accumulated proposal records
- Chain resource degradation from persistent spam transactions

**Severity Justification:**
This constitutes a Medium severity vulnerability because while it doesn't directly compromise funds, it can effectively disable the governance system's ability to respond to critical security issues in a timely manner. The ability to delay security patches through governance flooding represents a significant operational risk.

### Likelihood Explanation

**High Likelihood - All preconditions are met:**

**Reachable Entry Point:**
`ProposeNewContract` and `ProposeUpdateContract` are public RPC methods accessible to any user. [9](#0-8) 

**No Access Control:**
Authorization checks are explicitly disabled (commented out), confirming unrestricted access. [1](#0-0) 

**Low Attack Cost:**
- No base transaction fees configured by default for these methods
- Only minimal size fees apply per transaction
- Attacker can generate thousands of proposals with modest resources

**Simple Attack Execution:**
- Generate slight variations in contract bytecode (append random bytes)
- Call `ProposeNewContract` repeatedly with different inputs
- No sophisticated exploitation techniques required

**Detection Limitations:**
While transactions are visible on-chain, distinguishing malicious spam from legitimate proposals requires manual review of each proposal's content, which is exactly what creates the DoS condition.

### Recommendation

**1. Re-enable Access Control:**
Uncomment and implement `AssertDeploymentProposerAuthority` to restrict proposal creation to whitelisted addresses. [1](#0-0) 

**2. Implement Rate Limiting:**
Add per-address proposal limits in `RegisterContractProposingData`:
```csharp
private void RegisterContractProposingData(Hash proposedContractInputHash)
{
    // Check concurrent proposals from sender
    var activeProposals = GetActiveProposalCountForProposer(Context.Sender);
    Assert(activeProposals < MaxConcurrentProposalsPerProposer, 
        "Exceeded maximum concurrent proposals.");
    
    // Existing logic...
}
```

**3. Set Mandatory Method Fees:**
Configure substantial base fees for `ProposeNewContract` and `ProposeUpdateContract` via `SetMethodFee` during chain initialization to economically deter spam. [10](#0-9) 

**4. Add Global Proposal Cap:**
Implement maximum concurrent proposal limit in the proposal provider system to prevent unbounded storage growth.

**5. Add Test Cases:**
- Test proposal creation by non-whitelisted addresses (should fail)
- Test exceeding per-address proposal limits
- Test proposal spam resistance with fee requirements

### Proof of Concept

**Initial State:**
- Genesis contract deployed with default configuration
- No method fees set for `ProposeNewContract`
- Attacker has minimal token balance for size fees

**Attack Sequence:**

**Step 1:** Attacker generates 100 slightly different contract bytecode variations
```
contractCode1 = validContract + randomBytes(1)
contractCode2 = validContract + randomBytes(2)
...
contractCode100 = validContract + randomBytes(100)
```

**Step 2:** For each variation, call `ProposeNewContract`:
```
for i in 1 to 100:
    input = ContractDeploymentInput {
        Code: contractCode[i],
        Category: 0
    }
    GenesisContract.ProposeNewContract(input)
```

**Step 3:** Each call succeeds because:
- No access control check (line 124 commented) [1](#0-0) 
- Each unique code generates unique hash
- No per-address rate limit enforced
- Only minimal size fee charged

**Expected Result:**
All 100 proposals created successfully, each requiring BP review and consuming 72-hour expiration slots.

**Actual Result:**
100 governance proposals flood Parliament contract, creating backlog where legitimate security patch proposal submitted afterward is buried and delayed by minimum 72 hours while BPs manually triage spam.

**Success Condition:**
Legitimate proposal cannot be efficiently identified and approved within normal timeframe due to governance system saturation with spam proposals.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L122-122)
```csharp
    public override Hash ProposeNewContract(ContractDeploymentInput input)
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L124-124)
```csharp
        // AssertDeploymentProposerAuthority(Context.Sender);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L127-127)
```csharp
        var proposedContractInputHash = CalculateHashFromInput(input);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L143-165)
```csharp
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput = new CreateProposalInput
            {
                ToAddress = Context.Self,
                ContractMethodName =
                    nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.ProposeContractCodeCheck),
                Params = new ContractCodeCheckInput
                {
                    ContractInput = input.ToByteString(),
                    CodeCheckReleaseMethod = nameof(DeploySmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = input.Category,
                    IsSystemContract = false
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput.ToByteString());
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L204-215)
```csharp
    private void RegisterContractProposingData(Hash proposedContractInputHash)
    {
        var registered = State.ContractProposingInputMap[proposedContractInputHash];
        Assert(registered == null || Context.CurrentBlockTime >= registered.ExpiredTime, "Already proposed.");
        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();
        State.ContractProposingInputMap[proposedContractInputHash] = new ContractProposingInput
        {
            Proposer = Context.Sender,
            Status = ContractProposingInputStatus.Proposed,
            ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
        };
    }
```

**File:** src/AElf.Kernel.Proposal/Infrastructure/ProposalProvider.cs (L9-15)
```csharp
{
    private readonly ConcurrentDictionary<Hash, long> _proposalsToApprove = new();

    public void AddProposal(Hash proposalId, long height)
    {
        // keep the higher block index 
        _proposalsToApprove.AddOrUpdate(proposalId, height, (hash, h) => h >= height ? h : height);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L5-5)
```csharp
    public const int ContractProposalExpirationTimePeriod = 259200; // 60 * 60 * 72
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-52)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
        var fee = new Dictionary<string, long>();
        var isSizeFeeFree = false;
        if (methodFees != null)
        {
            isSizeFeeFree = methodFees.IsSizeFeeFree;
        }

        if (methodFees != null && methodFees.Fees.Any())
        {
            fee = GetBaseFeeDictionary(methodFees);
        }

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L9-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);

        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```
