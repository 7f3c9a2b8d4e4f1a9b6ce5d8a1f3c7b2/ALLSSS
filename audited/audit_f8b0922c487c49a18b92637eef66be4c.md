### Title
Authorization Bypass in CreateScheme Allows Attacker to Pollute Victim's Manager Scheme List Causing Bounded DoS

### Summary
The `CreateScheme` function in the Profit contract lacks authorization checks to prevent setting an arbitrary address as the scheme manager. An attacker can create schemes designating a victim as the manager without the victim's consent, polluting the victim's managing scheme list up to the state size limit (~4000 schemes, 128KB). This causes bounded DoS when querying `GetManagingSchemeIds`, degrading performance for the victim and any clients processing their scheme data.

### Finding Description

**Root Cause:** The `CreateScheme` function accepts an arbitrary `input.Manager` parameter without verifying the caller's authorization to assign that manager. [1](#0-0) 

The function directly uses `input.Manager ?? Context.Sender` without asserting that `input.Manager` (when provided) equals `Context.Sender`. This allows any caller to specify any address as the scheme manager.

**Execution Path:**
1. Attacker calls `CreateScheme` with `input.Manager` set to victim's address
2. The scheme is created with the victim as manager
3. The scheme ID is added to `State.ManagingSchemeIds[victim]` without authorization check [2](#0-1) 

**Why Protections Fail:**
The function only validates the `ProfitReceivingDuePeriodCount` parameter and scheme uniqueness, but performs no authorization check on the manager field assignment. [3](#0-2) 

**Bounded by State Size Limit:**
The attack is bounded by the state size limit of 128KB. Each Hash is 32 bytes, allowing approximately 4096 schemes maximum per manager address before state writes fail. [4](#0-3) 

**View Method Returns Unbounded Data (Within Limit):**
`GetManagingSchemeIds` returns the entire `CreatedSchemeIds` list without pagination, which can contain up to ~4000 scheme IDs (128KB of data). [5](#0-4) 

### Impact Explanation

**Operational DoS Impact:**
- A victim's `GetManagingSchemeIds` query returns up to ~4000 unwanted scheme IDs (128KB)
- Clients/nodes processing this data experience degraded performance with memory and CPU overhead
- The victim's legitimate scheme management interface becomes polluted with attacker-created schemes
- Applications displaying scheme lists must process and render 4000+ entries

**Authorization Violation:**
- Victims become managers of schemes they never created or authorized
- This violates the expected invariant that users control their own manager role assignments

**Affected Parties:**
- Targeted manager addresses
- Clients/applications querying victim's schemes
- Potentially blockchain nodes serving large responses

**Severity Justification:**
Medium severity due to:
1. Clear authorization bypass (no consent required)
2. Bounded but significant DoS (128KB, ~4000 schemes)
3. Practical exploitability with reasonable cost
4. Operational degradation rather than fund loss

### Likelihood Explanation

**Attacker Capabilities:**
- Any address with sufficient ELF tokens for transaction fees
- No special permissions or trusted role required

**Attack Complexity:**
- Simple: repeatedly call `CreateScheme` with victim's address as manager
- Each call costs 10 ELF transaction fee [6](#0-5) 

**Feasibility Conditions:**
- Attack cost: ~40,000 ELF to create maximum 4000 schemes
- Smaller-scale attacks (e.g., 100-500 schemes) cost 1,000-5,000 ELF and still cause noticeable degradation
- No rate limiting or scheme creation caps per manager

**Economic Rationality:**
- Feasible for motivated attackers (e.g., competitors, griefers)
- Cost scales linearly with desired DoS impact
- Smaller attacks (hundreds of schemes) are economically practical for targeted harassment

**Detection/Mitigation:**
- Attack is publicly visible on-chain
- Victim cannot remove unwanted schemes from their manager list
- No built-in protection or reversal mechanism

### Recommendation

**Code-Level Mitigation:**
Add authorization check in `CreateScheme` to enforce that only the sender can designate themselves as manager:

```csharp
public override Hash CreateScheme(CreateSchemeInput input)
{
    ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);
    
    // Add authorization check
    Assert(input.Manager == null || input.Manager == Context.Sender, 
        "Cannot create scheme with different manager address.");
    
    // ... rest of existing code
```

**Alternative/Additional Mitigations:**
1. Add pagination to `GetManagingSchemeIds` with maximum page size
2. Add scheme creation rate limiting per manager address
3. Implement scheme removal capability for managers to clean up unwanted schemes

**Invariant to Enforce:**
Only the transaction sender can designate themselves as a scheme manager. Specifically: `scheme.Manager == Context.Sender` must hold for all newly created schemes.

**Test Cases:**
1. Test that `CreateScheme` with `input.Manager != Context.Sender` reverts
2. Test that `CreateScheme` with `input.Manager == null` defaults to `Context.Sender`
3. Test that `CreateScheme` with `input.Manager == Context.Sender` succeeds
4. Test maximum scheme creation per manager (state size limit enforcement)

### Proof of Concept

**Required Initial State:**
- Attacker has sufficient ELF tokens for transaction fees (e.g., 50,000 ELF)
- Victim has a known address on the blockchain

**Attack Sequence:**

1. **Preparation:** Attacker identifies victim's address: `victim_addr`

2. **Execute Attack Loop (4000 iterations):**
   ```
   For i = 0 to 3999:
     CreateScheme({
       Manager: victim_addr,
       ProfitReceivingDuePeriodCount: 100,
       Token: Hash(random_seed + i)  // Ensure unique scheme IDs
     })
   ```
   - Cost: 10 ELF × 4000 = 40,000 ELF total
   - Each call adds one scheme ID to `State.ManagingSchemeIds[victim_addr]`

3. **Verify Attack Success:**
   ```
   result = GetManagingSchemeIds({ Manager: victim_addr })
   assert result.SchemeIds.Count == 4000
   assert serialized_size(result) ≈ 128KB
   ```

**Expected vs Actual Result:**
- **Expected (Secure):** Only victim can create schemes where they are manager
- **Actual (Vulnerable):** Attacker successfully creates 4000 schemes with victim as manager

**Success Condition:**
- `GetManagingSchemeIds` for victim returns ~4000 scheme IDs
- Total data size approaches 128KB state limit
- Victim experiences degraded performance when querying their schemes
- Further scheme creation attempts fail due to state size limit

**Notes:**
The attack is economically feasible at smaller scales (e.g., 100-500 schemes for 1,000-5,000 ELF) which still causes noticeable operational impact while being more cost-effective for targeted harassment scenarios.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L48-59)
```csharp
        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
        else
            Assert(
                input.ProfitReceivingDuePeriodCount > 0 &&
                input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
                "Invalid profit receiving due period count.");

        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L62-71)
```csharp
        var schemeIds = State.ManagingSchemeIds[scheme.Manager];
        if (schemeIds == null)
            schemeIds = new CreatedSchemeIds
            {
                SchemeIds = { schemeId }
            };
        else
            schemeIds.SchemeIds.Add(schemeId);

        State.ManagingSchemeIds[scheme.Manager] = schemeIds;
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L42-49)
```csharp
            case nameof(CreateScheme):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
```
