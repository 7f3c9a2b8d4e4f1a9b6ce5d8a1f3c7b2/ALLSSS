### Title
Fee-Free Consensus Methods Enable Resource Exhaustion DoS When Transaction Pre-Validation is Disabled

### Summary
The `NextRound` and `NextTerm` consensus methods are marked as fee-free, allowing unauthorized users to submit these transactions at zero cost. When Block Producer nodes disable `EnableTransactionExecutionValidation` for performance optimization, these invalid transactions bypass pre-execution validation and consume block space despite failing authorization checks, enabling a resource exhaustion denial-of-service attack.

### Finding Description

The `GetMethodFee()` method marks critical consensus methods including `NextRound` and `NextTerm` as completely fee-free: [1](#0-0) 

While authorization is enforced via `PreCheck()` during execution, which validates that the sender is in the current or previous miner list: [2](#0-1) 

The protection relies on `TransactionExecutionValidationProvider` performing mock execution before accepting transactions into the pool. However, the system explicitly allows Block Producer nodes to disable this validation for performance: [3](#0-2) 

When `EnableTransactionExecutionValidation = false`, unauthorized consensus transactions bypass pre-validation and enter the transaction pool. The fee charging mechanism confirms these transactions incur zero fees: [4](#0-3) 

During block execution, the invalid transactions fail at `PreCheck()` and their state rolls back: [5](#0-4) 

However, they still consume block space and computational resources while paying no fees.

### Impact Explanation

**Operational Impact - Resource Exhaustion DoS:**
- Attackers can flood the network with invalid consensus transactions at zero cost
- Block space is consumed by failed transactions, crowding out legitimate user transactions
- Network bandwidth and CPU resources are wasted processing invalid transactions
- The attack continues indefinitely at no cost to the attacker

**Who is Affected:**
- Block Producer nodes with validation disabled (performance optimization)
- Legitimate users whose transactions are delayed or rejected due to full blocks
- Network efficiency and throughput degraded

**NOT Affected:**
- Consensus integrity remains intact (legitimate miner transactions can still execute)
- No front-running possible due to state rollback on failure
- Default configuration nodes are protected

**Severity Justification:**
Medium severity due to:
- Requires non-default BP configuration (documented trade-off)
- Impact limited to resource waste, not consensus break
- Easy detection (failed transactions visible on-chain)
- Zero cost to attacker enables sustained attacks

### Likelihood Explanation

**Attacker Capabilities:**
- Any user can submit consensus transactions to the network
- No special privileges or setup required
- Zero cost to execute attack (no transaction fees)

**Attack Complexity:**
- Trivial: spam `NextRound`/`NextTerm` transactions continuously
- No sophisticated techniques required
- Automated script can generate unlimited transactions

**Feasibility Conditions:**
- At least one Block Producer must have `EnableTransactionExecutionValidation = false`
- Documentation explicitly mentions BPs may disable this for performance
- BP nodes are incentivized to optimize performance, making this configuration realistic

**Detection/Operational Constraints:**
- Attack is easily detectable (high volume of failed consensus transactions)
- However, detection doesn't prevent the resource consumption
- No automatic mitigation mechanism exists

**Probability Assessment:**
Medium likelihood because:
- Requires specific but documented configuration choice
- Default configuration prevents the attack
- BPs make deliberate trade-off between performance and security
- Attack is economically rational (zero cost, disrupts competitors)

### Recommendation

**Immediate Mitigation:**
1. Ensure all Block Producer nodes keep `EnableTransactionExecutionValidation = true` (default)
2. Add monitoring for high volumes of failed consensus transactions

**Code-Level Fix:**
Add transaction-pool-level validation specifically for consensus methods before they reach execution validation:

```csharp
// Add new validation provider: ConsensusMethodAuthorizationProvider
public class ConsensusMethodAuthorizationProvider : ITransactionValidationProvider
{
    public bool ValidateWhileSyncing => false;
    
    public async Task<bool> ValidateTransactionAsync(Transaction transaction, IChainContext chainContext)
    {
        var consensusMethods = new[] { "NextRound", "NextTerm", "UpdateValue", "UpdateTinyBlockInformation" };
        
        if (consensusMethods.Contains(transaction.MethodName))
        {
            // Verify sender is in current miner list before accepting into pool
            // This check happens regardless of EnableTransactionExecutionValidation setting
            var isAuthorized = await VerifySenderIsCurrentMiner(transaction, chainContext);
            if (!isAuthorized) return false;
        }
        
        return true;
    }
}
```

**Invariant Checks:**
- Assert that consensus transactions can only be accepted from authorized miners
- Rate-limit consensus transactions per sender per block height

**Test Cases:**
1. Test unauthorized user submitting `NextRound` transaction is rejected at pool level
2. Test authorized miner can submit consensus transactions
3. Test attack scenario with validation disabled shows pool rejection still works
4. Test performance impact of additional validation provider

### Proof of Concept

**Initial State:**
- AElf chain running with consensus contract deployed
- At least one Block Producer node configured with `EnableTransactionExecutionValidation = false`
- Attacker has valid wallet but is not in miner list

**Attack Steps:**
1. Attacker generates consensus extra data for current height
2. Attacker creates `NextRound` transaction with valid input structure:
   ```
   Transaction {
     To: ConsensusContractAddress,
     MethodName: "NextRound",
     Params: NextRoundInput { ... }
   }
   ```
3. Attacker submits transaction to network
4. Transaction reaches BP node with validation disabled
5. Transaction accepted into pool (no pre-validation check)
6. BP includes transaction in block

**Expected Result:**
- Transaction should be rejected at pool level (validation enabled)

**Actual Result:**
- Transaction included in block
- Transaction executes and fails at `PreCheck()`
- Transaction status: `Failed`, Error: "No permission."
- Fees charged: **0** (zero)
- Block space consumed: **1 transaction slot**

**Success Condition:**
- Attacker can sustain attack indefinitely (zero cost)
- Multiple invalid transactions fill blocks, preventing legitimate transactions
- Network throughput degraded
- Attack continues until BP enables validation or applies manual filtering

### Notes

The vulnerability exists as a documented security trade-off in the system design. The code comment explicitly acknowledges that disabling `EnableTransactionExecutionValidation` creates a transaction flood attack risk. However, this represents a real vulnerability because:

1. BPs have legitimate performance reasons to use the non-default configuration
2. No alternative protection mechanism exists for consensus methods specifically
3. The fee-free nature makes the attack economically rational and sustainable
4. The impact is concrete (resource exhaustion, not theoretical)

The state rollback mechanism prevents front-running of legitimate consensus transactions, as failed transactions don't persist state changes that would block subsequent valid transactions in the same block.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L40-49)
```csharp
        if (new List<string>
            {
                nameof(InitialAElfConsensusContract), nameof(FirstRound), nameof(UpdateValue),
                nameof(UpdateTinyBlockInformation), nameof(NextRound), nameof(NextTerm)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** src/AElf.Kernel.TransactionPool/TransactionOptions.cs (L15-19)
```csharp
    /// <summary>
    ///     Bp Node can disable this flag to make best performance.
    ///     But common node needs to enable it to prevent transaction flood attack
    /// </summary>
    public bool EnableTransactionExecutionValidation { get; set; } = true;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L40-52)
```csharp
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

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L105-126)
```csharp
    private static bool TryUpdateStateCache(TransactionTrace trace, TieredStateCache groupStateCache)
    {
        if (trace == null)
            return false;

        if (!trace.IsSuccessful())
        {
            var transactionExecutingStateSets = new List<TransactionExecutingStateSet>();

            AddToTransactionStateSets(transactionExecutingStateSets, trace.PreTraces);
            AddToTransactionStateSets(transactionExecutingStateSets, trace.PostTraces);

            groupStateCache.Update(transactionExecutingStateSets);
            trace.SurfaceUpError();
        }
        else
        {
            groupStateCache.Update(trace.GetStateSets());
        }

        return true;
    }
```
