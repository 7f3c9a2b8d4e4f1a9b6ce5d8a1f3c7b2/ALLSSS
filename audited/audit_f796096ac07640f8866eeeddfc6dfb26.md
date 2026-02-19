# Audit Report

## Title
Fee-Free Consensus Methods Enable Resource Exhaustion DoS When Transaction Pre-Validation is Disabled

## Summary
The consensus contract marks `NextRound` and `NextTerm` methods as completely fee-free, relying solely on runtime authorization checks. When Block Producer nodes disable `EnableTransactionExecutionValidation` for performance optimization (an explicitly documented configuration option), unauthorized consensus transactions bypass pool-level validation and consume block space despite failing execution, enabling zero-cost resource exhaustion attacks.

## Finding Description

The AEDPoS consensus contract designates several critical methods including `NextRound` and `NextTerm` as fee-free by setting `IsSizeFeeFree = true` in the `GetMethodFee()` implementation. [1](#0-0) 

Authorization is enforced during transaction execution via the `PreCheck()` method, which validates that the transaction sender's public key exists in either the current or previous round's miner list. [2](#0-1) 

When unauthorized users submit these transactions, the `ProcessConsensusInformation` method calls `PreCheck()` and asserts failure with "No permission." [3](#0-2) 

The security model assumes that `TransactionExecutionValidationProvider` will perform dry-run execution before accepting transactions into the pool. However, the system explicitly documents that Block Producer nodes can disable this validation for performance optimization. [4](#0-3) 

When `EnableTransactionExecutionValidation` is false, the validation provider immediately returns true without performing any execution checks. [5](#0-4) 

Critically, the codebase contains only three `ITransactionValidationProvider` implementations: `BasicTransactionValidationProvider` (size/signature checks), `TransactionExecutionValidationProvider` (dry-run execution), and `TransactionMethodValidationProvider` (view method rejection). [6](#0-5) 

Despite a code comment referencing a "ConstrainedAEDPoSTransactionValidationProvider" that would prevent unauthorized consensus transactions from entering the pool, [7](#0-6)  no such implementation exists in the codebase.

When invalid consensus transactions execute, they fail at the authorization check and their state changes are rolled back. [8](#0-7)  However, these failed transactions are still included in blocks with `TransactionResultStatus.Failed` status, [9](#0-8)  consuming block space and counting toward the block transaction limit.

The transaction pool enforces a limit of 5120 transactions, [10](#0-9)  and each block is limited to 512 transactions. [11](#0-10)  Since the fee-free consensus methods charge zero fees, attackers can repeatedly submit invalid transactions at no cost.

## Impact Explanation

**Resource Exhaustion:** Attackers can flood Block Producer nodes with invalid consensus transactions that consume block space (up to 512 transactions per block), CPU resources for execution and authorization checks, network bandwidth for transaction propagation, and memory for pool storage.

**Legitimate Transaction Delay:** Failed consensus transactions crowd out legitimate user transactions from blocks, degrading network throughput and increasing transaction confirmation times.

**Sustained Attack Viability:** The zero-cost nature enables indefinite attacks. Unlike normal transaction spam that depletes attacker funds via fees, this attack requires no economic resources beyond minimal network connectivity.

**Severity Assessment:** Medium severity is appropriate because while the attack causes operational disruption and resource waste, it does not compromise consensus integrity, steal funds, or break protocol invariants. Legitimate miners can still execute valid consensus transactions. The attack requires Block Producers to have opted into a documented performance optimization trade-off.

## Likelihood Explanation

**Attack Feasibility:** The attack is trivially executable. Any user can construct and broadcast `NextRound` or `NextTerm` transactions. No special permissions, stake, or technical sophistication is required. An automated script can generate unlimited invalid transactions.

**Configuration Likelihood:** The vulnerability requires Block Producers to disable `EnableTransactionExecutionValidation`. The configuration documentation explicitly states "Bp Node can disable this flag to make best performance," establishing this as an expected operational decision rather than misconfiguration.

**Economic Incentive:** Block Producers are economically incentivized to maximize performance and throughput. Disabling validation that performs mock execution on every incoming transaction is a rational performance optimization, especially for high-throughput nodes.

**Network Propagation:** If only BP nodes disable validation while common nodes maintain it enabled, the attack's effectiveness is limited since invalid transactions would be rejected before reaching BP nodes. However, attackers can submit transactions directly to BP node RPC endpoints, bypassing network-level filtering.

**Detection vs Prevention:** While attacks are easily detectable through on-chain monitoring (high volume of failed consensus transactions), detection does not prevent the resource consumption. No automatic rate-limiting or mitigation mechanisms exist for fee-free methods.

**Probability Assessment:** Medium likelihood reflects that the attack requires a specific but documented and rational configuration choice, combined with trivial execution requirements and zero economic cost to attackers.

## Recommendation

Implement consensus-specific transaction validation at the pool level that checks mining permissions before accepting consensus transactions, regardless of the `EnableTransactionExecutionValidation` setting. This validation should:

1. Create a dedicated `ConsensusTransactionValidationProvider` that implements `ITransactionValidationProvider`
2. Check if the transaction targets consensus methods (`NextRound`, `NextTerm`, `UpdateValue`, `UpdateTinyBlockInformation`)
3. Query the consensus contract to verify the sender's public key is in the current or previous miner list
4. Reject unauthorized consensus transactions before they enter the pool

Alternatively, consider removing the fee-free designation for consensus methods or implementing rate-limiting specifically for fee-free methods to prevent abuse.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a Block Producer node with `EnableTransactionExecutionValidation = false` in TransactionOptions
2. Submitting a `NextRound` transaction from an unauthorized address (not in current/previous miner list)
3. Observing that the transaction enters the transaction pool successfully
4. Observing that the transaction is included in a block and executes
5. Verifying the transaction fails with "No permission" error but still consumes block space
6. Confirming zero transaction fees were charged despite consuming block resources
7. Repeating the process to demonstrate sustained attack capability at zero cost

The test would verify that unauthorized consensus transactions bypass pool validation when the feature is disabled, consume block space despite failing authorization checks during execution, and incur no transaction fees, enabling sustainable resource exhaustion attacks.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L28-28)
```csharp
        if (!PreCheck()) Assert(false, "No permission.");
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

**File:** src/AElf.Kernel.TransactionPool/TransactionOptions.cs (L8-8)
```csharp
    public int PoolLimit { get; set; } = 5120;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionOptions.cs (L16-19)
```csharp
    ///     Bp Node can disable this flag to make best performance.
    ///     But common node needs to enable it to prevent transaction flood attack
    /// </summary>
    public bool EnableTransactionExecutionValidation { get; set; } = true;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionOptions.cs (L21-21)
```csharp
    public static int BlockTransactionLimit { get; set; } = 512;
```

**File:** src/AElf.Kernel.TransactionPool/Infrastructure/TransactionExecutionValidationProvider.cs (L33-34)
```csharp
        if (!_transactionOptions.EnableTransactionExecutionValidation)
            return true;
```

**File:** src/AElf.Kernel.TransactionPool/Infrastructure/TransactionMethodValidationProvider.cs (L23-35)
```csharp
    public async Task<bool> ValidateTransactionAsync(Transaction transaction, IChainContext chainContext = null)
    {
        var isView = await _transactionReadOnlyExecutionService.IsViewTransactionAsync(chainContext, transaction);
        if (isView)
            await LocalEventBus.PublishAsync(new TransactionValidationStatusChangedEvent
            {
                TransactionId = transaction.GetHash(),
                TransactionResultStatus = TransactionResultStatus.NodeValidationFailed,
                Error = "View transaction is not allowed."
            });

        return !isView;
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L110-119)
```csharp
        if (!trace.IsSuccessful())
        {
            var transactionExecutingStateSets = new List<TransactionExecutingStateSet>();

            AddToTransactionStateSets(transactionExecutingStateSets, trace.PreTraces);
            AddToTransactionStateSets(transactionExecutingStateSets, trace.PostTraces);

            groupStateCache.Update(transactionExecutingStateSets);
            trace.SurfaceUpError();
        }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L364-367)
```csharp
        if (!trace.IsSuccessful())
        {
            // Is failed.
            txResult.Status = TransactionResultStatus.Failed;
```
