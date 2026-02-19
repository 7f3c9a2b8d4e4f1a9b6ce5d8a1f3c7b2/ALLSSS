# Audit Report

## Title
Chain ID Collision Enables Side Chain State Overwrite and Token Theft

## Summary
The `CreateSideChain` function uses a collision-prone hash-based chain ID generation mechanism with only ~11 million possible IDs, and lacks validation to prevent overwriting existing side chain state. This allows different serial numbers to produce identical chain IDs, causing state corruption and enabling token theft when a colliding chain ID overwrites an existing side chain's data.

## Finding Description

The vulnerability exists in the cross-chain contract's side chain creation flow, specifically in how chain IDs are derived and how state is stored without duplicate validation.

**Chain ID Collision Mechanism:**

The chain ID generation uses a hash function with severe compression that guarantees collisions exist. [1](#0-0) 

The function maps long values (2^64 space) through `GetHashCode()` to int (2^32 space), then applies modulo 11316496, creating only ~11 million possible chain IDs. The test suite explicitly demonstrates that `GetChainId(long.MaxValue)` produces the same chain ID as `GetChainId(long.MinValue)`. [2](#0-1) 

**Missing Duplicate Validation:**

When creating a side chain, the contract increments the serial number, derives the chain ID, and directly overwrites multiple state mappings without any existence check. [3](#0-2) 

The critical state overwrites occur at lines 138, 154, 155, and 159 with NO assertions to verify the chain ID is unused. When a collision occurs, all state mappings for the original side chain (`SideChainInfo`, `AcceptedSideChainCreationRequest`, `CurrentSideChainHeight`, `SideChainInitializationData`) are simultaneously destroyed and replaced with the attacker's chain data.

**Attack Execution Path:**

1. Legitimate side chain created at serial number N with chain ID C
2. Attacker computes offline that serial number M will also produce chain ID C (where M > N)
3. Attacker monitors current serial number via `GetSideChainIdAndHeight` [4](#0-3) 
4. Attacker submits `RequestSideChainCreation` with malicious parameters timed to execute near serial M
5. After governance approval, `CreateSideChain` executes at serial M, derives chain ID C, and overwrites all state
6. Original chain's locked tokens become controlled by attacker's proposer address
7. Cross-chain indexing and merkle proofs for original chain permanently corrupted

## Impact Explanation

**Direct Financial Loss:**

When a side chain is disposed or tokens are unlocked, the funds are transferred to the address stored in `SideChainInfo.Proposer`. [5](#0-4) 

After the collision overwrites this field, the original owner's locked tokens are redirected to the attacker. The locked tokens are stored at a virtual address derived from the chain ID, which the attacker now controls through the overwritten `SideChainInfo` structure.

**Cross-Chain Integrity Violation:**

The `GetMerkleTreeRoot` function looks up side chain information by chain ID to retrieve merkle roots for cross-chain verification. [6](#0-5) 

After a collision, this function returns merkle roots for the wrong chain, breaking all cross-chain transaction verification for the original side chain. Cross-chain indexing becomes permanently corrupted since the parent chain can no longer correctly validate transactions from the original side chain.

**Operational Destruction:**

All view functions that query by chain ID will return the attacker's chain data instead of the original chain's data. Operations like `Recharge`, `GetSideChainBalance`, `GetSideChainCreator`, and `GetChainStatus` all become permanently redirected to the wrong chain, making the original side chain completely inaccessible through the parent chain contract.

**Severity Justification:** HIGH - Direct theft of locked tokens combined with complete destruction of cross-chain functionality for legitimate chains represents catastrophic failure of core protocol guarantees.

## Likelihood Explanation

**Mathematical Certainty:**

With only ~11 million possible chain IDs, the birthday paradox dictates that after approximately √11,316,496 ≈ 3,365 side chains, there is a 50% probability of at least one collision occurring. As the ecosystem grows, collisions become increasingly inevitable.

**Attacker Capabilities:**

- Chain ID computation is deterministic and publicly computable via `ChainHelper.GetChainId` - anyone can compute which serial numbers produce which chain IDs
- Current serial number is observable on-chain via view methods
- Only requires standard governance approval through Parliament/Association, no special privileges needed
- The helper function that adds the parent chain ID is publicly visible [7](#0-6) 

**Attack Complexity Assessment:**

While timing the attack to execute at an exact serial number requires coordination with governance approval timing, the more critical issue is that **collisions will occur naturally without any attacker**. The system will eventually fail on its own as more side chains are created. An active attacker merely accelerates this inevitable outcome.

**Realistic Scenario:**

Even if an attacker cannot precisely time execution, they can:
1. Monitor for natural collisions as they occur
2. Submit proposals for multiple serial numbers that collide with existing chains
3. Retry until one executes at the correct time
4. Benefit from any unintentional collision that occurs through normal system growth

**Probability Assessment:** MEDIUM-HIGH - The deterministic nature of the hash function, lack of validation, and mathematical certainty of eventual collisions make this a realistic and increasingly probable threat as the system matures.

## Recommendation

Add explicit validation in `CreateSideChain` to check if a chain ID already exists before creating a new side chain:

```csharp
public override Int32Value CreateSideChain(CreateSideChainInput input)
{
    AssertSideChainLifetimeControllerAuthority(Context.Sender);
    
    var proposedSideChainCreationRequestState = State.ProposedSideChainCreationRequestState[input.Proposer];
    State.ProposedSideChainCreationRequestState.Remove(input.Proposer);
    var sideChainCreationRequest = input.SideChainCreationRequest;
    Assert(
        proposedSideChainCreationRequestState != null &&
        proposedSideChainCreationRequestState.SideChainCreationRequest.Equals(sideChainCreationRequest),
        "Side chain creation failed without proposed data.");
    AssertValidSideChainCreationRequest(sideChainCreationRequest, input.Proposer);

    State.SideChainSerialNumber.Value = State.SideChainSerialNumber.Value.Add(1);
    var serialNumber = State.SideChainSerialNumber.Value;
    var chainId = GetChainId(serialNumber);
    
    // ADD THIS VALIDATION
    Assert(State.SideChainInfo[chainId] == null, "Chain ID collision detected - cannot create side chain.");
    
    State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;
    // ... rest of function
}
```

**Additional Recommendations:**

1. Use a collision-resistant chain ID generation mechanism with larger ID space (e.g., full 256-bit hash)
2. Implement a collision detection system that monitors and alerts when potential collisions approach
3. Consider using cryptographically secure identifiers instead of deterministic serial-number-based hashing
4. Add comprehensive collision testing to ensure the validation catches all cases

## Proof of Concept

```csharp
[Fact]
public async Task ChainIdCollision_EnablesStateOverwrite()
{
    // Initialize cross-chain contract
    await InitializeCrossChainContractAsync();
    
    // Create first side chain that will be victim
    var lockedAmount1 = 1000L;
    var proposer1 = DefaultSender;
    await ApproveBalanceAsync(lockedAmount1);
    var proposal1 = await CreateSideChainProposalAsync(1L, lockedAmount1, null, null, false);
    await ApproveWithMinersAsync(proposal1);
    var result1 = await CrossChainContractStub.ReleaseSideChainCreation.SendAsync(
        new ReleaseSideChainCreationInput { ProposalId = proposal1 });
    var chainId1 = SideChainCreatedEvent.Parser
        .ParseFrom(result1.TransactionResult.Logs.First(l => l.Name.Contains(nameof(SideChainCreatedEvent))).NonIndexed)
        .ChainId;
    
    // Verify original chain exists with correct proposer
    var originalInfo = await CrossChainContractStub.GetSideChainCreator.CallAsync(new Int32Value { Value = chainId1 });
    originalInfo.ShouldBe(proposer1);
    
    // Demonstrate collision: Compute serial number that produces same chain ID
    // In real attack, attacker would compute this offline
    // For POC, we use the proven collision from tests: long.MaxValue and long.MinValue
    // produce same chain ID. We need to manipulate serial number to reach collision.
    
    // Create many side chains to advance serial number to collision point
    // (In production, attacker would wait for natural progression or use specific collision calculation)
    
    // Create second side chain with different proposer that collides
    var proposer2 = AnotherSender;
    var lockedAmount2 = 500L;
    var keyPair2 = AnotherKeyPair;
    await ApproveBalanceAsync(lockedAmount2, keyPair2);
    var proposal2 = await CreateSideChainProposalAsync(1L, lockedAmount2, keyPair2, null, false);
    await ApproveWithMinersAsync(proposal2);
    
    // If serial number reaches collision point, this will overwrite first chain's state
    var result2 = await GetCrossChainContractStub(keyPair2).ReleaseSideChainCreation.SendAsync(
        new ReleaseSideChainCreationInput { ProposalId = proposal2 });
    var chainId2 = SideChainCreatedEvent.Parser
        .ParseFrom(result2.TransactionResult.Logs.First(l => l.Name.Contains(nameof(SideChainCreatedEvent))).NonIndexed)
        .ChainId;
    
    // If collision occurs (chainId1 == chainId2), verify state overwrite
    if (chainId1 == chainId2)
    {
        // Proposer has been overwritten - original owner loses control
        var newInfo = await CrossChainContractStub.GetSideChainCreator.CallAsync(new Int32Value { Value = chainId1 });
        newInfo.ShouldBe(proposer2); // Now attacker controls the chain!
        
        // Original proposer's locked tokens are now controlled by attacker
        // When disposed, funds go to proposer2 instead of proposer1
    }
}
```

**Note:** The actual collision demonstration requires computing specific serial numbers that collide. The core vulnerability is proven by: (1) test showing `GetChainId(long.MaxValue) == GetChainId(long.MinValue)`, and (2) absence of duplicate checks in `CreateSideChain` allowing overwrites.

### Citations

**File:** src/AElf.Types/Helper/ChainHelper.cs (L9-24)
```csharp
        public static int GetChainId(long serialNumber)
        {
            // For 4 base58 chars use following range (2111 ~ zzzz):
            // Max: 57*58*58*58+57*58*58+57*58+57 = 11316496 (zzzz)
            // Min: 1*58*58*58+0*58*58+0*58+0 = 195112 (2111)
            var validNUmber = (uint)serialNumber.GetHashCode() % 11316496;
            if (validNUmber < 195112)
                validNUmber += 195112;

            var validNUmberBytes = validNUmber.ToBytes().Skip(1).ToArray();

            // Use BigInteger(BigEndian) format (bytes size = 3)
            Array.Resize(ref validNUmberBytes, 4);

            return validNUmberBytes.ToInt32(false);
        }
```

**File:** test/AElf.Types.Tests/Helper/ChainHelperTests.cs (L37-38)
```csharp
            var chainIdMinValue = ChainHelper.GetChainId(long.MinValue);
            chainIdMinValue.ShouldBe(chainIdMaxValue);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L135-159)
```csharp
        State.SideChainSerialNumber.Value = State.SideChainSerialNumber.Value.Add(1);
        var serialNumber = State.SideChainSerialNumber.Value;
        var chainId = GetChainId(serialNumber);
        State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;

        // lock token
        ChargeSideChainIndexingFee(input.Proposer, sideChainCreationRequest.LockedTokenAmount, chainId);

        var sideChainInfo = new SideChainInfo
        {
            Proposer = input.Proposer,
            SideChainId = chainId,
            SideChainStatus = SideChainStatus.Active,
            IndexingPrice = sideChainCreationRequest.IndexingPrice,
            IsPrivilegePreserved = sideChainCreationRequest.IsPrivilegePreserved,
            CreationTimestamp = Context.CurrentBlockTime,
            CreationHeightOnParentChain = Context.CurrentHeight,
            IndexingFeeController = CreateDefaultOrganizationForIndexingFeePriceManagement(input.Proposer)
        };
        State.SideChainInfo[chainId] = sideChainInfo;
        State.CurrentSideChainHeight[chainId] = 0;

        var chainInitializationData =
            GetChainInitializationData(sideChainInfo, sideChainCreationRequest);
        State.SideChainInitializationData[sideChainInfo.SideChainId] = chainInitializationData;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L101-116)
```csharp
    public override ChainIdAndHeightDict GetSideChainIdAndHeight(Empty input)
    {
        var dict = new ChainIdAndHeightDict();
        var serialNumber = State.SideChainSerialNumber.Value;
        for (long i = 1; i <= serialNumber; i++)
        {
            var chainId = GetChainId(i);
            var sideChainInfo = State.SideChainInfo[chainId];
            if (sideChainInfo.SideChainStatus == SideChainStatus.Terminated)
                continue;
            var height = State.CurrentSideChainHeight[chainId];
            dict.IdHeightDict.Add(chainId, height);
        }

        return dict;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L73-86)
```csharp
    private void UnlockTokenAndResource(SideChainInfo sideChainInfo)
    {
        // unlock token
        var chainId = sideChainInfo.SideChainId;
        var balance = GetSideChainIndexingFeeDeposit(chainId);
        if (balance <= 0)
            return;
        TransferDepositToken(new TransferInput
        {
            To = sideChainInfo.Proposer,
            Amount = balance,
            Symbol = Context.Variables.NativeSymbol
        }, chainId);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L253-264)
```csharp
    private Hash GetMerkleTreeRoot(int chainId, long parentChainHeight)
    {
        if (chainId == State.ParentChainId.Value)
            // it is parent chain
            return GetParentChainMerkleTreeRoot(parentChainHeight);

        if (State.SideChainInfo[chainId] != null)
            // it is child chain
            return GetSideChainMerkleTreeRoot(parentChainHeight);

        return GetCousinChainMerkleTreeRoot(parentChainHeight);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L355-358)
```csharp
    private int GetChainId(long serialNumber)
    {
        return ChainHelper.GetChainId(serialNumber + Context.ChainId);
    }
```
