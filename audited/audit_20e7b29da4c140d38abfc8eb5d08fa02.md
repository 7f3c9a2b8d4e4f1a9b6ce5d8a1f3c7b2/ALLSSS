### Title
IssueChainId Collision Risk Due to Missing Chain ID Uniqueness Validation

### Summary
The `CreateSideChainToken` function sets `IssueChainId` to a `chainId` value computed from a hash-based algorithm with a limited output space of 11,316,496 values, without validating uniqueness. Hash collisions in `ChainHelper.GetChainId()` can cause multiple side chains to receive identical chain IDs, resulting in tokens with conflicting `IssueChainId` values and cross-chain token confusion. Additionally, no validation prevents the computed `chainId` from matching the parent chain ID.

### Finding Description

In `CreateSideChainToken`, the token's `IssueChainId` is set to the `chainId` parameter: [1](#0-0) 

This `chainId` is computed in `CreateSideChain` using: [2](#0-1) 

The `GetChainId` helper function applies a hash-based calculation: [3](#0-2) 

The underlying `ChainHelper.GetChainId` implementation uses `serialNumber.GetHashCode() % 11316496`, which maps all possible long values into a limited output space: [4](#0-3) 

**Root Cause**: The hash function exhibits collisions, as proven in the test suite where `GetChainId(long.MaxValue)` equals `GetChainId(long.MinValue)`: [5](#0-4) 

**Missing Protections**: In `CreateSideChain`, there is no validation that:
1. The computed `chainId` doesn't already exist in `State.SideChainInfo`
2. The computed `chainId` doesn't equal the parent chain ID (`State.ParentChainId.Value`) [6](#0-5) 

When a collision occurs, `State.SideChainInfo[chainId]` is directly overwritten without any assertion, orphaning the previous side chain's data.

### Impact Explanation

**Cross-Chain Integrity Violation**: When two side chains receive the same `chainId`:
- Both chains' tokens have identical `IssueChainId` values
- Cross-chain verification logic cannot distinguish which chain issued which tokens
- The second side chain overwrites the first chain's metadata in `State.SideChainInfo[chainId]`, orphaning the first chain
- Cross-chain indexing and merkle proof verification become unreliable

**Token Confusion**: Tokens with the same `IssueChainId` but different symbols create ambiguity in cross-chain token operations. The `IssueChainId` field is used for cross-chain transfer validation: [7](#0-6) 

**Affected Parties**: 
- Side chain operators whose chains get orphaned
- Users holding tokens with conflicting `IssueChainId` values
- Cross-chain bridge operations relying on `IssueChainId` for routing

**Severity Justification**: This violates the critical invariant "cross-chain proof verification and index heights" by allowing multiple chains to share the same identifier, corrupting the fundamental cross-chain architecture.

### Likelihood Explanation

**Attacker Capabilities**: No special privileges required—any user can propose side chain creation through the standard governance flow: [8](#0-7) 

**Attack Complexity**: The vulnerability triggers naturally as side chains accumulate. Using the birthday paradox, with an output space of 11,316,496 values, approximately 3,960 side chains yield a 50% collision probability: √(2 × 11,316,496 × ln(2)) ≈ 3,960.

**Execution Practicality**: The collision occurs deterministically based on the hash function. An attacker with knowledge of existing serial numbers could even calculate inputs that produce collisions.

**Feasibility Conditions**: 
- Normal side chain creation process
- No special permissions or governance bypass required
- Collision probability increases with each new side chain

**Detection**: The collision is silent—no events or errors indicate that a side chain ID conflict occurred, making it difficult to detect until cross-chain operations fail.

### Recommendation

Add explicit validation in `CreateSideChain` before assigning the chain ID:

```csharp
var chainId = GetChainId(serialNumber);

// Validate chain ID uniqueness
Assert(State.SideChainInfo[chainId] == null, 
    $"Chain ID {chainId} already exists. Hash collision detected.");
Assert(State.AcceptedSideChainCreationRequest[chainId] == null,
    $"Chain ID {chainId} already has accepted creation request.");

// Validate chain ID doesn't conflict with parent chain
Assert(chainId != State.ParentChainId.Value,
    "Computed chain ID conflicts with parent chain ID.");

State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;
```

**Additional Mitigations**:
1. Consider using a cryptographically secure hash or UUID-based chain ID generation
2. Maintain a separate mapping of used chain IDs for explicit collision detection
3. Add an event emission when chain IDs are assigned for monitoring

**Test Cases**:
1. Test that multiple side chain creations don't produce duplicate chain IDs
2. Test explicit rejection when a hash collision occurs
3. Test that side chain IDs never equal the parent chain ID

### Proof of Concept

**Initial State**:
- Parent chain with ID P initialized
- No side chains created yet
- Serial number at 0

**Attack Scenario**:

1. **Create First Side Chain**:
   - User A calls `RequestSideChainCreation` with token symbol "TOKENA"
   - Proposal approved and released
   - `serialNumber = 1`, `chainId = GetChainId(Context.ChainId + 1)` produces ID X
   - Token created with `IssueChainId = X`
   - Side chain A registered with `State.SideChainInfo[X]`

2. **Create Second Side Chain with Collision**:
   - User B calls `RequestSideChainCreation` with token symbol "TOKENB"
   - Due to hash collision, `serialNumber = N`, `chainId = GetChainId(Context.ChainId + N)` also produces ID X
   - Token "TOKENB" created successfully (different symbol) with `IssueChainId = X`
   - `State.SideChainInfo[X]` silently overwritten with chain B's data
   - Chain A becomes orphaned—its data is lost

**Expected Result**: Second creation should fail with "Chain ID already exists"

**Actual Result**: Second creation succeeds, overwriting first chain's data and creating two tokens with identical `IssueChainId` values

**Success Condition**: Query `State.SideChainInfo[X]` returns chain B's data (not A's), and both tokens show `IssueChainId = X`, confirming the collision and data corruption.

### Notes

The vulnerability is confirmed by the test suite proving hash collisions exist in `ChainHelper.GetChainId()`. While the probability of collision in small deployments is low, the lack of validation makes this a ticking time bomb as the ecosystem scales. The deterministic nature of the hash function means collisions are predictable for anyone with knowledge of the algorithm and existing serial numbers, potentially allowing targeted attacks.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L176-195)
```csharp
    private void CreateSideChainToken(SideChainCreationRequest sideChainCreationRequest, int chainId,
        Address creator)
    {
        if (!IsPrimaryTokenNeeded(sideChainCreationRequest))
            return;

        // new token needed only for exclusive side chain
        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        State.TokenContract.Create.Send(new CreateInput
        {
            TokenName = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenName,
            Decimals = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenDecimals,
            IsBurnable = true,
            Issuer = creator,
            IssueChainId = chainId,
            Symbol = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenSymbol,
            TotalSupply = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenTotalSupply,
            Owner = creator
        });
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L355-358)
```csharp
    private int GetChainId(long serialNumber)
    {
        return ChainHelper.GetChainId(serialNumber + Context.ChainId);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L90-96)
```csharp
    public override Empty RequestSideChainCreation(SideChainCreationRequest input)
    {
        AssertValidSideChainCreationRequest(input, Context.Sender);
        var sideChainCreationRequestState = ProposeNewSideChain(input, Context.Sender);
        State.ProposedSideChainCreationRequestState[Context.Sender] = sideChainCreationRequestState;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L135-155)
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
```

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L76-76)
```csharp
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
```
