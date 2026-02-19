# Audit Report

## Title
Chain ID Collision Enables Side Chain State Overwrite and Token Theft

## Summary
The `CreateSideChain` function generates chain IDs using a hash-based algorithm that mathematically guarantees collisions, and lacks any validation to prevent creating a side chain with an existing chain ID. An attacker can pre-compute colliding serial numbers offline, obtain governance approval for a malicious side chain creation proposal, and trigger its execution at precisely the moment when the collision occurs, completely overwriting the state of an existing legitimate side chain and redirecting its locked tokens to the attacker's address.

## Finding Description

The vulnerability exists in the chain ID derivation mechanism combined with missing uniqueness validation during side chain creation.

**Chain ID Derivation Uses Collision-Prone Hash Function:**

The chain ID is computed from a serial number using `ChainHelper.GetChainId()` which applies `GetHashCode()` (mapping 2^64 long values to 2^32 int values) followed by modulo 11,316,496, creating only ~11 million possible chain IDs: [1](#0-0) 

This compression guarantees mathematical collisions exist by the pigeonhole principle. The contract's helper function adds the parent chain ID before hashing: [2](#0-1) 

**Collision Explicitly Proven in Tests:**

The test suite explicitly demonstrates that different serial numbers produce identical chain IDs (long.MinValue and long.MaxValue both produce chain ID "mR59"): [3](#0-2) 

**Missing Validation Allows State Overwrite:**

When `CreateSideChain` executes, it increments the serial number, derives the chain ID, and directly assigns to state mappings without any check that the chain ID is already in use: [4](#0-3) 

Multiple critical state mappings are overwritten at the colliding chain ID:
- `State.AcceptedSideChainCreationRequest[chainId]` (line 138)
- `State.SideChainInfo[chainId]` (line 154) - **most critical, contains Proposer field**
- `State.CurrentSideChainHeight[chainId]` (line 155)
- `State.SideChainInitializationData[chainId]` (line 159)

**Attack Execution Path:**

1. **Collision Discovery**: Attacker computes `GetChainId(M + Context.ChainId)` offline for various serial numbers M and identifies a collision with existing chain at serial number N (where M > N)

2. **Proposal Submission**: Attacker calls `RequestSideChainCreation()` with malicious parameters, creating a governance proposal

3. **Governance Approval**: Proposal goes through standard Parliament approval process (requires no special privileges beyond meeting allowance requirements)

4. **Timing Control**: Attacker monitors `State.SideChainSerialNumber` and when it reaches M-1, calls `ReleaseSideChainCreation()`: [5](#0-4) 

5. **State Overwrite Execution**: The governance contract calls `CreateSideChain()`, incrementing serial number to M and overwriting all state at the colliding chain ID

## Impact Explanation

**Direct Financial Loss - Token Theft:**

The original side chain's locked tokens are stored at a virtual address derived from the chain ID. When the state is overwritten, `SideChainInfo.Proposer` now points to the attacker's address. When the chain is later disposed, tokens are sent to this attacker-controlled address: [6](#0-5) [7](#0-6) 

The `UnlockTokenAndResource()` function sends all locked tokens at the virtual address to `sideChainInfo.Proposer`, which is now the attacker's address after the state overwrite.

**Cross-Chain Integrity Destruction:**

The `GetMerkleTreeRoot()` function returns merkle roots based on `State.SideChainInfo[chainId]`, which now points to the wrong chain: [8](#0-7) 

This causes merkle proof verification failures for the original chain's transactions, permanently breaking cross-chain message validation.

**Operational Impact:**

- Original side chain becomes completely inaccessible through parent chain contract
- All view functions return attacker's chain data for the colliding chain ID
- Recharge, indexing, and disposal operations target the wrong chain
- No recovery mechanism exists once state is overwritten

**Severity Assessment: HIGH**
- Direct theft of locked native tokens (financial loss)
- Complete destruction of legitimate side chain functionality (operational failure)
- Permanent cross-chain communication breakdown (integrity violation)
- Multiple critical state mappings simultaneously compromised
- Irreversible once executed

## Likelihood Explanation

**Attacker Capabilities:**
- Can compute collisions offline using the deterministic `GetChainId()` function
- Can observe current `SideChainSerialNumber` from on-chain state
- Can predict exact chain ID for any future serial number
- Only requires standard governance approval (no privileged access needed)

**Attack Complexity:**
- **Finding collision: TRIVIAL** - Hash function is deterministic and public; tests prove collisions exist
- **Offline computation: TRIVIAL** - Can pre-compute millions of serial numbers in minutes
- **Governance approval: MODERATE** - Standard Parliament process, must meet allowance requirements
- **Timing control: EASY** - Attacker directly calls `ReleaseSideChainCreation()` when ready, controlling exact execution moment
- **Detection: NONE** - No validation checks for duplicate chain IDs, no monitoring alerts

**Feasibility Assessment:**

Birthday paradox analysis: With ~11.3 million possible chain IDs, 50% collision probability occurs after only sqrt(11,316,496) ≈ 3,365 side chains. In a mature ecosystem with hundreds or thousands of side chains, collisions become increasingly likely even without attacker action.

The attacker controls the critical timing element: they can monitor the serial number counter and trigger `ReleaseSideChainCreation()` at exactly the right moment (when serial number reaches M-1), ensuring their chain creation executes at serial number M where the collision occurs.

**Probability Assessment: MEDIUM-HIGH**
- Collision computation is trivial and deterministic
- No cryptographic hardness prevents collision discovery
- User controls execution timing via `ReleaseSideChainCreation()`
- Attack likelihood increases as ecosystem grows
- Only barrier is governance approval, not technical prevention

## Recommendation

Implement chain ID uniqueness validation in `CreateSideChain()` before any state assignments:

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
    
    // ADD THIS VALIDATION:
    Assert(State.SideChainInfo[chainId] == null, 
        "Chain ID collision detected - chain already exists.");
    
    State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;
    // ... rest of function
}
```

Additionally, consider:
1. Using a cryptographically secure hash function with larger output space (SHA256 instead of GetHashCode)
2. Adding chain ID as explicit input parameter instead of deriving from serial number
3. Implementing a registry of used chain IDs to detect collisions early
4. Adding monitoring/alerts for chain ID reuse attempts

## Proof of Concept

```csharp
[Fact]
public async Task ChainIdCollision_AllowsStateOverwrite_Test()
{
    // Step 1: Create legitimate chain at serial number 1
    var legitimateProposer = SampleAccount.Accounts[0].Address;
    var chainCreationRequest1 = CreateSideChainCreationRequest(
        1, 10000, ByteString.CopyFromUtf8("legitimate"));
    
    await ApproveWithMinersAsync(await CreateProposalAsync(chainCreationRequest1));
    var chainId1 = (await CrossChainContractStub.ReleaseSideChainCreation.SendAsync(
        new ReleaseSideChainCreationInput { ProposalId = await GetProposalIdAsync() })).Output.Value;
    
    var originalChainInfo = await CrossChainContractStub.GetSideChainInfo.CallAsync(
        new Int32Value { Value = chainId1 });
    originalChainInfo.Proposer.ShouldBe(legitimateProposer);
    
    // Step 2: Find colliding serial number
    var currentSerial = await CrossChainContractStub.GetSideChainSerialNumber.CallAsync(new Empty());
    long collidingSerial = FindCollidingSerialNumber(chainId1, currentSerial.Value);
    
    // Step 3: Create enough chains to reach collision point
    for (long i = currentSerial.Value + 1; i < collidingSerial; i++)
    {
        var dummyRequest = CreateSideChainCreationRequest(1, 5000, ByteString.CopyFromUtf8($"dummy{i}"));
        await ApproveWithMinersAsync(await CreateProposalAsync(dummyRequest));
        await CrossChainContractStub.ReleaseSideChainCreation.SendAsync(
            new ReleaseSideChainCreationInput { ProposalId = await GetProposalIdAsync() });
    }
    
    // Step 4: Attacker creates malicious chain at collision point
    var attackerProposer = SampleAccount.Accounts[1].Address;
    var maliciousRequest = CreateSideChainCreationRequest(
        1, 5000, ByteString.CopyFromUtf8("malicious"));
    
    await ApproveWithMinersAsync(await CreateProposalAsync(maliciousRequest));
    var chainId2 = (await CrossChainContractStub.ReleaseSideChainCreation.SendAsync(
        new ReleaseSideChainCreationInput { ProposalId = await GetProposalIdAsync() })).Output.Value;
    
    // Verify collision occurred
    chainId1.ShouldBe(chainId2);
    
    // Verify state overwrite - proposer changed to attacker
    var overwrittenChainInfo = await CrossChainContractStub.GetSideChainInfo.CallAsync(
        new Int32Value { Value = chainId1 });
    overwrittenChainInfo.Proposer.ShouldBe(attackerProposer); // State overwritten!
    overwrittenChainInfo.Proposer.ShouldNotBe(legitimateProposer); // Original proposer lost
}

private long FindCollidingSerialNumber(int targetChainId, long startSerial)
{
    var parentChainId = Context.ChainId;
    for (long serial = startSerial + 1; serial < startSerial + 100000; serial++)
    {
        if (ChainHelper.GetChainId(serial + parentChainId) == targetChainId)
            return serial;
    }
    throw new Exception("No collision found in range");
}
```

**Notes:**

This vulnerability represents a critical flaw in the side chain creation mechanism where mathematical properties of the hash function combine with missing validation to enable complete state takeover attacks. The attack is particularly dangerous because:

1. It requires no special privileges beyond standard governance approval
2. The attacker has complete control over timing via `ReleaseSideChainCreation()`
3. Collisions are mathematically guaranteed to exist
4. No recovery mechanism exists once state is overwritten
5. The likelihood increases as the ecosystem matures and more side chains are created

The fix is straightforward (add uniqueness validation) but critical for preventing both intentional attacks and accidental collisions as the number of side chains grows.

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

**File:** test/AElf.Types.Tests/Helper/ChainHelperTests.cs (L29-43)
```csharp
        {
            var chainIdMaxValue = ChainHelper.GetChainId(long.MaxValue);
            var chainIdBased58MaxValue = ChainHelper.ConvertChainIdToBase58(chainIdMaxValue);
            chainIdBased58MaxValue.ShouldBe("mR59");

            var convertedChainIdMaxValue = ChainHelper.ConvertBase58ToChainId(chainIdBased58MaxValue);
            convertedChainIdMaxValue.ShouldBe(chainIdMaxValue);

            var chainIdMinValue = ChainHelper.GetChainId(long.MinValue);
            chainIdMinValue.ShouldBe(chainIdMaxValue);
            var chainIdBased58MinValue = ChainHelper.ConvertChainIdToBase58(chainIdMaxValue);
            chainIdBased58MinValue.ShouldBe(chainIdBased58MaxValue);
            var convertedChainIdMinValue = ChainHelper.ConvertBase58ToChainId(chainIdBased58MinValue);
            convertedChainIdMinValue.ShouldBe(convertedChainIdMaxValue);
        }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L98-114)
```csharp
    public override Empty ReleaseSideChainCreation(ReleaseSideChainCreationInput input)
    {
        var sideChainCreationRequest = State.ProposedSideChainCreationRequestState[Context.Sender];
        Assert(sideChainCreationRequest != null, "Release side chain creation failed.");
        if (!TryClearExpiredSideChainCreationRequestProposal(input.ProposalId, Context.Sender))
        {
            var serialNumber = State.SideChainSerialNumber.Value.Add(1);
            var chainId = GetChainId(serialNumber);
            CreateSideChainToken(sideChainCreationRequest.SideChainCreationRequest, chainId,
                sideChainCreationRequest.Proposer);
            Context.SendInline(State.SideChainLifetimeController.Value.ContractAddress,
                nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release),
                input.ProposalId);
        }

        return new Empty();
    }
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L222-242)
```csharp
    public override Int32Value DisposeSideChain(Int32Value input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var chainId = input.Value;
        var info = State.SideChainInfo[chainId];
        Assert(info != null, "Side chain not found.");
        Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");

        if (TryGetIndexingProposal(chainId, out _))
            ResetChainIndexingProposal(chainId);

        UnlockTokenAndResource(info);
        info.SideChainStatus = SideChainStatus.Terminated;
        State.SideChainInfo[chainId] = info;
        Context.Fire(new Disposed
        {
            ChainId = chainId
        });
        return new Int32Value { Value = chainId };
    }
```
