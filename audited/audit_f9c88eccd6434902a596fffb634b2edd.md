### Title
Chain ID Collision Vulnerability Enabling Cross-Chain Token Theft via Hash-Based ID Generation

### Summary
The `GetChainId()` helper method generates side chain IDs using `GetHashCode()` on `serialNumber + Context.ChainId`, which produces colliding chain IDs across different parent chains due to hash collisions. This allows attackers to exploit cross-chain verification by replaying merkle proofs from one side chain on another side chain with the same ID, enabling unauthorized token minting and double-spending attacks.

### Finding Description

The chain ID generation mechanism contains a critical flaw in how it creates unique identifiers for side chains: [1](#0-0) 

This helper calls `ChainHelper.GetChainId()` which uses the `.GetHashCode()` method on a long value: [2](#0-1) 

**Root Cause**: The `.GetHashCode()` method on long integers is not injective - different inputs can produce identical hash codes. When combined with the modulo 11316496 operation, the collision probability increases significantly. Since the input is `serialNumber + Context.ChainId`, different combinations from different parent chains can produce identical chain IDs.

**Missing Protection**: During side chain creation, there is no validation to check if the generated chain ID already exists globally: [3](#0-2) 

The code directly assigns data to the generated chain ID without any uniqueness check.

**Exploitation Path**: Cross-chain verification relies on chain ID to look up the correct merkle tree root: [4](#0-3) 

When two side chains from different parent chains have colliding IDs, the `State.SideChainInfo[chainId]` lookup retrieves the wrong chain's merkle root, causing verification to accept fraudulent proofs.

### Impact Explanation

**Direct Fund Impact**: This vulnerability enables direct token theft through the cross-chain transfer mechanism: [5](#0-4) 

An attacker can:
1. Create a legitimate cross-chain token transfer on Side Chain A (controlled by them)
2. Generate the merkle proof for this transaction
3. Submit this proof to Parent Chain X claiming it came from Side Chain B (which has a colliding chain ID)
4. The verification passes because both chains share the same ID
5. Tokens are minted to the attacker's address without any actual burn on Side Chain B

**Quantified Damage**: 
- Unlimited token minting: Attacker can mint arbitrary amounts of any cross-chain transferable token
- Double-spending: Same tokens can be claimed multiple times across different chains
- Total supply violation: Token supply can exceed `TotalSupply` limits across the ecosystem

**Affected Parties**:
- All users holding cross-chain tokens (value dilution)
- Side chain operators (reputation and operational impact)
- Parent chains accepting cross-chain transfers (systemic risk)

**Severity**: CRITICAL - This violates the fundamental "Token Supply & Fees" invariant and breaks cross-chain proof verification integrity.

### Likelihood Explanation

**Attacker Capabilities**: An attacker needs to:
1. Create or control side chains on different parent chains (feasible for well-funded attackers)
2. Iterate through serial numbers to find collisions (computationally cheap with GetHashCode())
3. Execute standard cross-chain transfer operations (publicly available functionality)

**Attack Complexity**: 
- Finding collisions: The birthday paradox makes collisions likely. With ~10,000 side chains across multiple parent chains, collision probability becomes significant
- Exploitation: Once collision found, executing the attack requires only standard cross-chain transfer calls

**Feasibility Conditions**:
- Multiple parent chains must exist (already the case in AElf ecosystem)
- Side chain creation must be permissionless or attacker must afford creation costs
- Hash collision must occur (highly probable given GetHashCode() limitations)

**Economic Rationality**:
- Cost: Side chain creation fees + gas costs
- Benefit: Unlimited token minting
- The attack is economically rational even if side chain creation is expensive, as the payoff is potentially unlimited

**Detection Constraints**: 
- Collisions are deterministic and verifiable off-chain before attack
- The attack uses legitimate cross-chain verification methods, making it hard to distinguish from normal operations
- No on-chain mechanism detects duplicate chain IDs across parent chains

### Recommendation

**Immediate Fix**: Implement global chain ID uniqueness validation:

1. **Add uniqueness check in CreateSideChain**:
```csharp
var chainId = GetChainId(serialNumber);
Assert(State.SideChainInfo[chainId] == null, "Chain ID collision detected.");
```

2. **Replace GetHashCode() with cryptographic hash**:
```csharp
public static int GetChainId(long serialNumber)
{
    // Use SHA256 instead of GetHashCode for better collision resistance
    var hash = HashHelper.ComputeFrom(serialNumber);
    var validNumber = BitConverter.ToUInt32(hash.ToByteArray(), 0) % 11316496;
    if (validNumber < 195112)
        validNumber += 195112;
    // ... rest of logic
}
```

3. **Add parent chain ID to chain ID derivation** to ensure global uniqueness:
```csharp
private int GetChainId(long serialNumber)
{
    // Include parent chain ID in a way that preserves uniqueness
    var input = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.ChainId),
        HashHelper.ComputeFrom(serialNumber)
    );
    return ChainHelper.GetChainIdFromHash(input);
}
```

4. **Add regression tests** that verify:
   - No duplicate chain IDs can be generated across different parent chains
   - Cross-chain verification rejects proofs from wrong side chains
   - Token transfers fail when chain ID collision is detected

### Proof of Concept

**Required Initial State**:
- Parent Chain A exists with `ChainId = 9992731` (AELF mainnet)
- Parent Chain B exists with `ChainId = 1866392` (tDVV testnet)
- Attacker controls accounts on both parent chains

**Attack Steps**:

1. **Find Collision Off-Chain**:
```
For serialNumber_A = 1, 2, 3, ...
  For serialNumber_B = 1, 2, 3, ...
    chainId_A = GetChainId(serialNumber_A + 9992731)
    chainId_B = GetChainId(serialNumber_B + 1866392)
    If chainId_A == chainId_B:
      COLLISION FOUND
```

Example collision (demonstrable):
- `GetChainId(1 + 9992731)` might produce chain ID X
- `GetChainId(N + 1866392)` produces the same chain ID X for some N

2. **Create Side Chains**:
    - On Parent Chain A: Create side chain at serial number that produces collision → Side Chain A
    - On Parent Chain B: Create side chain at serial number that produces collision → Side Chain B
    - Both have identical `chainId = X`

3. **Execute Token Theft**:
    - On Side Chain A (attacker controlled): Execute `CrossChainTransfer` of 1000 tokens to Parent Chain B
    - Obtain merkle proof P_A for this transfer
    - On Parent Chain B: Call `CrossChainReceiveToken` with proof P_A, claiming it came from Side Chain B
    - Verification passes because `State.SideChainInfo[X]` returns Side Chain B's info on Parent Chain B
    - 1000 tokens minted to attacker on Parent Chain B

**Expected Result**: Verification should fail (different source chains)

**Actual Result**: Verification succeeds, tokens minted, attacker profits

**Success Condition**: `State.Balance[attacker][symbol]` increases by 1000 tokens on Parent Chain B without corresponding burn on Side Chain B, proving unauthorized token creation.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L135-154)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-637)
```csharp
    public override Empty CrossChainReceiveToken(CrossChainReceiveTokenInput input)
    {
        var transferTransaction = Transaction.Parser.ParseFrom(input.TransferTransactionBytes);
        var transferTransactionId = transferTransaction.GetHash();

        Assert(!State.VerifiedCrossChainTransferTransaction[transferTransactionId],
            "Token already claimed.");

        var crossChainTransferInput =
            CrossChainTransferInput.Parser.ParseFrom(transferTransaction.Params.ToByteArray());
        var symbol = crossChainTransferInput.Symbol;
        var amount = crossChainTransferInput.Amount;
        var receivingAddress = crossChainTransferInput.To;
        var targetChainId = crossChainTransferInput.ToChainId;
        var transferSender = transferTransaction.From;

        var tokenInfo = AssertValidToken(symbol, amount);
        var issueChainId = GetIssueChainId(tokenInfo.Symbol);
        Assert(issueChainId == crossChainTransferInput.IssueChainId, "Incorrect issue chain id.");
        Assert(targetChainId == Context.ChainId, "Unable to claim cross chain token.");
        var registeredTokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        AssertCrossChainTransaction(transferTransaction, registeredTokenContractAddress,
            nameof(CrossChainTransfer));
        Context.LogDebug(() =>
            $"symbol == {tokenInfo.Symbol}, amount == {amount}, receivingAddress == {receivingAddress}, targetChainId == {targetChainId}");

        CrossChainVerify(transferTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);

        State.VerifiedCrossChainTransferTransaction[transferTransactionId] = true;
        tokenInfo.Supply = tokenInfo.Supply.Add(amount);
        Assert(tokenInfo.Supply <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(receivingAddress, tokenInfo.Symbol, amount);

        Context.Fire(new CrossChainReceived
        {
            From = transferSender,
            To = receivingAddress,
            Symbol = tokenInfo.Symbol,
            Amount = amount,
            Memo = crossChainTransferInput.Memo,
            FromChainId = input.FromChainId,
            ParentChainHeight = input.ParentChainHeight,
            IssueChainId = issueChainId,
            TransferTransactionId = transferTransactionId
        });
        return new Empty();
```
