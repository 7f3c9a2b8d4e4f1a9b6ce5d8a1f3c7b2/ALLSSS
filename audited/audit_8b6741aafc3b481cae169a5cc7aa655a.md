### Title
GetChainId Hash Collision Causes Permanent DoS on Side Chain Information Retrieval

### Summary
The `GetSideChainIdAndHeight()` function uses `ChainHelper.GetChainId()` to generate chain IDs from serial numbers, which relies on `GetHashCode()` - a non-cryptographic hash function that can produce collisions. When two different serial numbers generate the same chain ID, the dictionary `Add()` operation throws an `ArgumentException`, causing permanent failure of this critical cross-chain view function.

### Finding Description

The vulnerability exists in the chain ID generation and retrieval logic: [1](#0-0) 

The function iterates through all serial numbers and calls `GetChainId(i)` for each: [2](#0-1) 

This delegates to `ChainHelper.GetChainId()` which uses the non-cryptographic `GetHashCode()` method: [3](#0-2) 

The root cause is at line 14 where `serialNumber.GetHashCode()` is used. The `GetHashCode()` method for `long` types is NOT collision-resistant and can return identical values for different inputs. This is proven in the test suite: [4](#0-3) 

The test explicitly shows that `GetChainId(long.MinValue)` equals `GetChainId(long.MaxValue)`, confirming collisions exist.

When a collision occurs during side chain creation, the second side chain with the colliding ID overwrites the first one's state: [5](#0-4) [6](#0-5) 

There is no collision check before assigning to `State.SideChainInfo[chainId]`. When `GetSideChainIdAndHeight()` subsequently iterates through both serial numbers that produce the same chain ID, the `dict.IdHeightDict.Add(chainId, height)` operation attempts to add the same key twice, throwing an `ArgumentException`.

### Impact Explanation

**Operational Impact - DoS of Cross-Chain Infrastructure:**

1. **Permanent failure** of `GetSideChainIdAndHeight()` - once a collision occurs, this view function becomes permanently unusable, throwing an exception on every call
2. **Cascading failures** to dependent functions: [7](#0-6) [8](#0-7) 

3. **Cross-chain indexing infrastructure breakdown** - these view functions are critical for retrieving side chain indexing information used by the cross-chain system
4. **Side chain state corruption** - the first side chain's `SideChainInfo` is silently overwritten when the collision occurs during creation, losing its configuration permanently

The severity is **Medium** because while the impact is high (permanent DoS), the likelihood is constrained by governance and economic factors.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires ability to create multiple side chains through governance proposals
- Each side chain creation requires:
  - Governance approval via Parliament organization [9](#0-8) 
  - Locked token amounts [10](#0-9) 

**Attack Complexity:**
- By the birthday paradox, collisions become likely after creating ~√11,316,496 ≈ 3,365 side chains (since the hash output space is limited to ~11 million values)
- Creating thousands of side chains would require:
  - Thousands of successful governance votes
  - Enormous amounts of locked tokens
  - Significant time (each proposal has expiration periods)

**Probability Reasoning:**
- **Low but Non-Zero**: While sequential serial numbers (1, 2, 3, ...) are unlikely to collide in practical ranges, the test proves collisions exist in the hash function
- The vulnerability is **mathematically certain** to occur if enough side chains are created over the system's lifetime
- No graceful degradation or recovery mechanism exists once collision occurs

### Recommendation

**1. Use collision-resistant chain ID generation:**
Replace `GetHashCode()` with a cryptographic hash or ensure uniqueness:

```csharp
private int GetChainId(long serialNumber)
{
    // Use cryptographic hash to ensure collision resistance
    var input = HashHelper.ComputeFrom(serialNumber + Context.ChainId);
    var validNumber = (uint)BitConverter.ToInt32(input.ToByteArray(), 0) % 11316496;
    if (validNumber < 195112)
        validNumber += 195112;
    // ... rest of conversion logic
}
```

**2. Add collision detection during side chain creation:**
```csharp
var chainId = GetChainId(serialNumber);
Assert(State.SideChainInfo[chainId] == null, "Chain ID collision detected.");
```

**3. Add defensive handling in GetSideChainIdAndHeight():**
```csharp
if (dict.IdHeightDict.ContainsKey(chainId))
{
    // Log collision and skip duplicate
    continue;
}
dict.IdHeightDict.Add(chainId, height);
```

**4. Add regression test:**
Create test that verifies no collisions occur for sequential serial numbers up to reasonable limits (e.g., 10,000 side chains).

### Proof of Concept

**Initial State:**
- Parent chain initialized with ChainId = X
- Side chain serial number = 0

**Attack Sequence:**

1. **Create side chain with serial i** where `GetHashCode(i + X)` produces hash value H
2. **Create side chain with serial j** where `GetHashCode(j + X)` also produces hash value H
   - Both calls to `ChainHelper.GetChainId(i + X)` and `ChainHelper.GetChainId(j + X)` return same chain ID
   - Second creation overwrites first side chain's `SideChainInfo[chainId]`

3. **Call GetSideChainIdAndHeight():**
   - Loop processes serial i: `chainId = GetChainId(i)`, adds to dictionary successfully
   - Loop processes serial j: `chainId = GetChainId(j)` (same value), attempts `dict.IdHeightDict.Add(chainId, height)`
   
**Expected Result:** Function returns dictionary with all side chains

**Actual Result:** Function throws `System.ArgumentException: An item with the same key has already been added to the dictionary`

**Success Condition:** The function call fails permanently, breaking cross-chain information retrieval infrastructure. The test suite already demonstrates that collisions exist for `long.MinValue` and `long.MaxValue`, proving the hash function's susceptibility to collisions.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L118-128)
```csharp
    public override ChainIdAndHeightDict GetAllChainsIdAndHeight(Empty input)
    {
        var dict = GetSideChainIdAndHeight(new Empty());

        if (State.ParentChainId.Value == 0)
            return dict;
        var parentChainHeight = GetParentChainHeight(new Empty()).Value;
        Assert(parentChainHeight > AElfConstants.GenesisBlockHeight, "Invalid parent chain height");
        dict.IdHeightDict.Add(State.ParentChainId.Value, parentChainHeight);
        return dict;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L130-145)
```csharp
    public override SideChainIndexingInformationList GetSideChainIndexingInformationList(Empty input)
    {
        var sideChainIndexingInformationList = new SideChainIndexingInformationList();
        var sideChainIdAndHeightDict = GetSideChainIdAndHeight(new Empty());
        foreach (var kv in sideChainIdAndHeightDict.IdHeightDict)
        {
            var chainId = kv.Key;
            sideChainIndexingInformationList.IndexingInformationList.Add(new SideChainIndexingInformation
            {
                ChainId = chainId,
                IndexedHeight = kv.Value
            });
        }

        return sideChainIndexingInformationList;
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

**File:** test/AElf.Types.Tests/Helper/ChainHelperTests.cs (L37-38)
```csharp
            var chainIdMinValue = ChainHelper.GetChainId(long.MinValue);
            chainIdMinValue.ShouldBe(chainIdMaxValue);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L121-124)
```csharp
    public override Int32Value CreateSideChain(CreateSideChainInput input)
    {
        // side chain creation should be triggered by organization address.
        AssertSideChainLifetimeControllerAuthority(Context.Sender);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L135-137)
```csharp
        State.SideChainSerialNumber.Value = State.SideChainSerialNumber.Value.Add(1);
        var serialNumber = State.SideChainSerialNumber.Value;
        var chainId = GetChainId(serialNumber);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L141-141)
```csharp
        ChargeSideChainIndexingFee(input.Proposer, sideChainCreationRequest.LockedTokenAmount, chainId);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L154-155)
```csharp
        State.SideChainInfo[chainId] = sideChainInfo;
        State.CurrentSideChainHeight[chainId] = 0;
```
