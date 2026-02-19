### Title
Mining Order Manipulation via InValue Grinding in First Round of New Term

### Summary
Miners can arbitrarily choose their InValue during the first round of each new term without cryptographic binding to previous round data, allowing them to compute mining orders off-chain and select an InValue that places them in a favorable position. This breaks the randomness property of the consensus mechanism and enables predictable mining order manipulation approximately every 7 days.

### Finding Description

The vulnerability exists in the interaction between round generation, signature calculation, and validation logic:

**Root Cause**: When generating the first round of a new term, all miners are initialized with `PreviousInValue = Hash.Empty` [1](#0-0) , and the validation explicitly allows this by returning `true` when `previousInValue == Hash.Empty` [2](#0-1) .

**Why Protections Fail**: During the first round of a new term, the signature calculation skips the cryptographic binding to the previous round. The condition `!IsFirstRoundOfCurrentTerm(out _)` prevents execution of the validation and previous-round binding logic [3](#0-2) . Instead, the signature is calculated as simply `HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue)` [4](#0-3) , where both values are chosen by the miner.

**Execution Path**: The weak signature is then used to determine the miner's position in the next round via `GetAbsModulus(sigNum, minersCount) + 1` [5](#0-4) . Since a miner can compute this calculation off-chain for any InValue they choose, they can select the InValue that produces their desired mining order.

### Impact Explanation

**Concrete Harm**:
1. **Consensus Randomness Broken**: Miners can predictably choose their mining position rather than having it determined randomly, violating a fundamental security property of the AEDPoS consensus mechanism
2. **Mining Order Advantages**: Early mining positions may capture more valuable transactions and higher transaction fees; miners can also avoid being the extra block producer
3. **MEV Extraction**: Predictable mining order enables sophisticated front-running and MEV (Miner Extractable Value) attacks
4. **Coordinated Attacks**: Multiple malicious miners can coordinate their InValue selections to arrange favorable sequences

**Who Is Affected**: All network participants are affected as the integrity of the consensus mechanism is compromised. Honest users face increased transaction costs and potential front-running.

**Severity Justification**: HIGH - This directly undermines consensus integrity, a critical invariant. Terms change approximately every 604,800 seconds (7 days) [6](#0-5) , making this exploitable weekly by every miner in the network.

### Likelihood Explanation

**Attacker Capabilities**: Any valid miner in the network can execute this attack. No special privileges or compromised roles are required.

**Attack Complexity**: LOW - The attack only requires:
1. Off-chain computation to try different InValues and calculate resulting mining orders
2. Selecting the InValue that produces the desired order
3. Submitting it during the miner's time slot in the first round of a new term

**Feasibility Conditions**: 
- Attacker must be a current miner (already satisfied for the attack scenario)
- Must occur during the first round of a new term (happens weekly)
- Computational cost is negligible (basic hashing operations)

**Detection Constraints**: The attack is undetectable on-chain since any InValue is valid when `PreviousInValue = Hash.Empty`. All submitted values pass validation.

**Probability**: VERY HIGH - Every miner can exploit this during every term change (approximately weekly), with zero on-chain cost and minimal off-chain computational cost.

### Recommendation

**Code-Level Mitigation**:
1. Bind the first round's signature to unpredictable data from the previous term's final round. Instead of skipping the previous round logic entirely, use specific fields from the last round of the previous term (e.g., the final block hash or accumulated signatures).

2. Modify the signature calculation in `GetConsensusExtraDataToPublishOutValue` to include binding even for first rounds:
   - Store the last round's consensus data across term boundaries
   - Use `previousRound.CalculateSignature(derivedInValue)` where `derivedInValue` incorporates both the miner's choice AND unpredictable data from the previous term

3. Update validation logic to enforce that first-round signatures must include verifiable binding to previous term data.

**Invariant Checks to Add**:
- Assert that signatures in the first round of a new term cannot be computed solely from miner-controlled inputs
- Verify that mining order distribution across first rounds maintains expected randomness properties

**Test Cases**:
- Test that a miner cannot predict their mining order in the next round by trying different InValues
- Verify that first-round signatures depend on data the miner cannot control
- Test that mining order distribution remains statistically random across term boundaries

### Proof of Concept

**Required Initial State**:
- Network approaching end of current term (determined by `NeedToChangeTerm` returning true)
- Attacker is a valid miner in the upcoming term's miner list

**Attack Steps**:
1. Off-chain, attacker generates 10,000 random candidate InValues
2. For each candidate InValue, attacker computes:
   - `outValue = Hash(inValue)`
   - `signature = Hash(outValue + inValue)` (per line 69 logic)
   - `sigNum = signature.ToInt64()`
   - `order = Abs(sigNum % minerCount) + 1`
3. Attacker selects the InValue that produces `order = 1` (or any other desired position)
4. When the new term begins and it's the attacker's turn to mine in the first round, they submit their chosen InValue
5. The consensus contract processes their block with the attacker's chosen InValue
6. Validation passes because `PreviousInValue == Hash.Empty` returns true without checking the InValue itself
7. The weak signature is calculated and stored
8. When the next round is generated, the attacker's position is determined by their pre-computed signature, placing them in their desired mining order

**Expected vs Actual Result**:
- **Expected**: Mining order should be unpredictable and based on random values miners cannot control
- **Actual**: Attacker successfully places themselves in their desired mining position (e.g., first miner of next round)

**Success Condition**: Attacker's mining order in round 2 of the new term matches their pre-computed desired position, demonstrating successful manipulation of consensus randomness.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L35-35)
```csharp
            minerInRound.PreviousInValue = Hash.Empty;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L69-69)
```csharp
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L72-72)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** test/AElf.Contracts.Economic.TestBase/EconomicContractsTestConstants.cs (L19-19)
```csharp
    public const long PeriodSeconds = 604800;
```
