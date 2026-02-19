### Title
Secret Sharing Reveal Blocked by Incorrect Threshold Check - Byzantine Fault Tolerance Broken

### Summary
The `RevealSharedInValues()` function requires 100% of miners to provide decrypted pieces (line 36) before revealing InValues, but Shamir's Secret Sharing algorithm only needs 2/3 threshold (minimumCount). This allows even a single malicious miner to block all InValue reveals by refusing to submit decrypted pieces, defeating the Byzantine fault tolerance that the secret sharing mechanism was designed to provide.

### Finding Description
The vulnerability exists in two locations with identical logic: [1](#0-0) [2](#0-1) 

**Root Cause:**
Line 35 correctly checks `EncryptedPieces.Count < minimumCount` where `minimumCount = minersCount * 2 / 3`, but line 36 incorrectly checks `DecryptedPieces.Count < minersCount` (100% of all miners). The actual cryptographic operation uses only the 2/3 threshold: [3](#0-2) [4](#0-3) 

**Why Protections Fail:**
The secret sharing mechanism populates DecryptedPieces through other miners' submissions: [5](#0-4) 

A miner's `DecryptedPieces` count depends entirely on whether OTHER miners include that miner's pieces in their `UpdateValueInput.decrypted_pieces` map. The 100% requirement means ALL miners must cooperate, contradicting the 2/3 Byzantine fault tolerance design.

**Execution Path:**
1. Round N: MinerA provides encrypted pieces (stored in MinerA.EncryptedPieces)
2. Round N+1: Other miners should decrypt and submit via UpdateValueInput.decrypted_pieces
3. These get added to MinerA.DecryptedPieces by PerformSecretSharing
4. RevealSharedInValues checks if DecryptedPieces.Count >= minersCount (100%)
5. If any miner withholds their decryption, the check fails and MinerA's InValue is never revealed

### Impact Explanation
**Consensus Integrity Impact:**
- Breaks the Byzantine fault tolerance of Shamir's Secret Sharing - the entire purpose of using a 2/3 threshold is to tolerate up to 1/3 malicious/offline nodes
- Single point of failure: Even ONE miner refusing to provide decrypted pieces blocks ALL reveals (in a 10-miner network, need all 10 instead of just 7)
- Selective censorship: Malicious miners can strategically block specific miners' InValue reveals

**Who is Affected:**
All miners relying on the secret sharing mechanism to reveal their PreviousInValue. While miners can voluntarily provide their PreviousInValue directly: [6](#0-5) 

The comment "It is permissible for miners not publish their in values" indicates the secret sharing should serve as an automatic fallback. With this bug, that fallback is broken.

**Severity Justification:**
Medium severity - while the system has fallback mechanisms (direct reveals, SupplyCurrentRoundInformation), the core security property of Byzantine fault-tolerant secret recovery is completely defeated. This could enable manipulation of consensus randomness by selectively blocking reveals.

### Likelihood Explanation
**Attacker Capabilities:**
Any active miner can execute this attack by simply omitting entries from the `decrypted_pieces` map in their UpdateValueInput.

**Attack Complexity:**
Trivial - requires no special capabilities beyond being a miner. The attacker merely excludes specific keys from their submission: [7](#0-6) 

**Feasibility Conditions:**
- Attacker is an active miner (realistic - 1/N probability)
- Secret sharing is enabled via configuration
- No cost or penalty for not providing decrypted pieces
- Can be executed selectively against specific targets

**Detection/Operational Constraints:**
Difficult to distinguish malicious withholding from legitimate node failures or network issues. The behavior appears identical to a miner simply not participating.

**Probability Reasoning:**
High likelihood given the ease of execution and lack of penalties. A single malicious miner can disrupt the entire reveal mechanism.

### Recommendation
**Code-Level Mitigation:**
Change line 36 in both files from:
```
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```
to:
```
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This aligns the verification threshold with the cryptographic requirement of Shamir's Secret Sharing.

**Affected Files:**
1. contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs:36
2. src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs:162

**Invariant Checks:**
- Verify that DecryptedPieces.Count >= minimumCount before calling DecodeSecret
- Ensure the threshold check matches the DecodeSecret parameter: [8](#0-7) 

**Test Cases:**
- Test reveal with exactly minimumCount (2/3) decrypted pieces - should succeed
- Test reveal with minimumCount-1 pieces - should fail  
- Test reveal with > minimumCount but < minersCount pieces - should succeed (currently fails)
- Test Byzantine scenario: 1/3 miners offline/malicious, 2/3 provide pieces - should succeed

### Proof of Concept
**Initial State:**
- 10 active miners in current round
- minimumCount = 10 * 2 / 3 = 6
- MinerA in previous round provided 7 encrypted pieces (passes line 35 check)

**Attack Sequence:**
1. Round N: MinerA produces block with 7 encrypted pieces in UpdateValueInput.encrypted_pieces
2. These are stored in previousRound.RealTimeMinersInformation[MinerA].EncryptedPieces (count = 7)
3. Round N+1: 8 out of 10 miners include MinerA's decrypted piece in their UpdateValueInput.decrypted_pieces
4. previousRound.RealTimeMinersInformation[MinerA].DecryptedPieces now has count = 8
5. 2 malicious miners deliberately exclude MinerA from their decrypted_pieces
6. When RevealSharedInValues executes:
   - Line 35: 7 >= 6 (minimumCount) ✓ passes
   - Line 36: 8 < 10 (minersCount) ✗ fails
   - `continue` statement skips the reveal
7. MinerA's PreviousInValue is never set via secret sharing

**Expected Result:**
Since 8 > 6 (minimumCount), DecodeSecret has sufficient pieces to reconstruct the secret. The reveal should succeed.

**Actual Result:**
The reveal is blocked because 8 < 10 (minersCount), even though cryptographically sufficient pieces exist.

**Success Condition:**
After fix, with 8 decrypted pieces available, MinerA's PreviousInValue should be successfully revealed and set at line 52, enabling proper consensus operation with Byzantine fault tolerance.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-36)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L161-162)
```csharp
            if (minerInRound.EncryptedPieces.Count < minimumCount) continue;
            if (minerInRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-48)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-293)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** protobuf/aedpos_contract.proto (L194-212)
```text
message UpdateValueInput {
    // Calculated from current in value.
    aelf.Hash out_value = 1;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
    // Publish previous in value for validation previous signature and previous out value.
    aelf.Hash previous_in_value = 4;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    google.protobuf.Timestamp actual_mining_time = 5;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 8;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 9;
```
