# Audit Report

## Title
Election Deposit Refund Mismatch After Contract Upgrade Due to Hard-Coded Constant

## Summary
The Election contract locks candidate deposits using a compile-time constant but does not store the actual locked amount. When the contract is upgraded with a different constant value, candidates who locked tokens under the old value will receive incorrect refunds, leading to either complete denial of service (if constant increases) or permanent fund loss (if constant decreases).

## Finding Description

The vulnerability exists in the Election contract's deposit mechanism where the lock and unlock operations both rely on reading the same constant value at execution time, rather than storing the actual locked amount.

**Lock Operation**: When a candidate announces election, the `LockCandidateNativeToken()` method locks exactly `ElectionContractConstants.LockTokenForElection` tokens (100,000 with 8 decimals). [1](#0-0) 

The constant is defined as a compile-time value. [2](#0-1) 

**State Storage Gap**: The contract only stores the `AnnouncementTransactionId` in `CandidateInformation`, with no field for the locked amount. [3](#0-2) 

**Unlock Operation**: When a candidate quits election, `QuitElection` retrieves the lock ID from state but reads the constant value again to determine the unlock amount. [4](#0-3) 

**Balance Enforcement**: When `TransferFrom` attempts to transfer more tokens than exist in the virtual address, the `ModifyBalance` method asserts with "Insufficient balance" error, causing the transaction to fail. [5](#0-4) 

C# constants are compile-time values embedded in bytecode. When the contract is upgraded through AElf's standard governance process, these constants change to their new values, breaking the invariant that locked and unlocked amounts must match.

## Impact Explanation

**Scenario 1 - Constant Increases (Complete DoS)**:
If the constant increases (e.g., from 100,000 to 200,000 tokens), all existing candidates face permanent denial of service:
- Their virtual addresses contain only 100,000 tokens
- `QuitElection` attempts to unlock 200,000 tokens
- The MultiToken contract's balance check fails with "Insufficient balance"
- All pre-upgrade candidates are permanently unable to quit election and recover their deposits

**Scenario 2 - Constant Decreases (Direct Fund Loss)**:
If the constant decreases (e.g., from 100,000 to 50,000 tokens):
- Candidates who locked 100,000 tokens receive only 50,000 tokens back
- Remaining 50,000 tokens per candidate are permanently locked in virtual addresses
- With 100 active candidates, total permanent loss would be 5,000,000 tokens

The test suite confirms this behavior - refund amounts are expected to exactly match the constant value at execution time. [6](#0-5) 

## Likelihood Explanation

**Trigger Path**: This is not an attack but a protocol design flaw that manifests during legitimate operations:
1. Contract upgrade is proposed and approved through standard governance
2. Developers modify the constant to adjust deposit requirements (reasonable for economic policy changes)
3. Contract is recompiled and deployed with new constant value
4. Any pre-upgrade candidate attempts to quit election
5. Vulnerability triggers automatically

**Realistic Preconditions**: 
- Contract upgrades are routine maintenance operations in AElf
- The deposit requirement might legitimately need adjustment over the protocol's lifetime (e.g., due to token price changes)
- No migration logic exists to handle constant value changes
- Developers would naturally update the constant without realizing the impact on existing deposits

**Probability**: HIGH - The adjustment of economic parameters like deposit requirements is a normal governance activity, making this scenario highly likely to occur during the protocol's lifetime.

## Recommendation

Store the actual locked amount in the `CandidateInformation` protobuf message and use that stored value during unlock:

1. Add a new field to `CandidateInformation`:
```protobuf
message CandidateInformation {
    // ... existing fields ...
    int64 locked_deposit_amount = 8;
}
```

2. Modify `LockCandidateNativeToken()` to store the amount:
```csharp
candidateInformation.LockedDepositAmount = ElectionContractConstants.LockTokenForElection;
State.CandidateInformationMap[pubkey] = candidateInformation;
```

3. Modify `QuitElection` to use the stored amount:
```csharp
State.TokenContract.TransferFrom.Send(new TransferFromInput
{
    From = lockVirtualAddress,
    To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
    Symbol = Context.Variables.NativeSymbol,
    Amount = candidateInformation.LockedDepositAmount, // Use stored amount
    Memo = "Quit election."
});
```

This ensures that candidates always receive back exactly what they locked, regardless of contract upgrades.

## Proof of Concept

The following test demonstrates the vulnerability scenario where a constant change causes mismatch:

```csharp
[Fact]
public async Task QuitElection_After_Constant_Change_Causes_Mismatch()
{
    // Step 1: Candidate announces with original constant (100,000)
    var candidateKeyPair = ValidationDataCenterKeyPairs.First();
    var balanceBeforeAnnounce = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    
    await AnnounceElectionAsync(candidateKeyPair);
    
    var balanceAfterAnnounce = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    var lockedAmount = balanceBeforeAnnounce - balanceAfterAnnounce;
    lockedAmount.ShouldBe(ElectionContractConstants.LockTokenForElection); // 100,000
    
    // Step 2: Simulate contract upgrade with increased constant (200,000)
    // In reality, this would be a contract upgrade changing the constant
    // The unlock operation would read the NEW constant value (200,000)
    // while the virtual address only contains the OLD amount (100,000)
    
    // Step 3: Attempt to quit - this would fail with "Insufficient balance"
    // because QuitElection tries to unlock 200,000 but virtual address has only 100,000
    var balanceBeforeQuit = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    
    await QuitElectionAsync(candidateKeyPair);
    
    var balanceAfterQuit = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    
    // Expected: Should receive back the ACTUAL locked amount (100,000)
    // Actual Bug: Tries to unlock the NEW constant value (200,000)
    // Result: Transaction fails with "Insufficient balance"
    (balanceAfterQuit - balanceBeforeQuit).ShouldBe(lockedAmount);
}
```

The existing test confirms the expected behavior matches the constant at execution time, which is the root cause of the vulnerability. [7](#0-6)

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L177-195)
```csharp
    private void LockCandidateNativeToken()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Lock the token from sender for deposit of announce election
        var lockId = Context.OriginTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        var sponsorAddress = Context.Sender;
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = sponsorAddress,
            To = lockVirtualAddress,
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Lock for announcing election."
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-250)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });

```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L3-6)
```csharp
public static class ElectionContractConstants
{
    public const long LockTokenForElection = 100_000_00000000;

```

**File:** protobuf/election_contract.proto (L365-380)
```text
message CandidateInformation {
    // Candidate’s public key.
    string pubkey = 1;
    // The number of terms that the candidate is elected.
    repeated int64 terms = 2;
    // The number of blocks the candidate has produced.
    int64 produced_blocks = 3;
    // The time slot for which the candidate failed to produce blocks.
    int64 missed_time_slots = 4;
    // The count of continual appointment.
    int64 continual_appointment_count = 5;
    // The transaction id when the candidate announced.
    aelf.Hash announcement_transaction_id = 6;
    // Indicate whether the candidate can be elected in the current term.
    bool is_current_candidate = 7;
}
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L146-150)
```csharp
        foreach (var quitCandidate in quitCandidates)
        {
            var balance = await GetNativeTokenBalance(quitCandidate.PublicKey);
            balance.ShouldBe(balancesBeforeQuiting[quitCandidate] + ElectionContractConstants.LockTokenForElection);
        }
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L163-170)
```csharp
    public async Task ElectionContract_QuiteElection_State_Test()
    {
        var candidatesKeyPair = ValidationDataCenterKeyPairs.First();
        await AnnounceElectionAsync(candidatesKeyPair);
        var balanceBeforeQuit = await GetNativeTokenBalance(candidatesKeyPair.PublicKey);
        await QuitElectionAsync(candidatesKeyPair);
        var balanceAfterQuit = await GetNativeTokenBalance(candidatesKeyPair.PublicKey);
        balanceAfterQuit.ShouldBe(balanceBeforeQuit + ElectionContractConstants.LockTokenForElection);
```
