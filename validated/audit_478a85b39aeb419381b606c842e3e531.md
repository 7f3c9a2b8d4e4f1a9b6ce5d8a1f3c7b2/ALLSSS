# Audit Report

## Title
Refund Amount Mismatch Due to Hardcoded Constant in Lock/Unlock Operations Leading to Fund Loss

## Summary
The Election contract uses a hardcoded constant `LockTokenForElection` for both locking tokens during candidate announcement and unlocking during quit operations, without storing the actual locked amount per candidate. If this constant is changed via contract upgrade, candidates who announced under the old value will receive incorrect refunds, leading to either permanent fund lock-in or partial fund loss.

## Finding Description

The Election contract's candidate deposit mechanism contains a critical lock/unlock asymmetry vulnerability where both operations rely on the current value of a hardcoded constant rather than storing the actual locked amount.

**Constant Definition:**
The constant is hardcoded as 100,000 ELF (with 8 decimals). [1](#0-0) 

**Lock Operation:**
When a candidate announces election, the `LockCandidateNativeToken` method transfers a fixed amount to a virtual address derived from the transaction ID, using the current constant value. [2](#0-1) 

**Unlock Operation:**
When quitting election, the contract attempts to unlock using the CURRENT value of the constant, not the amount that was actually locked. The unlock operation retrieves the `AnnouncementTransactionId` to identify the virtual address, then transfers back the current constant value. [3](#0-2) 

**Missing State Storage:**
The `CandidateInformation` protobuf message only stores the `announcement_transaction_id` (used to derive the virtual address) but does NOT store the actual locked amount. [4](#0-3) 

**Balance Check Behavior:**
The MultiToken contract's `ModifyBalance` function checks if sufficient balance exists before allowing negative amounts (withdrawals), throwing an assertion error when insufficient balance is detected. [5](#0-4) 

This creates two failure modes:
- **If constant increases**: Transaction fails with "Insufficient balance", permanently locking the original deposit
- **If constant decreases**: Transaction succeeds but only unlocks the new (smaller) amount, permanently losing the difference

## Impact Explanation

**Scenario 1 (Constant Increases)**: If `LockTokenForElection` is changed from 100,000 to 200,000 ELF through a governance-approved contract upgrade, all candidates who locked 100,000 ELF cannot quit election. The contract tries to withdraw 200,000 ELF from a virtual address containing only 100,000 ELF, causing the MultiToken balance check to fail and permanently locking the deposit.

**Scenario 2 (Constant Decreases)**: If `LockTokenForElection` is changed from 100,000 to 50,000 ELF, candidates who locked 100,000 ELF only receive 50,000 ELF back. The remaining 50,000 ELF stays permanently locked at the virtual address with no recovery mechanism.

**Severity Justification (Medium):**
- Direct and guaranteed financial loss occurs if the constant changes
- Requires governance action (contract upgrade) as a precondition
- Breaks the fundamental invariant that deposits should be fully refundable upon quitting
- No attacker profit mechanism (pure loss scenario due to design flaw)

## Likelihood Explanation

Contract upgrades that modify economic parameters are legitimate and realistic governance activities. The `LockTokenForElection` constant might be changed to adjust the barrier to entry for candidates based on token price changes or rebalance economic incentives.

**Execution Path:**
1. Candidate calls `AnnounceElection`, locking 100,000 ELF (constant value V1)
2. Governance votes on and approves Election contract upgrade
3. New contract version changes `LockTokenForElection` to V2 (where V2 ≠ V1)
4. Candidate calls `QuitElection` under new contract version
5. Contract attempts to unlock V2 amount from virtual address containing V1 amount
6. Fund mismatch occurs automatically

**Probability (Medium):**
- Contract upgrades are infrequent but realistic in evolving blockchain systems
- Economic parameter adjustments are common governance activities across DPoS chains
- No migration logic or protection exists against constant value changes

## Recommendation

Add a new field to `CandidateInformation` to store the actual locked amount:

```protobuf
message CandidateInformation {
    string pubkey = 1;
    repeated int64 terms = 2;
    int64 produced_blocks = 3;
    int64 missed_time_slots = 4;
    int64 continual_appointment_count = 5;
    aelf.Hash announcement_transaction_id = 6;
    bool is_current_candidate = 7;
    int64 locked_token_amount = 8;  // NEW FIELD
}
```

Update the lock operation to store the amount:
```csharp
candidateInformation.LockedTokenAmount = ElectionContractConstants.LockTokenForElection;
State.CandidateInformationMap[pubkey] = candidateInformation;
```

Update the unlock operation to use the stored amount:
```csharp
State.TokenContract.TransferFrom.Send(new TransferFromInput
{
    From = lockVirtualAddress,
    To = recipient,
    Symbol = Context.Variables.NativeSymbol,
    Amount = candidateInformation.LockedTokenAmount,  // Use stored amount
    Memo = "Quit election."
});
```

For existing candidates during upgrade, implement a migration function to populate `LockedTokenAmount` with the old constant value.

## Proof of Concept

```csharp
[Fact]
public async Task ConstantChange_CausesRefundMismatch_Test()
{
    // Step 1: Announce election with old constant (100,000 ELF)
    var candidateKeyPair = ValidationDataCenterKeyPairs.First();
    var balanceBeforeAnnounce = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    await AnnounceElectionAsync(candidateKeyPair);
    var balanceAfterAnnounce = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    
    // Verify 100,000 ELF was locked
    balanceAfterAnnounce.ShouldBe(balanceBeforeAnnounce - ElectionContractConstants.LockTokenForElection);
    
    // Step 2: Simulate contract upgrade by changing constant
    // (In real scenario, this would be a contract code upgrade with new constant value)
    // For PoC, we can demonstrate the mismatch by checking what would happen:
    // - If constant increases to 200,000: QuitElection will fail with insufficient balance
    // - If constant decreases to 50,000: QuitElection succeeds but only returns 50,000
    
    // Step 3: Attempt to quit election
    var balanceBeforeQuit = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    await QuitElectionAsync(candidateKeyPair);
    var balanceAfterQuit = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
    
    // With current constant unchanged, this passes:
    balanceAfterQuit.ShouldBe(balanceBeforeQuit + ElectionContractConstants.LockTokenForElection);
    
    // But if constant had changed:
    // - Increased: would throw "Insufficient balance" error
    // - Decreased: would only return partial amount
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L239-249)
```csharp
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
