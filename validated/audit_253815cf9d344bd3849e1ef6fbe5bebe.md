# Audit Report

## Title
Refund Amount Mismatch Due to Hardcoded Constant in Lock/Unlock Operations Leading to Fund Loss

## Summary
The Election contract uses a hardcoded constant `LockTokenForElection` for both locking tokens during candidate announcement and unlocking during quit operations, without storing the actual locked amount per candidate. If this constant is changed via contract upgrade, candidates who announced under the old value will receive incorrect refunds, leading to either permanent fund lock-in or partial fund loss.

## Finding Description

The Election contract's candidate deposit mechanism contains a critical lock/unlock asymmetry vulnerability:

**Constant Definition:**
The `LockTokenForElection` constant is defined as a hardcoded value of 100,000 ELF (with 8 decimals). [1](#0-0) 

**Lock Operation:**
When a candidate announces election, the `LockCandidateNativeToken` method transfers a fixed amount to a virtual address derived from the transaction ID. The amount locked is always the current value of `ElectionContractConstants.LockTokenForElection`. [2](#0-1) 

**Unlock Operation:**
When quitting election, the contract attempts to unlock using the CURRENT value of `ElectionContractConstants.LockTokenForElection`, not the amount that was actually locked. The unlock operation retrieves the `AnnouncementTransactionId` to identify the virtual address, then transfers back the current constant value. [3](#0-2) 

**Missing State Storage:**
The `CandidateInformation` structure only stores the `announcement_transaction_id` (used to derive the virtual address) but does NOT store the actual locked amount. This means there is no record of how much was originally locked. [4](#0-3) 

**Balance Check Behavior:**
The MultiToken contract's `ModifyBalance` function checks if sufficient balance exists before allowing negative amounts (withdrawals). When `addAmount < 0` and the balance is insufficient, it asserts with an "Insufficient balance" error. [5](#0-4) 

This balance check creates two failure modes:
- **If constant increases**: Transaction fails with "Insufficient balance", permanently locking the original deposit
- **If constant decreases**: Transaction succeeds but only unlocks the new (smaller) amount, permanently losing the difference

## Impact Explanation

**Direct Financial Loss Scenarios:**

**Scenario 1 (Constant Increases)**: If `LockTokenForElection` is changed from 100,000 to 200,000 ELF through a governance-approved contract upgrade, all candidates who locked 100,000 ELF before the upgrade cannot quit election. When they attempt to quit, the contract tries to withdraw 200,000 ELF from a virtual address containing only 100,000 ELF. The MultiToken balance check fails, and their 100,000 ELF deposit becomes permanently locked with no recovery mechanism.

**Scenario 2 (Constant Decreases)**: If `LockTokenForElection` is changed from 100,000 to 50,000 ELF, candidates who locked 100,000 ELF will only receive 50,000 ELF back when quitting. The remaining 50,000 ELF stays permanently locked at the virtual address. Since the virtual address is derived from the announcement transaction ID and there is no administrative function to recover funds from arbitrary virtual addresses, these tokens are irrecoverable.

**Affected Parties:**
All candidates who announced election before a constant change are affected. In a typical blockchain election system with dozens of active candidates, this could impact millions of ELF tokens in total aggregate losses.

**Severity Justification (Medium):**
1. Direct and guaranteed financial loss occurs if the constant changes
2. Requires governance action (contract upgrade) as a precondition, not directly exploitable by attackers
3. Impact scales with number of active candidates and deposit amount
4. No attacker profit mechanism (pure loss scenario due to design flaw)
5. Breaks the fundamental invariant that deposits should be fully refundable upon quitting

## Likelihood Explanation

**Realistic Preconditions:**
Contract upgrades that modify economic parameters are legitimate and realistic governance activities. The `LockTokenForElection` constant might be changed to:
- Adjust the barrier to entry for candidates (increase/decrease based on token price)
- Align with ELF token market price changes
- Rebalance economic incentives in the election system
- Match similar parameter updates in other DPoS systems

**Execution Path:**
1. Candidate calls `AnnounceElection`, locking 100,000 ELF (constant value V1)
2. Governance votes on and approves Election contract upgrade
3. New contract version changes `LockTokenForElection` to V2 (where V2 ≠ V1)
4. Candidate calls `QuitElection` under new contract version
5. Contract attempts to unlock V2 amount from virtual address containing V1 amount
6. Fund mismatch occurs automatically: insufficient balance error (if V2 > V1) or partial refund (if V2 < V1)

**Probability (Medium):**
- Contract upgrades are infrequent but realistic in evolving blockchain systems
- Economic parameter adjustments are common governance activities across DPoS chains
- No migration logic or protection exists against constant value changes
- Impact is automatic and unavoidable once upgrade occurs for all pre-existing candidates

## Recommendation

**Store the Locked Amount Per Candidate:**

Modify the `CandidateInformation` structure to include a `locked_amount` field that stores the actual amount locked during announcement:

```protobuf
message CandidateInformation {
    string pubkey = 1;
    repeated int64 terms = 2;
    int64 produced_blocks = 3;
    int64 missed_time_slots = 4;
    int64 continual_appointment_count = 5;
    aelf.Hash announcement_transaction_id = 6;
    bool is_current_candidate = 7;
    int64 locked_amount = 8;  // Add this field
}
```

Update `LockCandidateNativeToken` to store the locked amount:

```csharp
private void LockCandidateNativeToken(string pubkey)
{
    var lockAmount = ElectionContractConstants.LockTokenForElection;
    var lockId = Context.OriginTransactionId;
    var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
    
    State.TokenContract.TransferFrom.Send(new TransferFromInput
    {
        From = Context.Sender,
        To = lockVirtualAddress,
        Symbol = Context.Variables.NativeSymbol,
        Amount = lockAmount,
        Memo = "Lock for announcing election."
    });
    
    // Store the locked amount
    var candidateInfo = State.CandidateInformationMap[pubkey];
    if (candidateInfo != null)
    {
        candidateInfo.LockedAmount = lockAmount;
        State.CandidateInformationMap[pubkey] = candidateInfo;
    }
}
```

Update `QuitElection` to use the stored amount:

```csharp
// Unlock candidate's native token using the originally locked amount
var lockId = candidateInformation.AnnouncementTransactionId;
var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
var lockedAmount = candidateInformation.LockedAmount; // Use stored amount

State.TokenContract.TransferFrom.Send(new TransferFromInput
{
    From = lockVirtualAddress,
    To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
    Symbol = Context.Variables.NativeSymbol,
    Amount = lockedAmount, // Use the amount that was actually locked
    Memo = "Quit election."
});
```

**Migration Strategy:**
For existing candidates who announced before this fix, implement a one-time migration function (callable only by Parliament) that populates the `locked_amount` field with the current constant value, or implement a fallback in `QuitElection` that uses the constant value if `locked_amount` is zero.

## Proof of Concept

The existing test demonstrates the vulnerability assumption: [6](#0-5) 

This test expects the refund to equal `ElectionContractConstants.LockTokenForElection` (the current value). If the constant changes between announcement and quitting, this test would fail, demonstrating the vulnerability.

**Conceptual PoC Flow:**
```csharp
// Step 1: Candidate announces with LockTokenForElection = 100,000 ELF
await AnnounceElectionAsync(candidateKeyPair);
var balanceAfterLock = await GetNativeTokenBalance(candidateKeyPair.PublicKey);
// Virtual address now contains 100,000 ELF

// Step 2: Simulate contract upgrade changing constant to 200,000 ELF
// (This would be done via governance upgrade in reality)

// Step 3: Candidate tries to quit
await QuitElectionAsync(candidateKeyPair);
// Expected: Transaction fails with "Insufficient balance"
// Result: 100,000 ELF permanently locked at virtual address

// Alternative Step 2: Constant changes to 50,000 ELF
// Step 3: Candidate quits successfully
// Result: Only 50,000 ELF returned, 50,000 ELF permanently locked
```

**Notes:**
This vulnerability breaks the fundamental guarantee that candidate deposits are fully refundable. The lack of amount storage combined with the use of a mutable constant for both lock and unlock operations creates a time-based inconsistency that results in guaranteed fund loss under realistic contract upgrade scenarios.

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

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L145-150)
```csharp
        // Check balances after quiting election.
        foreach (var quitCandidate in quitCandidates)
        {
            var balance = await GetNativeTokenBalance(quitCandidate.PublicKey);
            balance.ShouldBe(balancesBeforeQuiting[quitCandidate] + ElectionContractConstants.LockTokenForElection);
        }
```
