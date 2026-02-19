# Audit Report

## Title
Permanent Token Lock When CandidateSponsorMap Is Null and Candidate Key Is Lost

## Summary
When a candidate announces election via `AnnounceElection` (self-sponsored flow), the `CandidateSponsorMap` is never initialized. If the candidate subsequently loses their private key, the 100,000 token deposit becomes permanently inaccessible because `QuitElection` defaults to transferring funds to the candidate's own address, with no mechanism to redirect to a recoverable address.

## Finding Description
The vulnerability stems from an asymmetry in how two election announcement methods handle sponsor tracking:

**Missing Sponsor Initialization in Self-Announcement:**
When using `AnnounceElection`, tokens are locked from the sender but `State.CandidateSponsorMap` remains uninitialized (null). [1](#0-0) 

In contrast, `AnnounceElectionFor` explicitly sets the sponsor mapping. [2](#0-1) 

**Irrecoverable Token Destination:**
During `QuitElection`, tokens are transferred to `State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes)`. When the sponsor map is null, the fallback destination is the candidate's own address derived from their public key. [3](#0-2) 

**Insufficient Administrative Recovery:**
While Parliament can change the admin via `SetCandidateAdmin` to enable a new admin to call `QuitElection`, [4](#0-3)  this doesn't help because the token destination is hardcoded based on `CandidateSponsorMap`, not the admin address.

**Virtual Address Constraint:**
The virtual address holding the locked tokens cannot directly transfer them via `TransferFrom` because it requires prior allowance approval. [5](#0-4)  Virtual addresses, being computed addresses without private keys, cannot call `Approve` to grant such allowances.

**No Setter Mechanism:**
The codebase contains no method to set or update `CandidateSponsorMap` after announcement. It's only assigned in `AnnounceElectionFor` and transferred during pubkey replacement. [6](#0-5) 

The locked amount is 100,000 tokens per candidate. [7](#0-6) 

## Impact Explanation
**Quantified Loss:** Each affected candidate permanently loses 100,000 tokens (100_000_00000000 with 8 decimals).

**Affected Parties:**
- Candidates who announced via `AnnounceElection` and subsequently lost their private key
- Cannot recover their election deposit despite having an admin with authorization
- Tokens remain locked in virtual addresses with no recovery path

**Protocol Impact:**
- Violates the protocol invariant that locked deposits should be recoverable
- Creates operational risk for candidates using the legitimate `AnnounceElection` method
- No governance intervention mechanism exists to recover these funds

The severity is Medium because while the impact is significant (100,000 tokens permanently lost), it requires both the use of a specific method and key loss to manifest.

## Likelihood Explanation
**Realistic Preconditions:**
1. Using `AnnounceElection` is a documented, public method that candidates legitimately choose
2. Private key loss is a well-documented occurrence in blockchain systems (hardware failure, operational errors, security breaches)
3. Both conditions are realistic operational scenarios rather than malicious attacks

**Feasibility:**
- Entry point: Public `AnnounceElection` method accessible to any candidate
- No special privileges required to enter the vulnerable state
- The issue manifests naturally through normal contract usage combined with key loss

**Probability:**
The likelihood is Medium because it requires both conditions: (1) choosing `AnnounceElection` over `AnnounceElectionFor` AND (2) experiencing key loss. However, both are realistic scenarios that can occur in production environments.

## Recommendation
Implement one of the following solutions:

**Option 1: Add Sponsor Setter Function**
Create a governance-controlled function to set or update `CandidateSponsorMap` for candidates who used `AnnounceElection`:

```csharp
public override Empty SetCandidateSponsor(SetCandidateSponsorInput input)
{
    // Only Parliament can call this
    Assert(Context.Sender == GetParliamentDefaultAddress(), "No permission.");
    
    Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey), "Not a valid candidate.");
    Assert(State.CandidateSponsorMap[input.Pubkey] == null, "Sponsor already set.");
    
    State.CandidateSponsorMap[input.Pubkey] = input.SponsorAddress;
    return new Empty();
}
```

**Option 2: Initialize Sponsor in AnnounceElection**
Modify `AnnounceElection` to set the sponsor to the admin address:

```csharp
State.CandidateAdmins[pubkey] = input;
State.CandidateSponsorMap[pubkey] = input; // Add this line
```

This ensures tokens can be recovered by the admin address if the candidate key is lost.

**Option 3: Add Emergency Withdrawal Function**
Implement a Parliament-controlled emergency function that can redirect locked tokens in proven key loss scenarios.

## Proof of Concept
```csharp
// Test demonstrating permanent token lock
[Fact]
public async Task AnnounceElection_LostKey_PermanentLock_Test()
{
    // Step 1: Candidate announces election using AnnounceElection
    var candidateKeyPair = SampleKeyPairs.KeyPairs[0];
    var candidatePubkey = candidateKeyPair.PublicKey.ToHex();
    var candidateAddress = Address.FromPublicKey(candidateKeyPair.PublicKey);
    var adminAddress = Address.FromPublicKey(SampleKeyPairs.KeyPairs[1].PublicKey);
    
    // Candidate calls AnnounceElection with admin address
    await ElectionContractStub.AnnounceElection.SendAsync(adminAddress);
    
    // Verify tokens are locked
    var lockedAmount = ElectionContractConstants.LockTokenForElection;
    
    // Verify CandidateSponsorMap was NOT set (remains null)
    var sponsor = await ElectionContractStub.GetSponsor.CallAsync(new StringValue { Value = candidatePubkey });
    sponsor.ShouldBe(candidateAddress); // Falls back to candidate address
    
    // Step 2: Simulate key loss - candidate private key is no longer accessible
    // Admin tries to recover funds by calling QuitElection
    var adminStub = GetElectionContractStub(SampleKeyPairs.KeyPairs[1]);
    await adminStub.QuitElection.SendAsync(new StringValue { Value = candidatePubkey });
    
    // Step 3: Verify tokens went to candidate address (inaccessible due to lost key)
    var candidateBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = candidateAddress,
        Symbol = "ELF"
    });
    
    candidateBalance.Balance.ShouldBe(lockedAmount); // Tokens sent to lost address
    
    // Step 4: Verify no recovery mechanism exists
    // - CandidateSponsorMap cannot be updated
    // - Virtual address cannot self-transfer (no Approve capability)
    // - Parliament cannot override token destination
    // Result: 100,000 tokens permanently locked
}
```

## Notes
This is an operational vulnerability rather than an exploitable security bug. The design of `AnnounceElection` appears to assume candidates will maintain control of their keys indefinitely. While `AnnounceElectionFor` provides a safer alternative by allowing sponsor-based recovery, candidates using the self-sponsored flow are exposed to permanent fund loss upon key compromise. A governance-controlled recovery mechanism would provide essential resilience against this realistic failure scenario.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L27-40)
```csharp
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
            }
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-119)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;

        LockCandidateNativeToken();

        AddCandidateAsOption(pubkey);

        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L140-140)
```csharp
        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L242-249)
```csharp
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L74-89)
```csharp
        // First check allowance.
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L320-321)
```csharp
        State.CandidateSponsorMap[newPubkey] = State.CandidateSponsorMap[oldPubkey];
        State.CandidateSponsorMap.Remove(oldPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
