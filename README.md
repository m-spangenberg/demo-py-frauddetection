# demo-py-frauddetection

This demo explores a common fintech/e-commerce fraud scenario: referral bonus abuse. 

## Demo Conditions

- A synthetic dataset of 50,000 normal users and 2 fraud rings.
- Each fraud ring consists of 5 accounts that create fake referrals to earn bonuses.
- Fraud accounts cash out quickly after the signup bonus lands.
- The detector groups linked accounts into clusters so the output shows both risky accounts and risky rings.

## Signals

- Shared device fingerprint across multiple accounts
- Multiple accounts cashing out to the same bank account or card
- High signup velocity from the same IP or subnet
- Reused or patterned contact details
- Referral chains that collapse onto a small connected cluster
- Withdrawal or transfer shortly after receiving the bonus

## What The Script Does

- Generates 50,010 accounts in memory.
- Creates two linked fraud rings with shared devices, payout accounts, subnet activity, and fast cashout behaviour.
- Scores each account with manager-friendly reason codes.
- Builds connected clusters of linked accounts.
- Prints a ranked suspicious-account list, suspicious clusters, and simple detection metrics.

## Run It

Console output:

```bash
uv run main.py
```

## Demo Output

When run, the main script generates a synthetic population of normal customers, injects two small fraud rings, and scores each account using fraud signals. 

```log
Referral Bonus Abuse Demo
================================================================================
Accounts simulated: 50,010
Known fraud accounts: 10
High-risk threshold: 70

Detection snapshot
--------------------------------------------------------------------------------
TP=10 FP=0 TN=50000 FN=0

Top suspicious accounts
--------------------------------------------------------------------------------
fraud_1_4    score=145 label=fraud band=HIGH   payout=mule_01    device=shared_device_01    
  reasons: shared_device:4, shared_payout:5, burst_signups:4_in_30m, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:5.0h, bonus_collected
fraud_2_4    score=145 label=fraud band=HIGH   payout=mule_02    device=shared_device_02    
  reasons: shared_device:4, shared_payout:5, burst_signups:4_in_30m, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:5.0h, bonus_collected
fraud_1_2    score=125 label=fraud band=HIGH   payout=mule_01    device=shared_device_01    
  reasons: shared_device:4, shared_payout:5, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:3.0h, bonus_collected
fraud_1_3    score=125 label=fraud band=HIGH   payout=mule_01    device=shared_device_01    
  reasons: shared_device:4, shared_payout:5, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:4.0h, bonus_collected
fraud_2_2    score=125 label=fraud band=HIGH   payout=mule_02    device=shared_device_02    
  reasons: shared_device:4, shared_payout:5, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:3.0h, bonus_collected
fraud_2_3    score=125 label=fraud band=HIGH   payout=mule_02    device=shared_device_02    
  reasons: shared_device:4, shared_payout:5, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:4.0h, bonus_collected
fraud_1_1    score=115 label=fraud band=HIGH   payout=mule_01    device=shared_device_01    
  reasons: shared_device:4, shared_payout:5, phone_pattern:5, email_pattern:5, cashout_lt_24h:2.0h, bonus_collected
fraud_1_5    score=115 label=fraud band=HIGH   payout=mule_01    device=shared_device_01_backup
  reasons: shared_payout:5, burst_signups:5_in_30m, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:6.0h, bonus_collected
fraud_2_1    score=115 label=fraud band=HIGH   payout=mule_02    device=shared_device_02    
  reasons: shared_device:4, shared_payout:5, phone_pattern:5, email_pattern:5, cashout_lt_24h:2.0h, bonus_collected
fraud_2_5    score=115 label=fraud band=HIGH   payout=mule_02    device=shared_device_02_backup
  reasons: shared_payout:5, burst_signups:5_in_30m, internal_referral_chain, phone_pattern:5, email_pattern:5, cashout_lt_24h:6.0h, bonus_collected
acct_00060   score= 15 label=legit band=REVIEW payout=bank_00060 device=device_00060        
  reasons: referrer_fanout, bonus_collected
acct_00075   score= 15 label=legit band=REVIEW payout=bank_00075 device=device_00075        
  reasons: referrer_fanout, bonus_collected

Suspicious clusters
--------------------------------------------------------------------------------
cluster_3499 members=5 mean_score=125.0 known_fraud=5
  signals: bonus_collected, burst_signups, cashout_lt_24h, email_pattern, internal_referral_chain, phone_pattern, shared_device, shared_payout
  payouts: mule_01
  devices: shared_device_01, shared_device_01_backup
  sample_members: fraud_1_1, fraud_1_2, fraud_1_3, fraud_1_4, fraud_1_5
cluster_3522 members=5 mean_score=125.0 known_fraud=5
  signals: bonus_collected, burst_signups, cashout_lt_24h, email_pattern, internal_referral_chain, phone_pattern, shared_device, shared_payout
  payouts: mule_02
  devices: shared_device_02, shared_device_02_backup
  sample_members: fraud_2_1, fraud_2_2, fraud_2_3, fraud_2_4, fraud_2_5
```

The output report is a ranked list of suspicious accounts and clusters paired with user-friendly reason codes. It includes:

- A detection snapshot with true positive (TP), false positive (FP), true negative (TN), and false negative (FN) counts against the planted synthetic fraud labels.
- The 10 fraud accounts at the top of the ranked suspicious-account list.
- Two suspicious clusters representing the injected fraud rings.