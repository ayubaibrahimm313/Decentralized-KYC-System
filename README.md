# 🔐 Decentralized KYC System

A blockchain-based Know Your Customer (KYC) verification system built on Stacks.

## 🎯 Features

- One-time KYC verification
- Reusable identity credentials
- Privacy-preserving verification checks
- On-chain revocation and expiration
- Multi-level verification support

## 🛠 Smart Contract Functions

### Administrative Functions
- `set-kyc-provider`: Set the main KYC provider
- `add-verifier`: Add authorized KYC verifiers
- `remove-verifier`: Remove verifier access

### Verification Functions
- `verify-identity`: Create new KYC verification
- `revoke-verification`: Revoke existing verification
- `get-kyc-status`: Check complete KYC status
- `is-verified`: Quick verification check
- `get-verification-level`: Get user's KYC level
- `is-verifier`: Check if address is authorized verifier

## 📝 Usage Example

```clarity
;; Add a verifier
(contract-call? .kyc-system add-verifier 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)

;; Verify user identity
(contract-call? .kyc-system verify-identity 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 u2 u52560)

;; Check verification status
(contract-call? .kyc-system is-verified 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
```

## 🔒 Security Considerations

- Only authorized verifiers can create/revoke verifications
- Automatic expiration after validity period
- Revocation support for compliance
- Multi-level verification for different security needs
```
