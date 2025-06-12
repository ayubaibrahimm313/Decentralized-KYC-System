(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-VERIFIED (err u101))
(define-constant ERR-NOT-VERIFIED (err u102))
(define-constant ERR-EXPIRED (err u103))
(define-constant ERR-INVALID-STATUS (err u104))
(define-constant ERR-INVALID-LEVEL (err u105))
(define-constant ERR-INVALID-PERIOD (err u106))
(define-constant ERR-SELF-VERIFICATION (err u107))
(define-constant ERR-INVALID-PROVIDER (err u108))

(define-constant MIN-VALIDITY-PERIOD u43200) ;; Minimum 30 days
(define-constant MAX-VALIDITY-PERIOD u525600) ;; Maximum 365 days
(define-constant MAX-KYC-LEVEL u3)

(define-data-var contract-owner principal tx-sender)
(define-data-var kyc-provider principal tx-sender)
(define-data-var total-verifications uint u0)
(define-data-var active-verifications uint u0)

(define-map kyc-records
  principal
  {
    status: (string-ascii 20),
    verified-at: uint,
    expires-at: uint,
    level: uint,
    verifier: principal,
    verification-count: uint,
    last-updated: uint
  }
)

(define-map authorized-verifiers 
  principal 
  {
    active: bool,
    added-at: uint,
    total-verifications: uint,
    last-verification: uint
  }
)

(define-map verification-history
  { user: principal, index: uint }
  {
    status: (string-ascii 20),
    timestamp: uint,
    verifier: principal,
    level: uint
  }
)

(define-public (set-kyc-provider (provider principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq provider tx-sender)) ERR-SELF-VERIFICATION)
    (var-set kyc-provider provider)
    (ok true)))

(define-public (add-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender (var-get kyc-provider)) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq verifier tx-sender)) ERR-SELF-VERIFICATION)
    (ok (map-set authorized-verifiers verifier {
      active: true,
      added-at: stacks-block-height,
      total-verifications: u0,
      last-verification: u0
    }))))

(define-public (remove-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender (var-get kyc-provider)) ERR-NOT-AUTHORIZED)
    (match (map-get? authorized-verifiers verifier)
      prev-data (ok (map-set authorized-verifiers verifier 
        (merge prev-data { active: false })))
      ERR-INVALID-PROVIDER)))

(define-public (verify-identity (user principal) (level uint) (validity-period uint))
  (let
    (
      (expires-at (+ stacks-block-height validity-period))
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq user tx-sender)) ERR-SELF-VERIFICATION)
    (asserts! (<= level MAX-KYC-LEVEL) ERR-INVALID-LEVEL)
    (asserts! (and (>= validity-period MIN-VALIDITY-PERIOD) (<= validity-period MAX-VALIDITY-PERIOD)) ERR-INVALID-PERIOD)
    (asserts! (is-none (map-get? kyc-records user)) ERR-ALREADY-VERIFIED)
    (map-set verification-history { user: user, index: (var-get total-verifications) }
      {
        status: "VERIFIED",
        timestamp: stacks-block-height,
        verifier: tx-sender,
        level: level
      })
    (map-set authorized-verifiers tx-sender 
      (merge verifier-data {
        total-verifications: (+ (get total-verifications verifier-data) u1),
        last-verification: stacks-block-height
      }))
    (var-set total-verifications (+ (var-get total-verifications) u1))
    (var-set active-verifications (+ (var-get active-verifications) u1))
    (ok (map-set kyc-records user {
      status: "VERIFIED",
      verified-at: stacks-block-height,
      expires-at: expires-at,
      level: level,
      verifier: tx-sender,
      verification-count: u1,
      last-updated: stacks-block-height
    }))))

(define-public (revoke-verification (user principal))
  (let
    (
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
      (user-record (unwrap! (map-get? kyc-records user) ERR-NOT-VERIFIED))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (map-set verification-history { user: user, index: (var-get total-verifications) }
      {
        status: "REVOKED",
        timestamp: stacks-block-height,
        verifier: tx-sender,
        level: u0
      })
    (var-set total-verifications (+ (var-get total-verifications) u1))
    (var-set active-verifications (- (var-get active-verifications) u1))
    (ok (map-set kyc-records user 
      (merge user-record {
        status: "REVOKED",
        expires-at: stacks-block-height,
        level: u0,
        last-updated: stacks-block-height
      })))))

(define-read-only (get-kyc-status (user principal))
  (match (map-get? kyc-records user)
    record (ok record)
    ERR-NOT-VERIFIED))

(define-read-only (is-verified (user principal))
  (match (map-get? kyc-records user)
    record (if (and
      (is-eq (get status record) "VERIFIED")
      (< stacks-block-height (get expires-at record)))
      (ok true)
      (ok false))
    (ok false)))

(define-read-only (get-verification-level (user principal))
  (match (map-get? kyc-records user)
    record (ok (get level record))
    (ok u0)))

(define-read-only (is-verifier (address principal))
  (match (map-get? authorized-verifiers address)
    verifier-data (ok (get active verifier-data))
    (ok false)))

(define-read-only (get-verifier-stats (verifier principal))
  (match (map-get? authorized-verifiers verifier)
    stats (ok stats)
    ERR-INVALID-PROVIDER))

(define-read-only (get-contract-stats)
  (ok {
    total-verifications: (var-get total-verifications),
    active-verifications: (var-get active-verifications)
  }))
