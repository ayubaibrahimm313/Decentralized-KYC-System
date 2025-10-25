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

(define-constant ERR-INSUFFICIENT-SIGNATURES (err u109))
(define-constant ERR-ALREADY-SIGNED (err u110))
(define-constant ERR-PENDING-NOT-FOUND (err u111))
(define-constant ERR-INVALID-THRESHOLD (err u112))

(define-data-var signature-threshold uint u2)
(define-data-var pending-verification-counter uint u0)

(define-map pending-verifications
  uint
  {
    user: principal,
    level: uint,
    validity-period: uint,
    created-at: uint,
    signatures-count: uint,
    initiator: principal,
    status: (string-ascii 20)
  }
)

(define-map verification-signatures
  { verification-id: uint, verifier: principal }
  {
    signed-at: uint,
    active: bool
  }
)

(define-public (set-signature-threshold (threshold uint))
  (begin
    (asserts! (is-eq tx-sender (var-get kyc-provider)) ERR-NOT-AUTHORIZED)
    (asserts! (> threshold u0) ERR-INVALID-THRESHOLD)
    (var-set signature-threshold threshold)
    (ok true)))

(define-public (initiate-verification (user principal) (level uint) (validity-period uint))
  (let
    (
      (verification-id (var-get pending-verification-counter))
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq user tx-sender)) ERR-SELF-VERIFICATION)
    (asserts! (<= level MAX-KYC-LEVEL) ERR-INVALID-LEVEL)
    (asserts! (and (>= validity-period MIN-VALIDITY-PERIOD) (<= validity-period MAX-VALIDITY-PERIOD)) ERR-INVALID-PERIOD)
    (asserts! (is-none (map-get? kyc-records user)) ERR-ALREADY-VERIFIED)
    (map-set pending-verifications verification-id {
      user: user,
      level: level,
      validity-period: validity-period,
      created-at: stacks-block-height,
      signatures-count: u1,
      initiator: tx-sender,
      status: "PENDING"
    })
    (map-set verification-signatures { verification-id: verification-id, verifier: tx-sender } {
      signed-at: stacks-block-height,
      active: true
    })
    (var-set pending-verification-counter (+ verification-id u1))
    (ok verification-id)))

(define-public (sign-verification (verification-id uint))
  (let
    (
      (pending-verification (unwrap! (map-get? pending-verifications verification-id) ERR-PENDING-NOT-FOUND))
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
      (signature-key { verification-id: verification-id, verifier: tx-sender })
      (new-signature-count (+ (get signatures-count pending-verification) u1))
      (threshold (var-get signature-threshold))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status pending-verification) "PENDING") ERR-INVALID-STATUS)
    (asserts! (is-none (map-get? verification-signatures signature-key)) ERR-ALREADY-SIGNED)
    (map-set verification-signatures signature-key {
      signed-at: stacks-block-height,
      active: true
    })
    (map-set pending-verifications verification-id
      (merge pending-verification { signatures-count: new-signature-count }))
    (if (>= new-signature-count threshold)
      (finalize-verification verification-id)
      (ok true))))

(define-private (finalize-verification (verification-id uint))
  (let
    (
      (pending-verification (unwrap! (map-get? pending-verifications verification-id) ERR-PENDING-NOT-FOUND))
      (user (get user pending-verification))
      (level (get level pending-verification))
      (validity-period (get validity-period pending-verification))
      (expires-at (+ stacks-block-height validity-period))
    )
    (map-set pending-verifications verification-id
      (merge pending-verification { status: "COMPLETED" }))
    (map-set verification-history { user: user, index: (var-get total-verifications) }
      {
        status: "VERIFIED",
        timestamp: stacks-block-height,
        verifier: (get initiator pending-verification),
        level: level
      })
    (var-set total-verifications (+ (var-get total-verifications) u1))
    (var-set active-verifications (+ (var-get active-verifications) u1))
    (ok (map-set kyc-records user {
      status: "VERIFIED",
      verified-at: stacks-block-height,
      expires-at: expires-at,
      level: level,
      verifier: (get initiator pending-verification),
      verification-count: u1,
      last-updated: stacks-block-height
    }))))

(define-read-only (get-pending-verification (verification-id uint))
  (match (map-get? pending-verifications verification-id)
    verification (ok verification)
    ERR-PENDING-NOT-FOUND))

(define-read-only (get-signature-threshold)
  (ok (var-get signature-threshold)))

(define-read-only (has-signed-verification (verification-id uint) (verifier principal))
  (is-some (map-get? verification-signatures { verification-id: verification-id, verifier: verifier })))

  (define-constant ERR-INVALID-RATING (err u113))
(define-constant ERR-CANNOT-RATE-SELF (err u114))
(define-constant ERR-ALREADY-RATED (err u115))
(define-constant ERR-LOW-REPUTATION (err u116))
(define-constant ERR-INSUFFICIENT-PAYMENT (err u117))
(define-constant ERR-INVALID-FEE (err u118))
(define-constant ERR-WITHDRAWAL-FAILED (err u119))
(define-constant ERR-INVALID-WITHDRAWAL (err u120))
(define-constant ERR-NOT-RENEWABLE (err u124))
(define-constant ERR-RENEWAL-WINDOW-NOT-OPEN (err u125))

(define-constant MIN-REPUTATION-SCORE u50)
(define-constant MAX-RATING u5)
(define-constant PLATFORM-FEE-PERCENTAGE u10)
(define-constant MIN-VERIFICATION-FEE u1000)
(define-constant MAX-VERIFICATION-FEE u100000)
(define-constant RENEWAL-WINDOW-BLOCKS u7200)
(define-constant RENEWAL-DISCOUNT-PERCENTAGE u20)

(define-data-var reputation-update-counter uint u0)
(define-data-var total-platform-earnings uint u0)
(define-data-var total-renewals uint u0)

(define-map verifier-fees
  principal
  {
    level-1-fee: uint,
    level-2-fee: uint,
    level-3-fee: uint,
    total-earned: uint,
    pending-withdrawal: uint,
    last-updated: uint
  }
)

(define-map verifier-earnings
  principal
  uint
)

(define-map platform-earnings
  uint
  uint
)

(define-map verification-payments
  { user: principal, verification-id: uint }
  {
    total-fee: uint,
    verifier-share: uint,
    platform-share: uint,
    paid-at: uint,
    status: (string-ascii 20)
  }
)

(define-map verifier-reputation
  principal
  {
    score: uint,
    total-ratings: uint,
    average-rating: uint,
    successful-verifications: uint,
    disputed-verifications: uint,
    last-updated: uint,
    status: (string-ascii 20)
  }
)

(define-map user-trust-scores
  principal
  {
    score: uint,
    verification-history-count: uint,
    revocation-count: uint,
    last-calculated: uint
  }
)

(define-map verifier-ratings
  { rater: principal, rated: principal, period: uint }
  {
    rating: uint,
    comment: (string-ascii 100),
    timestamp: uint
  }
)

(define-map reputation-events
  uint
  {
    event-type: (string-ascii 20),
    verifier: principal,
    user: (optional principal),
    impact: int,
    timestamp: uint
  }
)

(define-map renewal-history
  { user: principal, renewal-index: uint }
  {
    previous-expiry: uint,
    new-expiry: uint,
    renewed-at: uint,
    verifier: principal,
    fee-paid: uint,
    discount-applied: uint,
    level: uint
  }
)

(define-map user-renewal-stats
  principal
  {
    total-renewals: uint,
    last-renewal: uint,
    consecutive-renewals: uint,
    lifetime-discount-saved: uint
  }
)

(define-public (rate-verifier (verifier principal) (rating uint) (comment (string-ascii 100)))
  (let
    (
      (rater-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
      (rating-key { rater: tx-sender, rated: verifier, period: (/ stacks-block-height u1440) })
      (current-reputation (default-to { 
        score: u100, 
        total-ratings: u0, 
        average-rating: u0, 
        successful-verifications: u0, 
        disputed-verifications: u0, 
        last-updated: u0,
        status: "ACTIVE"
      } (map-get? verifier-reputation verifier)))
    )
    (asserts! (get active rater-data) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq tx-sender verifier)) ERR-CANNOT-RATE-SELF)
    (asserts! (and (>= rating u1) (<= rating MAX-RATING)) ERR-INVALID-RATING)
    (asserts! (is-none (map-get? verifier-ratings rating-key)) ERR-ALREADY-RATED)
    (map-set verifier-ratings rating-key {
      rating: rating,
      comment: comment,
      timestamp: stacks-block-height
    })
    (let
      (
        (new-total-ratings (+ (get total-ratings current-reputation) u1))
        (new-average (/ (+ (* (get average-rating current-reputation) (get total-ratings current-reputation)) rating) new-total-ratings))
        (reputation-impact (if (> rating u3) u5 u5))
        (new-score (if (> rating u3)
                      (if (> (+ (get score current-reputation) u5) u200)
                          u200
                          (+ (get score current-reputation) u5))
                      (if (> (get score current-reputation) u5)
                          (- (get score current-reputation) u5)
                          u0)))
      )
      (map-set verifier-reputation verifier
        (merge current-reputation {
          total-ratings: new-total-ratings,
          average-rating: new-average,
          score: new-score,
          last-updated: stacks-block-height
        }))
      (map-set reputation-events (var-get reputation-update-counter) {
        event-type: "RATING",
        verifier: verifier,
        user: none,
        impact: (if (> rating u3) 5 -5),
        timestamp: stacks-block-height
      })
      (var-set reputation-update-counter (+ (var-get reputation-update-counter) u1))
      (ok true))))
(define-public (update-verifier-reputation (verifier principal) (event-type (string-ascii 20)) (impact int))
  (let
    (
      (current-reputation (default-to { 
        score: u100, 
        total-ratings: u0, 
        average-rating: u0, 
        successful-verifications: u0, 
        disputed-verifications: u0, 
        last-updated: u0,
        status: "ACTIVE"
      } (map-get? verifier-reputation verifier)))
    )
    (asserts! (is-eq tx-sender (var-get kyc-provider)) ERR-NOT-AUTHORIZED)
    (let
      (
        (current-score (get score current-reputation))
        (new-score (if (< impact 0)
                      (if (> current-score (to-uint (- 0 impact)))
                          (- current-score (to-uint (- 0 impact)))
                          u0)
                      (if (< (+ current-score (to-uint impact)) u200)
                          (+ current-score (to-uint impact))
                          u200)))
        (successful-count (if (is-eq event-type "SUCCESS") 
                             (+ (get successful-verifications current-reputation) u1)
                             (get successful-verifications current-reputation)))
        (disputed-count (if (is-eq event-type "DISPUTE") 
                           (+ (get disputed-verifications current-reputation) u1)
                           (get disputed-verifications current-reputation)))
      )
      (map-set verifier-reputation verifier
        (merge current-reputation {
          score: new-score,
          successful-verifications: successful-count,
          disputed-verifications: disputed-count,
          last-updated: stacks-block-height,
          status: (if (< new-score MIN-REPUTATION-SCORE) "SUSPENDED" "ACTIVE")
        }))
      (map-set reputation-events (var-get reputation-update-counter) {
        event-type: event-type,
        verifier: verifier,
        user: none,
        impact: impact,
        timestamp: stacks-block-height
      })
      (var-set reputation-update-counter (+ (var-get reputation-update-counter) u1))
      (ok true))))

(define-public (calculate-user-trust-score (user principal))
  (let
    (
      (kyc-record (map-get? kyc-records user))
      (current-trust (default-to { 
        score: u50, 
        verification-history-count: u0, 
        revocation-count: u0, 
        last-calculated: u0 
      } (map-get? user-trust-scores user)))
    )
    (match kyc-record
      record (let
        (
          (verification-count (get verification-count record))
          (is-currently-verified (and (is-eq (get status record) "VERIFIED") 
                                     (< stacks-block-height (get expires-at record))))
          (base-score u50)
          (verification-bonus (* verification-count u10))
          (status-bonus (if is-currently-verified u20 u0))
          (revocation-penalty (* (get revocation-count current-trust) u15))
          (calculated-score (if (> (+ base-score verification-bonus status-bonus) revocation-penalty)
                               (- (+ base-score verification-bonus status-bonus) revocation-penalty)
                               u0))
          (final-score (if (> calculated-score u100) u100 calculated-score))
        )
        (ok (map-set user-trust-scores user {
          score: final-score,
          verification-history-count: verification-count,
          revocation-count: (get revocation-count current-trust),
          last-calculated: stacks-block-height
        })))
      (ok (map-set user-trust-scores user
        (merge current-trust { 
          score: u25,
          last-calculated: stacks-block-height 
        }))))))

(define-read-only (get-verifier-reputation (verifier principal))
  (match (map-get? verifier-reputation verifier)
    reputation (ok reputation)
    (ok { 
      score: u100, 
      total-ratings: u0, 
      average-rating: u0, 
      successful-verifications: u0, 
      disputed-verifications: u0, 
      last-updated: u0,
      status: "ACTIVE"
    })))
(define-read-only (get-user-trust-score (user principal))
  (match (map-get? user-trust-scores user)
    trust-data (ok trust-data)
    (ok { 
      score: u50, 
      verification-history-count: u0, 
      revocation-count: u0, 
      last-calculated: u0 
    })))

(define-read-only (get-verifier-rating (rater principal) (rated principal) (period uint))
  (match (map-get? verifier-ratings { rater: rater, rated: rated, period: period })
    rating (ok rating)
    ERR-PENDING-NOT-FOUND))

(define-read-only (can-verify-based-on-reputation (verifier principal))
  (match (map-get? verifier-reputation verifier)
    reputation (ok (and 
      (>= (get score reputation) MIN-REPUTATION-SCORE)
      (is-eq (get status reputation) "ACTIVE")))
    (ok true)))

(define-read-only (get-reputation-event (event-id uint))
  (match (map-get? reputation-events event-id)
    event (ok event)
    ERR-PENDING-NOT-FOUND))

(define-read-only (get-reputation-stats)
  (ok {
    total-reputation-events: (var-get reputation-update-counter),
    min-reputation-threshold: MIN-REPUTATION-SCORE,
    max-rating: MAX-RATING
  }))

(define-public (set-verifier-fees (level-1-fee uint) (level-2-fee uint) (level-3-fee uint))
  (let
    (
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= level-1-fee MIN-VERIFICATION-FEE) (<= level-1-fee MAX-VERIFICATION-FEE)) ERR-INVALID-FEE)
    (asserts! (and (>= level-2-fee MIN-VERIFICATION-FEE) (<= level-2-fee MAX-VERIFICATION-FEE)) ERR-INVALID-FEE)
    (asserts! (and (>= level-3-fee MIN-VERIFICATION-FEE) (<= level-3-fee MAX-VERIFICATION-FEE)) ERR-INVALID-FEE)
    (ok (map-set verifier-fees tx-sender {
      level-1-fee: level-1-fee,
      level-2-fee: level-2-fee,
      level-3-fee: level-3-fee,
      total-earned: u0,
      pending-withdrawal: u0,
      last-updated: stacks-block-height
    }))))

(define-public (verify-identity-with-payment (user principal) (level uint) (validity-period uint))
  (let
    (
      (expires-at (+ stacks-block-height validity-period))
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
      (fee-data (unwrap! (map-get? verifier-fees tx-sender) ERR-INVALID-FEE))
      (verification-fee (if (is-eq level u1)
                          (get level-1-fee fee-data)
                          (if (is-eq level u2)
                            (get level-2-fee fee-data)
                            (get level-3-fee fee-data))))
      (platform-fee (/ (* verification-fee PLATFORM-FEE-PERCENTAGE) u100))
      (verifier-share (- verification-fee platform-fee))
      (payment-amount (stx-get-balance user))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq user tx-sender)) ERR-SELF-VERIFICATION)
    (asserts! (<= level MAX-KYC-LEVEL) ERR-INVALID-LEVEL)
    (asserts! (and (>= validity-period MIN-VALIDITY-PERIOD) (<= validity-period MAX-VALIDITY-PERIOD)) ERR-INVALID-PERIOD)
    (asserts! (is-none (map-get? kyc-records user)) ERR-ALREADY-VERIFIED)
    (asserts! (>= payment-amount verification-fee) ERR-INSUFFICIENT-PAYMENT)
    
    (try! (stx-transfer? verification-fee user (as-contract tx-sender)))
    
    (map-set verification-payments { user: user, verification-id: (var-get total-verifications) } {
      total-fee: verification-fee,
      verifier-share: verifier-share,
      platform-share: platform-fee,
      paid-at: stacks-block-height,
      status: "PAID"
    })
    
    (map-set verifier-earnings tx-sender 
      (+ (default-to u0 (map-get? verifier-earnings tx-sender)) verifier-share))
    
    (var-set total-platform-earnings (+ (var-get total-platform-earnings) platform-fee))
    
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

(define-public (withdraw-earnings)
  (let
    (
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
      (pending-amount (default-to u0 (map-get? verifier-earnings tx-sender)))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (> pending-amount u0) ERR-INVALID-WITHDRAWAL)
    
    (try! (as-contract (stx-transfer? pending-amount tx-sender tx-sender)))
    
    (map-set verifier-earnings tx-sender u0)
    (ok pending-amount)))

(define-public (withdraw-platform-earnings (amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get kyc-provider)) ERR-NOT-AUTHORIZED)
    (asserts! (<= amount (var-get total-platform-earnings)) ERR-INVALID-WITHDRAWAL)
    
    (try! (as-contract (stx-transfer? amount tx-sender tx-sender)))
    
    (var-set total-platform-earnings (- (var-get total-platform-earnings) amount))
    (ok amount)))

(define-read-only (get-verifier-fees (verifier principal))
  (match (map-get? verifier-fees verifier)
    fees (ok fees)
    (ok {
      level-1-fee: MIN-VERIFICATION-FEE,
      level-2-fee: MIN-VERIFICATION-FEE,
      level-3-fee: MIN-VERIFICATION-FEE,
      total-earned: u0,
      pending-withdrawal: u0,
      last-updated: u0
    })))

(define-read-only (get-verification-cost (verifier principal) (level uint))
  (let
    (
      (fee-data (default-to {
        level-1-fee: MIN-VERIFICATION-FEE,
        level-2-fee: MIN-VERIFICATION-FEE,
        level-3-fee: MIN-VERIFICATION-FEE,
        total-earned: u0,
        pending-withdrawal: u0,
        last-updated: u0
      } (map-get? verifier-fees verifier)))
    )
    (ok (if (is-eq level u1)
          (get level-1-fee fee-data)
          (if (is-eq level u2)
            (get level-2-fee fee-data)
            (get level-3-fee fee-data))))))

(define-read-only (get-verifier-earnings (verifier principal))
  (ok (default-to u0 (map-get? verifier-earnings verifier))))

(define-read-only (get-platform-earnings)
  (ok (var-get total-platform-earnings)))

(define-read-only (get-verification-payment (user principal) (verification-id uint))
  (match (map-get? verification-payments { user: user, verification-id: verification-id })
    payment (ok payment)
    ERR-PENDING-NOT-FOUND))

(define-read-only (get-fee-stats)
  (ok {
    platform-fee-percentage: PLATFORM-FEE-PERCENTAGE,
    min-verification-fee: MIN-VERIFICATION-FEE,
    max-verification-fee: MAX-VERIFICATION-FEE,
    total-platform-earnings: (var-get total-platform-earnings)
  }))

(define-constant ERR-NOTIFICATION-NOT-FOUND (err u121))
(define-constant ERR-NOTIFICATION-ALREADY-EXISTS (err u122))
(define-constant ERR-INVALID-NOTIFICATION-THRESHOLD (err u123))

(define-constant DEFAULT-EXPIRATION-THRESHOLD u4320)
(define-constant MAX-EXPIRATION-THRESHOLD u14400)

(define-data-var notification-counter uint u0)
(define-data-var global-notification-threshold uint DEFAULT-EXPIRATION-THRESHOLD)

(define-map expiration-notifications
  principal
  {
    threshold-blocks: uint,
    last-notification: uint,
    notification-count: uint,
    enabled: bool,
    created-at: uint
  }
)

(define-map notification-history
  uint
  {
    user: principal,
    notification-type: (string-ascii 20),
    blocks-until-expiry: uint,
    triggered-at: uint,
    expires-at: uint
  }
)

(define-public (set-expiration-notification (threshold-blocks uint))
  (begin
    (asserts! (<= threshold-blocks MAX-EXPIRATION-THRESHOLD) ERR-INVALID-NOTIFICATION-THRESHOLD)
    (asserts! (> threshold-blocks u0) ERR-INVALID-NOTIFICATION-THRESHOLD)
    (ok (map-set expiration-notifications tx-sender {
      threshold-blocks: threshold-blocks,
      last-notification: u0,
      notification-count: u0,
      enabled: true,
      created-at: stacks-block-height
    }))))

(define-public (disable-expiration-notification)
  (match (map-get? expiration-notifications tx-sender)
    current-settings (ok (map-set expiration-notifications tx-sender
      (merge current-settings { enabled: false })))
    ERR-NOTIFICATION-NOT-FOUND))

(define-public (trigger-expiration-notification (user principal))
  (let
    (
      (user-record (unwrap! (map-get? kyc-records user) ERR-NOT-VERIFIED))
      (notification-settings (unwrap! (map-get? expiration-notifications user) ERR-NOTIFICATION-NOT-FOUND))
      (blocks-until-expiry (if (> (get expires-at user-record) stacks-block-height)
                             (- (get expires-at user-record) stacks-block-height)
                             u0))
      (notification-id (var-get notification-counter))
    )
    (asserts! (get enabled notification-settings) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status user-record) "VERIFIED") ERR-NOT-VERIFIED)
    (asserts! (<= blocks-until-expiry (get threshold-blocks notification-settings)) ERR-INVALID-NOTIFICATION-THRESHOLD)
    (map-set notification-history notification-id {
      user: user,
      notification-type: "EXPIRY_WARNING",
      blocks-until-expiry: blocks-until-expiry,
      triggered-at: stacks-block-height,
      expires-at: (get expires-at user-record)
    })
    (map-set expiration-notifications user
      (merge notification-settings {
        last-notification: stacks-block-height,
        notification-count: (+ (get notification-count notification-settings) u1)
      }))
    (var-set notification-counter (+ notification-id u1))
    (ok notification-id)))

(define-public (set-global-notification-threshold (threshold uint))
  (begin
    (asserts! (is-eq tx-sender (var-get kyc-provider)) ERR-NOT-AUTHORIZED)
    (asserts! (<= threshold MAX-EXPIRATION-THRESHOLD) ERR-INVALID-NOTIFICATION-THRESHOLD)
    (asserts! (> threshold u0) ERR-INVALID-NOTIFICATION-THRESHOLD)
    (var-set global-notification-threshold threshold)
    (ok true)))

(define-read-only (get-expiration-notification-settings (user principal))
  (match (map-get? expiration-notifications user)
    settings (ok settings)
    (ok {
      threshold-blocks: (var-get global-notification-threshold),
      last-notification: u0,
      notification-count: u0,
      enabled: false,
      created-at: u0
    })))

(define-read-only (get-notification-history (notification-id uint))
  (match (map-get? notification-history notification-id)
    notification (ok notification)
    ERR-NOTIFICATION-NOT-FOUND))

(define-read-only (check-expiration-status (user principal))
  (match (map-get? kyc-records user)
    record (let
      (
        (blocks-until-expiry (if (> (get expires-at record) stacks-block-height)
                               (- (get expires-at record) stacks-block-height)
                               u0))
        (notification-settings (map-get? expiration-notifications user))
        (threshold (match notification-settings
                     settings (get threshold-blocks settings)
                     (var-get global-notification-threshold)))
        (needs-notification (and (is-eq (get status record) "VERIFIED")
                                (<= blocks-until-expiry threshold)
                                (> blocks-until-expiry u0)))
      )
      (ok {
        expires-at: (get expires-at record),
        blocks-until-expiry: blocks-until-expiry,
        needs-notification: needs-notification,
        notification-threshold: threshold,
        is-expired: (>= stacks-block-height (get expires-at record))
      }))
    ERR-NOT-VERIFIED))

(define-read-only (get-users-needing-notification)
  (ok {
    global-threshold: (var-get global-notification-threshold),
    current-block: stacks-block-height,
    total-notifications: (var-get notification-counter)
  }))

(define-read-only (get-notification-stats)
  (ok {
    total-notifications-sent: (var-get notification-counter),
    global-threshold-blocks: (var-get global-notification-threshold),
    max-threshold-blocks: MAX-EXPIRATION-THRESHOLD,
    default-threshold-blocks: DEFAULT-EXPIRATION-THRESHOLD
  }))

(define-public (renew-verification (user principal) (validity-period uint))
  (let
    (
      (user-record (unwrap! (map-get? kyc-records user) ERR-NOT-VERIFIED))
      (verifier-data (unwrap! (map-get? authorized-verifiers tx-sender) ERR-NOT-AUTHORIZED))
      (fee-data (unwrap! (map-get? verifier-fees tx-sender) ERR-INVALID-FEE))
      (current-level (get level user-record))
      (current-expiry (get expires-at user-record))
      (blocks-until-expiry (if (> current-expiry stacks-block-height)
                             (- current-expiry stacks-block-height)
                             u0))
      (base-fee (if (is-eq current-level u1)
                   (get level-1-fee fee-data)
                   (if (is-eq current-level u2)
                     (get level-2-fee fee-data)
                     (get level-3-fee fee-data))))
      (discount-amount (/ (* base-fee RENEWAL-DISCOUNT-PERCENTAGE) u100))
      (renewal-fee (- base-fee discount-amount))
      (platform-fee (/ (* renewal-fee PLATFORM-FEE-PERCENTAGE) u100))
      (verifier-share (- renewal-fee platform-fee))
      (new-expiry (+ current-expiry validity-period))
      (renewal-stats (default-to {
        total-renewals: u0,
        last-renewal: u0,
        consecutive-renewals: u0,
        lifetime-discount-saved: u0
      } (map-get? user-renewal-stats user)))
      (payment-amount (stx-get-balance user))
    )
    (asserts! (get active verifier-data) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq user tx-sender)) ERR-SELF-VERIFICATION)
    (asserts! (is-eq (get status user-record) "VERIFIED") ERR-NOT-RENEWABLE)
    (asserts! (<= blocks-until-expiry RENEWAL-WINDOW-BLOCKS) ERR-RENEWAL-WINDOW-NOT-OPEN)
    (asserts! (> blocks-until-expiry u0) ERR-EXPIRED)
    (asserts! (and (>= validity-period MIN-VALIDITY-PERIOD) (<= validity-period MAX-VALIDITY-PERIOD)) ERR-INVALID-PERIOD)
    (asserts! (>= payment-amount renewal-fee) ERR-INSUFFICIENT-PAYMENT)
    (try! (stx-transfer? renewal-fee user (as-contract tx-sender)))
    (map-set renewal-history { user: user, renewal-index: (get total-renewals renewal-stats) } {
      previous-expiry: current-expiry,
      new-expiry: new-expiry,
      renewed-at: stacks-block-height,
      verifier: tx-sender,
      fee-paid: renewal-fee,
      discount-applied: discount-amount,
      level: current-level
    })
    (map-set user-renewal-stats user {
      total-renewals: (+ (get total-renewals renewal-stats) u1),
      last-renewal: stacks-block-height,
      consecutive-renewals: (+ (get consecutive-renewals renewal-stats) u1),
      lifetime-discount-saved: (+ (get lifetime-discount-saved renewal-stats) discount-amount)
    })
    (map-set verifier-earnings tx-sender
      (+ (default-to u0 (map-get? verifier-earnings tx-sender)) verifier-share))
    (var-set total-platform-earnings (+ (var-get total-platform-earnings) platform-fee))
    (map-set authorized-verifiers tx-sender
      (merge verifier-data {
        total-verifications: (+ (get total-verifications verifier-data) u1),
        last-verification: stacks-block-height
      }))
    (var-set total-renewals (+ (var-get total-renewals) u1))
    (ok (map-set kyc-records user
      (merge user-record {
        expires-at: new-expiry,
        verification-count: (+ (get verification-count user-record) u1),
        last-updated: stacks-block-height
      })))))

(define-read-only (check-renewal-eligibility (user principal))
  (match (map-get? kyc-records user)
    record (let
      (
        (blocks-until-expiry (if (> (get expires-at record) stacks-block-height)
                               (- (get expires-at record) stacks-block-height)
                               u0))
        (is-eligible (and
          (is-eq (get status record) "VERIFIED")
          (<= blocks-until-expiry RENEWAL-WINDOW-BLOCKS)
          (> blocks-until-expiry u0)))
      )
      (ok {
        eligible: is-eligible,
        current-expiry: (get expires-at record),
        blocks-until-expiry: blocks-until-expiry,
        renewal-window-blocks: RENEWAL-WINDOW-BLOCKS,
        level: (get level record)
      }))
    ERR-NOT-VERIFIED))

(define-read-only (calculate-renewal-cost (user principal) (verifier principal))
  (match (map-get? kyc-records user)
    record (match (map-get? verifier-fees verifier)
      fees (let
        (
          (current-level (get level record))
          (base-fee (if (is-eq current-level u1)
                      (get level-1-fee fees)
                      (if (is-eq current-level u2)
                        (get level-2-fee fees)
                        (get level-3-fee fees))))
          (discount (/ (* base-fee RENEWAL-DISCOUNT-PERCENTAGE) u100))
          (renewal-fee (- base-fee discount))
        )
        (ok {
          base-fee: base-fee,
          discount-amount: discount,
          discount-percentage: RENEWAL-DISCOUNT-PERCENTAGE,
          final-fee: renewal-fee
        }))
      ERR-INVALID-FEE)
    ERR-NOT-VERIFIED))

(define-read-only (get-renewal-stats (user principal))
  (match (map-get? user-renewal-stats user)
    stats (ok stats)
    (ok {
      total-renewals: u0,
      last-renewal: u0,
      consecutive-renewals: u0,
      lifetime-discount-saved: u0
    })))

(define-read-only (get-renewal-history (user principal) (renewal-index uint))
  (match (map-get? renewal-history { user: user, renewal-index: renewal-index })
    history (ok history)
    ERR-PENDING-NOT-FOUND))

(define-read-only (get-global-renewal-stats)
  (ok {
    total-renewals: (var-get total-renewals),
    renewal-window-blocks: RENEWAL-WINDOW-BLOCKS,
    renewal-discount-percentage: RENEWAL-DISCOUNT-PERCENTAGE
  }))
