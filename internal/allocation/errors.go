// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package allocation

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrTCPConnectionTimeoutOrFailure = errors.New("failed to create tcp connection")
	ErrDupeTCPConnection             = errors.New("tcp connection already exists for peer address")

	// ErrAdmissionInProgress is returned when another Allocate request for the
	// same five-tuple is currently being admitted. The request may be retried;
	// the in-flight request either publishes an allocation (making the retry a
	// duplicate) or fails and frees the five-tuple, after which a retry proceeds
	// with a new generation.
	ErrAdmissionInProgress = errors.New("allocation admission already in progress for five-tuple")

	// ErrAllocationExists is returned when the five-tuple already has a live
	// allocation.
	ErrAllocationExists = errors.New("allocation already exists for five-tuple")

	// ErrQuotaExceeded is the sentinel returned for an Allocate request rejected
	// because the per-user allocation quota is exhausted.
	ErrQuotaExceeded = errors.New("allocation quota exceeded")

	// ErrSameChannelDifferentPeer is returned when a client attempts to bind a
	// channel number that is already bound to a different peer address.
	ErrSameChannelDifferentPeer = errors.New("you cannot use the same channel number with different peer")

	// ErrSamePeerDifferentChannel is returned when a client attempts to bind a
	// peer address that is already bound to a different channel number.
	ErrSamePeerDifferentChannel = errors.New("you cannot use the same peer with different channel number")

	errAllocatePacketConnMustBeSet  = errors.New("AllocatePacketConn must be set")
	errAllocateListenerMustBeSet    = errors.New("AllocateListener must be set")
	errAllocateConnMustBeSet        = errors.New("AllocateConn must be set")
	errLeveledLoggerMustBeSet       = errors.New("LeveledLogger must be set")
	errNilFiveTuple                 = errors.New("allocations must not be created with nil FivTuple")
	errNilFiveTupleSrcAddr          = errors.New("allocations must not be created with nil FiveTuple.SrcAddr")
	errNilFiveTupleDstAddr          = errors.New("allocations must not be created with nil FiveTuple.DstAddr")
	errNilTurnSocket                = errors.New("allocations must not be created with nil turnSocket")
	errLifetimeZero                 = errors.New("allocations must not be created with a lifetime of 0")
	errUnsupportedTransport         = errors.New("allocation requested an unsupported transport")
	errAdmissionRequired            = errors.New("allocation admission does not belong to this manager")
	errManagerClosed                = errors.New("allocation manager is closed")
	errFailedToCastUDPAddr          = errors.New("failed to cast net.Addr to *net.UDPAddr")
	errFailedToAllocateEvenPort     = errors.New("failed to allocate an even port")
	errAdminProhibited              = errors.New("permission request administratively prohibited")
	errFailedToGenerateConnectionID = errors.New("failed to generate a unique connection id")
	errInvalidPeerAddress           = errors.New("invalid peer address")
	errNilRelaySocket               = errors.New("allocation has no relay socket")
	errAllocationClosed             = errors.New("allocation is closed")
)

// DefaultQuotaRetryAfter is the minimum wait before a client retries an Allocate
// request rejected with 486 (Allocation Quota Reached).
//
// RFC 5766 Section 6.2 and RFC 8656 Section 6.6 both ask clients to wait at
// least one minute before creating more allocations on the same server.
const DefaultQuotaRetryAfter = time.Minute

// QuotaExceededError explains a 486 (Allocation Quota Reached) rejection and
// tells the caller when it may retry. The reason is safe to put on the wire in
// an ERROR-CODE attribute and in logs.
type QuotaExceededError struct {
	UserID     string
	Realm      string
	RetryAfter time.Duration
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("allocation quota exceeded for user %q in realm %q (retry after %s)",
		e.UserID, e.Realm, e.RetryAfter)
}

// Is reports QuotaExceededError as ErrQuotaExceeded so callers can test the
// rejection with errors.Is.
func (e *QuotaExceededError) Is(target error) bool {
	return target == ErrQuotaExceeded
}
