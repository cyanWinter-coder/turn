// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/pion/randutil"
	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5/internal/allocation"
	"github.com/pion/turn/v5/internal/ipnet"
	"github.com/pion/turn/v5/internal/proto"
)

const runesAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// See: https://tools.ietf.org/html/rfc5766#section-6.2
// .
func handleAllocateRequest(req Request, stunMsg *stun.Message) error { //nolint:cyclop,gocyclo,maintidx,gocognit
	req.Log.Debugf("Received AllocateRequest from %s", req.SrcAddr)

	// 1. The server MUST require that the request be authenticated.  This
	//    authentication MUST be done using the long-term credential
	//    mechanism of [https://tools.ietf.org/html/rfc5389#section-10.2.2]
	//    unless the client and server agree to use another mechanism through
	//    some procedure outside the scope of this document.
	messageIntegrity, hasAuth, userID, err := authenticateRequest(req, stunMsg, stun.MethodAllocate)
	if !hasAuth {
		return err
	}

	fiveTuple := &allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}
	requestedPort := 0
	reservationToken := ""

	badRequestMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest}, messageIntegrity)
	insufficientCapacityMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeInsufficientCapacity}, messageIntegrity)

	// 2. The server checks if the 5-tuple is currently in use by an
	//    existing allocation.  If yes, the server rejects the request with
	//    a 437 (Allocation Mismatch) error.
	if alloc := req.AllocationManager.GetAllocation(fiveTuple); alloc != nil {
		id, attrs := alloc.GetResponseCache()
		if id != stunMsg.TransactionID {
			msg := buildMsg(
				stunMsg.TransactionID,
				stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
				&stun.ErrorCodeAttribute{Code: stun.CodeAllocMismatch}, messageIntegrity)

			return buildAndSendErr(req.Conn, req.SrcAddr, errRelayAlreadyAllocatedForFiveTuple, msg...)
		}
		// A retry allocation
		msg := buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodAllocate, stun.ClassSuccessResponse),
			append(attrs, messageIntegrity)...,
		)

		return buildAndSend(req.Conn, req.SrcAddr, msg...)
	}

	// The same five-tuple is already being admitted by another request. Only one
	// admission may reserve a relay address, so reject this one with 437; the
	// client retries and either finds the published allocation or starts a fresh
	// admission generation.
	if req.AllocationManager.AdmissionInProgress(fiveTuple) {
		msg := buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeAllocMismatch}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, allocation.ErrAdmissionInProgress, msg...)
	}

	// 3. The server checks if the request contains a REQUESTED-TRANSPORT
	//    attribute.  If the REQUESTED-TRANSPORT attribute is not included
	//    or is malformed, the server rejects the request with a 400 (Bad
	//    Request) error.  Otherwise, if the attribute is included but
	//    specifies a protocol other that UDP/TCP, the server rejects the
	//    request with a 442 (Unsupported Transport Protocol) error.
	var requestedTransport proto.RequestedTransport
	if err = requestedTransport.GetFrom(stunMsg); err != nil {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	} else if requestedTransport.Protocol != proto.ProtoUDP && requestedTransport.Protocol != proto.ProtoTCP {
		msg := buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeUnsupportedTransProto}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, errUnsupportedTransportProtocol, msg...)
	}

	// 4. The request may contain a DONT-FRAGMENT attribute.  If it does,
	//    but the server does not support sending UDP datagrams with the DF
	//    bit set to 1 (see Section 12), then the server treats the DONT-
	//    FRAGMENT attribute in the Allocate request as an unknown
	//    comprehension-required attribute.
	if stunMsg.Contains(stun.AttrDontFragment) {
		msg := buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeUnknownAttribute},
			&stun.UnknownAttributes{stun.AttrDontFragment}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, errNoDontFragmentSupport, msg...)
	}

	// 5.  The server checks if the request contains a RESERVATION-TOKEN
	//     attribute.  If yes, and the request also contains an EVEN-PORT
	//     attribute, then the server rejects the request with a 400 (Bad
	//     Request) error.  Otherwise, it checks to see if the token is
	//     valid (i.e., the token is in range and has not expired and the
	//     corresponding relayed transport address is still available).  If
	//     the token is not valid for some reason, the server rejects the
	//     request with a 508 (Insufficient Capacity) error.
	//
	//     The token is consumed only after admission succeeds, below, so a
	//     request that never reaches admission cannot burn it.
	var reservationTokenAttr proto.ReservationToken
	hasReservationToken := false
	if err = reservationTokenAttr.GetFrom(stunMsg); err == nil {
		var evenPort proto.EvenPort
		if err = evenPort.GetFrom(stunMsg); err == nil {
			return buildAndSendErr(req.Conn, req.SrcAddr, errRequestWithReservationTokenAndEvenPort, badRequestMsg...)
		}

		// Validate the token before the quota check, so a stale token is
		// rejected without consuming a quota slot. It is consumed atomically
		// after admission, since two clients may race for the same token.
		if _, reservationFound := req.AllocationManager.GetReservation(string(reservationTokenAttr)); !reservationFound {
			return buildAndSendErr(req.Conn, req.SrcAddr, errNoAllocationFound, insufficientCapacityMsg...)
		}
		hasReservationToken = true
	}

	// 6. The server checks if the request contains an EVEN-PORT attribute.
	//    If yes, then the server checks that it can satisfy the request
	//    (i.e., can allocate a relayed transport address as described
	//    below).  If the server cannot satisfy the request, then the
	//    server rejects the request with a 508 (Insufficient Capacity)
	//    error.
	//
	//    The even-port probe runs after the quota check so a rejected user never
	//    makes the address generator open a socket.
	var evenPort proto.EvenPort
	hasEvenPort := evenPort.GetFrom(stunMsg) == nil

	// Parse realm (already checked in authenticateRequest)
	realmAttr := &stun.Realm{}
	_ = realmAttr.GetFrom(stunMsg)

	// RFC 6156: Parse REQUESTED-ADDRESS-FAMILY attribute if present.
	// If absent, default to the listener family unless strict RFC 6156
	// behavior is requested.
	// "Length:  this 16-bit field contains the length of the attribute in
	// bytes.  The length of this attribute is 4 bytes."
	// "If the server does not support the address family requested by the
	// client, it MUST generate an Allocate error response, and it MUST
	// include an ERROR-CODE attribute with the 440 (Address Family not
	// Supported) response code, which is defined in Section 4.2.1."
	var requestedFamily proto.RequestedAddressFamily
	if err = requestedFamily.GetFrom(stunMsg); err != nil {
		switch {
		case errors.Is(err, stun.ErrAttributeNotFound):
			requestedFamily = defaultAllocationAddressFamily(req)
		case stun.IsAttrSizeInvalid(err) || stun.IsAttrSizeOverflow(err):
			return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
		default:
			msg := buildMsg(
				stunMsg.TransactionID,
				stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
				&stun.ErrorCodeAttribute{Code: stun.CodeAddrFamilyNotSupported}, messageIntegrity)

			return buildAndSendErr(req.Conn, req.SrcAddr, errUnsupportedAddressFamily, msg...)
		}
	}

	// RFC 6156: Check if the requested address family is supported.
	// If not, reject with 440 (Address Family not Supported) error.
	if requestedFamily != proto.RequestedFamilyIPv4 && requestedFamily != proto.RequestedFamilyIPv6 {
		msg := buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeAddrFamilyNotSupported}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, errUnsupportedAddressFamily, msg...)
	}

	// RFC 6156: REQUESTED-ADDRESS-FAMILY and RESERVATION-TOKEN are mutually exclusive.
	if stunMsg.Contains(stun.AttrReservationToken) && stunMsg.Contains(stun.AttrRequestedAddressFamily) {
		return buildAndSendErr(req.Conn, req.SrcAddr, errRequestWithReservationTokenAndRequestedFamily, badRequestMsg...)
	}

	// 7. At any point, the server MAY choose to reject the request with a
	//    486 (Allocation Quota Reached) error if it feels the client is
	//    trying to exceed some locally defined allocation quota.  The
	//    server is free to define this allocation quota any way it wishes,
	//    but SHOULD define it based on the username used to authenticate
	//    the request, and not on the client's transport address.
	//
	//    The quota check happens before any relay port is reserved. A handler
	//    that reserves a slot when this check passes releases it from
	//    OnAllocationFailed or OnAllocationDeleted; exactly one of those fires
	//    for every admitted request.
	if req.QuotaHandler != nil && !req.QuotaHandler(userID, realmAttr.String(), req.SrcAddr) {
		quotaErr := &allocation.QuotaExceededError{
			UserID:     userID,
			Realm:      realmAttr.String(),
			RetryAfter: allocation.DefaultQuotaRetryAfter,
		}
		req.Log.Warnf("Rejecting Allocate from %s: %v", req.SrcAddr, quotaErr)

		quotaReachedMsg := buildMsg(stunMsg.TransactionID,
			stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{
				Code:   stun.CodeAllocQuotaReached,
				Reason: quotaReason(quotaErr),
			},
			messageIntegrity)

		return buildAndSend(req.Conn, req.SrcAddr, quotaReachedMsg...)
	}

	// All authentication, permission and quota checks have passed. From here on
	// a failure must not leak a relay port or a quota slot: the admission owns
	// them until the allocation is published, and Abort releases them exactly
	// once.
	admission, err := req.AllocationManager.BeginAdmission(fiveTuple)
	if err != nil {
		if errors.Is(err, allocation.ErrAdmissionInProgress) || errors.Is(err, allocation.ErrAllocationExists) {
			msg := buildMsg(
				stunMsg.TransactionID,
				stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
				&stun.ErrorCodeAttribute{Code: stun.CodeAllocMismatch}, messageIntegrity)

			notifyAllocationFailed(req, fiveTuple, userID, realmAttr.String(), err)

			return buildAndSendErr(req.Conn, req.SrcAddr, err, msg...)
		}
		notifyAllocationFailed(req, fiveTuple, userID, realmAttr.String(), err)

		return buildAndSendErr(req.Conn, req.SrcAddr, err, insufficientCapacityMsg...)
	}

	// The admission is aborted on every path that does not publish an
	// allocation. Once CreateAllocationWithAdmission succeeds the allocation
	// itself owns the relay port and quota slot, and OnAllocationDeleted will
	// release the slot.
	consumedReservationPort := 0
	consumedReservation := false
	defer func() {
		admission.Abort()
	}()

	if hasReservationToken {
		allocationPort, reservationFound := req.AllocationManager.TakeReservation(string(reservationTokenAttr))
		if !reservationFound {
			notifyAllocationFailed(req, fiveTuple, userID, realmAttr.String(), errNoAllocationFound)

			return buildAndSendErr(req.Conn, req.SrcAddr, errNoAllocationFound, insufficientCapacityMsg...)
		}
		requestedPort = allocationPort + 1
		consumedReservationPort = allocationPort
		consumedReservation = true
	}

	if hasEvenPort {
		var randomPort int
		randomPort, err = req.AllocationManager.GetRandomEvenPort()
		if err != nil {
			restoreConsumedReservation(req, consumedReservation, consumedReservationPort, reservationTokenAttr)
			notifyAllocationFailed(req, fiveTuple, userID, realmAttr.String(), err)

			return buildAndSendErr(req.Conn, req.SrcAddr, err, insufficientCapacityMsg...)
		}
		requestedPort = randomPort

		reservationToken, err = randutil.GenerateCryptoRandomString(8, runesAlpha)
		if err != nil {
			restoreConsumedReservation(req, consumedReservation, consumedReservationPort, reservationTokenAttr)
			notifyAllocationFailed(req, fiveTuple, userID, realmAttr.String(), err)

			return err
		}
	}

	// 8. Also at any point, the server MAY choose to reject the request
	//    with a 300 (Try Alternate) error if it wishes to redirect the
	//    client to a different server.  The use of this error code and
	//    attribute follow the specification in [RFC5389].
	lifetimeDuration := allocationLifeTime(req, stunMsg)
	alloc, err := req.AllocationManager.CreateAllocationWithAdmission(
		admission,
		req.Conn,
		requestedTransport.Protocol,
		requestedPort,
		lifetimeDuration,
		userID,
		realmAttr.String(),
		requestedFamily,
	)
	if err != nil {
		restoreConsumedReservation(req, consumedReservation, consumedReservationPort, reservationTokenAttr)
		notifyAllocationFailed(req, fiveTuple, userID, realmAttr.String(), err)

		return buildAndSendErr(req.Conn, req.SrcAddr, err, insufficientCapacityMsg...)
	}

	// Once the allocation is created, the server replies with a success
	// response.
	// The success response contains:
	//   * An XOR-RELAYED-ADDRESS attribute containing the relayed transport
	//     address.
	//   * A LIFETIME attribute containing the current value of the time-to-
	//     expiry timer.
	//   * A RESERVATION-TOKEN attribute (if a second relayed transport
	//     address was reserved).
	//   * An XOR-MAPPED-ADDRESS attribute containing the client's IP address
	//     and port (from the 5-tuple).
	srcIP, srcPort, err := ipnet.AddrIPPort(req.SrcAddr)
	if err != nil {
		restoreConsumedReservation(req, consumedReservation, consumedReservationPort, reservationTokenAttr)
		req.AllocationManager.DeleteAllocationIf(alloc)

		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	relayIP, relayPort, err := ipnet.AddrIPPort(alloc.RelayAddr)
	if err != nil {
		restoreConsumedReservation(req, consumedReservation, consumedReservationPort, reservationTokenAttr)
		req.AllocationManager.DeleteAllocationIf(alloc)

		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	responseAttrs := []stun.Setter{
		&proto.RelayedAddress{
			IP:   relayIP,
			Port: relayPort,
		},
		&proto.Lifetime{
			Duration: lifetimeDuration,
		},
		&stun.XORMappedAddress{
			IP:   srcIP,
			Port: srcPort,
		},
	}

	if reservationToken != "" {
		req.AllocationManager.CreateReservation(reservationToken, relayPort)
		responseAttrs = append(responseAttrs, proto.ReservationToken([]byte(reservationToken)))
	}

	msg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodAllocate, stun.ClassSuccessResponse),
		append(responseAttrs, messageIntegrity)...,
	)
	alloc.SetResponseCache(stunMsg.TransactionID, responseAttrs)

	if err = buildAndSend(req.Conn, req.SrcAddr, msg...); err != nil {
		// The client never saw the relay address, so the allocation and its
		// quota slot must not survive the failed response. OnAllocationDeleted
		// released the slot; do not also report OnAllocationFailed.
		req.AllocationManager.DeleteAllocationIf(alloc)
		if reservationToken != "" {
			req.AllocationManager.RemoveReservation(reservationToken)
		}
		restoreConsumedReservation(req, consumedReservation, consumedReservationPort, reservationTokenAttr)

		return err
	}

	return nil
}

// restoreConsumedReservation returns a RESERVATION-TOKEN taken for an Allocate
// request that failed before producing an allocation, so the client can retry
// with the same token.
func restoreConsumedReservation(req Request, consumed bool, consumedPort int, token proto.ReservationToken) {
	if !consumed {
		return
	}

	req.AllocationManager.RestoreReservation(string(token), consumedPort)
}

// quotaReason renders a 486 reason phrase that names the cause and the retry
// window, capped to the 763 byte ERROR-CODE reason limit.
func quotaReason(err *allocation.QuotaExceededError) []byte {
	retryAfter := int64(err.RetryAfter / time.Second)
	reason := fmt.Sprintf("Allocation Quota Reached; retry after %ds", retryAfter)
	if len(reason) > 763 {
		reason = reason[:763]
	}

	return []byte(reason)
}

// notifyAllocationFailed reports an Allocate request that passed the quota check
// but did not produce an allocation, so a slot reserved by QuotaHandler can be
// released exactly once.
func notifyAllocationFailed(req Request, fiveTuple *allocation.FiveTuple, userID, realm string, cause error) {
	handler := req.AllocationManager.EventHandler.OnAllocationFailed
	if handler == nil {
		return
	}

	handler(fiveTuple.SrcAddr, fiveTuple.DstAddr, fiveTuple.Protocol.String(), userID, realm, cause)
}

func handleRefreshRequest(req Request, stunMsg *stun.Message) error {
	req.Log.Debugf("Received RefreshRequest from %s", req.SrcAddr)

	messageIntegrity, hasAuth, userID, err := authenticateRequest(req, stunMsg, stun.MethodRefresh)
	if !hasAuth {
		return err
	}

	lifetimeDuration := allocationLifeTime(req, stunMsg)
	fiveTuple := &allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}

	a := req.AllocationManager.GetAllocationForUserID(fiveTuple, userID) //nolint:varnamelen
	if a == nil {
		return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
	}

	// RFC 6156: If REQUESTED-ADDRESS-FAMILY is present in Refresh request,
	// it must match the allocation's address family.
	// "The client MUST NOT include any REQUESTED-ADDRESS-FAMILY attribute in
	// its Refresh Request."
	// "If a server receives a Refresh Request with a REQUESTED-ADDRESS-
	// FAMILY attribute, and the attribute's value doesn't match the address
	// family of the allocation, the server MUST reply with a 443 (Peer
	// Address Family Mismatch) Refresh error response."
	if err = checkRefreshAddressFamily(req, stunMsg, a, messageIntegrity); err != nil {
		return err
	}

	if lifetimeDuration != 0 {
		// A Refresh for a generation that has already been reclaimed must not
		// bring it back; Refresh reports that instead of resetting a dead timer.
		if !a.Refresh(lifetimeDuration) {
			return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
		}
	} else {
		req.AllocationManager.DeleteAllocationIf(a)
	}

	return buildAndSend(
		req.Conn,
		req.SrcAddr,
		buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse),
			[]stun.Setter{
				&proto.Lifetime{
					Duration: lifetimeDuration,
				},
				messageIntegrity,
			}...,
		)...,
	)
}

// checkRefreshAddressFamily enforces the RFC 6156 address-family rules for a
// Refresh request.
func checkRefreshAddressFamily(
	req Request,
	stunMsg *stun.Message,
	alloc *allocation.Allocation,
	messageIntegrity stun.MessageIntegrity,
) error {
	var requestedFamily proto.RequestedAddressFamily
	badRequestMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest}, messageIntegrity)

	if err := requestedFamily.GetFrom(stunMsg); err != nil {
		switch {
		case errors.Is(err, stun.ErrAttributeNotFound):
			return nil
		case stun.IsAttrSizeInvalid(err) || stun.IsAttrSizeOverflow(err):
			return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
		default:
			msg := buildMsg(
				stunMsg.TransactionID,
				stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse),
				&stun.ErrorCodeAttribute{Code: stun.CodePeerAddrFamilyMismatch}, messageIntegrity)

			return buildAndSendErr(req.Conn, req.SrcAddr, errPeerAddressFamilyMismatch, msg...)
		}
	}

	if requestedFamily != alloc.AddressFamily() {
		msg := buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodePeerAddrFamilyMismatch}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, errPeerAddressFamilyMismatch, msg...)
	}

	return nil
}

func handleCreatePermissionRequest(req Request, stunMsg *stun.Message) error {
	req.Log.Debugf("Received CreatePermission from %s", req.SrcAddr)

	messageIntegrity, hasAuth, userID, err := authenticateRequest(req, stunMsg, stun.MethodCreatePermission)
	if !hasAuth {
		return err
	}

	alloc := req.AllocationManager.GetAllocationForUserID(&allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}, userID)
	if alloc == nil {
		return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
	}

	addCount := 0
	errorCode := stun.CodeBadRequest

	if err := stunMsg.ForEach(stun.AttrXORPeerAddress, func(m *stun.Message) error {
		var peerAddress proto.PeerAddress
		if err := peerAddress.GetFrom(m); err != nil {
			errorCode = stun.CodeBadRequest

			return err
		}

		// RFC 6156: Peer address must match allocation's address family.
		if !ipMatchesFamily(peerAddress.IP, alloc.AddressFamily()) {
			req.Log.Infof("peer address family mismatch for client %s to peer %s", req.SrcAddr, peerAddress.IP)
			errorCode = stun.CodePeerAddrFamilyMismatch

			return errPeerAddressFamilyMismatch
		}

		if err := req.AllocationManager.GrantPermission(req.SrcAddr, peerAddress.IP); err != nil {
			req.Log.Infof("permission denied for client %s to peer %s", req.SrcAddr, peerAddress.IP)
			errorCode = stun.CodeForbidden

			return err
		}

		req.Log.Debugf("Adding permission for %s", net.JoinHostPort(
			peerAddress.IP.String(), strconv.Itoa(peerAddress.Port)))

		alloc.AddPermission(allocation.NewPermission(
			&net.UDPAddr{
				IP:   peerAddress.IP,
				Port: peerAddress.Port,
			},
			req.Log,
			req.PermissionTimeout,
		))
		addCount++

		return nil
	}); err != nil {
		addCount = 0
	}

	respClass := stun.ClassSuccessResponse
	if addCount == 0 {
		respClass = stun.ClassErrorResponse
	}
	attrs := []stun.Setter{messageIntegrity}
	if respClass == stun.ClassErrorResponse {
		attrs = []stun.Setter{
			&stun.ErrorCodeAttribute{Code: errorCode},
			messageIntegrity,
		}
	}

	return buildAndSend(
		req.Conn,
		req.SrcAddr,
		buildMsg(stunMsg.TransactionID, stun.NewType(stun.MethodCreatePermission, respClass),
			attrs...)...,
	)
}

func handleSendIndication(req Request, stunMsg *stun.Message) error {
	req.Log.Debugf("Received SendIndication from %s", req.SrcAddr)
	alloc := req.AllocationManager.GetAllocation(&allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	})
	if alloc == nil {
		return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
	}

	dataAttr := proto.Data{}
	if err := dataAttr.GetFrom(stunMsg); err != nil {
		return err
	}

	peerAddress := proto.PeerAddress{}
	if err := peerAddress.GetFrom(stunMsg); err != nil {
		return err
	}

	msgDst := &net.UDPAddr{IP: peerAddress.IP, Port: peerAddress.Port}
	// RFC 8656 Section 11.2: the permission check comes before any
	// address/port restrictions, and a Send indication never refreshes the
	// permission.
	if perm := alloc.GetPermission(msgDst); perm == nil {
		return fmt.Errorf("%w: %v", errNoPermission, msgDst)
	}

	// RFC 8656 Section 11.2: the server MAY impose restrictions on the peer
	// address; the peer address family must match the allocation's address
	// family (see Section 10.2). A Send indication carries no response, so
	// mismatched data is silently discarded.
	if !ipMatchesFamily(peerAddress.IP, alloc.AddressFamily()) {
		req.Log.Debugf("peer address family mismatch for client %s to peer %s", req.SrcAddr, peerAddress.IP)

		return errPeerAddressFamilyMismatch
	}

	l, err := alloc.WriteTo(dataAttr, msgDst)
	if err != nil {
		return fmt.Errorf("%w: %s", errFailedWriteSocket, err.Error())
	} else if l != len(dataAttr) {
		return fmt.Errorf("%w %d != %d (expected)", errShortWrite, l, len(dataAttr))
	}

	return err
}

func handleChannelBindRequest(req Request, stunMsg *stun.Message) error { // nolint:cyclop
	req.Log.Debugf("Received ChannelBindRequest from %s", req.SrcAddr)

	messageIntegrity, hasAuth, userID, err := authenticateRequest(req, stunMsg, stun.MethodChannelBind)
	if !hasAuth {
		return err
	}

	badRequestMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodChannelBind, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest}, messageIntegrity)

	alloc := req.AllocationManager.GetAllocationForUserID(&allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}, userID)
	if alloc == nil {
		return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
	}

	var channel proto.ChannelNumber
	if err = channel.GetFrom(stunMsg); err != nil {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	peerAddr := proto.PeerAddress{}
	if err = peerAddr.GetFrom(stunMsg); err != nil {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	// RFC 6156: Peer address must match allocation's address family.
	if !ipMatchesFamily(peerAddr.IP, alloc.AddressFamily()) {
		req.Log.Infof("peer address family mismatch for client %s to peer %s", req.SrcAddr, peerAddr.IP)

		peerAddrFamilyMismatchMsg := buildMsg(stunMsg.TransactionID,
			stun.NewType(stun.MethodChannelBind, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodePeerAddrFamilyMismatch}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, errPeerAddressFamilyMismatch, peerAddrFamilyMismatchMsg...)
	}

	if err = req.AllocationManager.GrantPermission(req.SrcAddr, peerAddr.IP); err != nil {
		req.Log.Infof("permission denied for client %s to peer %s", req.SrcAddr, peerAddr.IP)

		unauthorizedRequestMsg := buildMsg(stunMsg.TransactionID,
			stun.NewType(stun.MethodChannelBind, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeUnauthorized}, messageIntegrity)

		return buildAndSendErr(req.Conn, req.SrcAddr, err, unauthorizedRequestMsg...)
	}

	peerNetAddr := &net.UDPAddr{IP: peerAddr.IP, Port: peerAddr.Port}
	req.Log.Debugf("Binding channel %d to %s", channel, peerAddr)
	err = alloc.AddChannelBind(allocation.NewChannelBind(
		channel,
		peerNetAddr,
		req.Log,
	), req.ChannelBindTimeout, req.PermissionTimeout)
	if err != nil { // nolint:nestif
		if errors.Is(err, allocation.ErrSamePeerDifferentChannel) {
			if existing := alloc.GetChannelByAddr(peerNetAddr); existing != nil {
				req.Log.Warnf(
					"ChannelBind rejected: peer %s already bound to channel %d, attempted %d",
					peerNetAddr.String(), uint16(existing.Number), uint16(channel),
				)
			} else {
				req.Log.Warnf(
					"ChannelBind rejected: peer %s attempted to rebind to channel %d",
					peerNetAddr.String(), uint16(channel),
				)
			}
		} else if errors.Is(err, allocation.ErrSameChannelDifferentPeer) {
			if existing := alloc.GetChannelByNumber(channel); existing != nil {
				req.Log.Warnf(
					"ChannelBind rejected: channel %d already bound to peer %s, attempted peer %s",
					uint16(channel), existing.Peer.String(), peerNetAddr.String(),
				)
			} else {
				req.Log.Warnf(
					"ChannelBind rejected: channel %d attempted to bind to peer %s",
					uint16(channel), peerNetAddr.String(),
				)
			}
		}

		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	return buildAndSend(
		req.Conn,
		req.SrcAddr,
		buildMsg(stunMsg.TransactionID, stun.NewType(stun.MethodChannelBind, stun.ClassSuccessResponse),
			[]stun.Setter{messageIntegrity}...)...,
	)
}

func handleChannelData(req Request, channelData *proto.ChannelData) error {
	req.Log.Debugf("Received ChannelData from %s", req.SrcAddr)

	alloc := req.AllocationManager.GetAllocation(&allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	})
	if alloc == nil {
		return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
	}

	channel := alloc.GetChannelByNumber(channelData.Number)
	if channel == nil {
		return fmt.Errorf("%w %x", errNoSuchChannelBind, uint16(channelData.Number))
	}

	l, err := alloc.WriteTo(channelData.Data, channel.Peer)
	if err != nil {
		return fmt.Errorf("%w: %s", errFailedWriteSocket, err.Error())
	} else if l != len(channelData.Data) {
		return fmt.Errorf("%w %d != %d (expected)", errShortWrite, l, len(channelData.Data))
	}

	return nil
}

func handleConnectRequest(req Request, stunMsg *stun.Message) error {
	req.Log.Debugf("Received Connect from %s", req.SrcAddr)

	messageIntegrity, hasAuth, userID, err := authenticateRequest(req, stunMsg, stun.MethodConnect)
	if !hasAuth {
		return err
	}

	alloc := req.AllocationManager.GetAllocationForUserID(&allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}, userID)
	if alloc == nil {
		return fmt.Errorf("%w %v:%v", errNoAllocationFound, req.SrcAddr, req.Conn.LocalAddr())
	}

	// If the request does not contain an XOR-PEER-ADDRESS attribute, or if
	// such attribute is invalid, the server MUST return a 400 (Bad Request)
	// error.
	var peerAddr proto.PeerAddress
	if err = peerAddr.GetFrom(stunMsg); err != nil {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodConnect, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest}, messageIntegrity)...)
	}

	if err = req.AllocationManager.GrantPermission(req.SrcAddr, peerAddr.IP); err != nil {
		req.Log.Infof("permission denied for client %s to peer %s", req.SrcAddr, peerAddr.IP)

		return buildAndSendErr(req.Conn, req.SrcAddr, err, buildMsg(
			stunMsg.TransactionID,
			stun.NewType(stun.MethodConnect, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: stun.CodeForbidden}, messageIntegrity)...)
	}

	connectionID, err := req.AllocationManager.CreateTCPConnection(alloc, peerAddr)
	if err != nil {
		// If the server is currently processing a Connect request for this
		// allocation with the same XOR-PEER-ADDRESS, it MUST return a 446
		// (Connection Already Exists) error.

		// If the server has already successfully processed a Connect request
		// for this allocation with the same XOR-PEER-ADDRESS, and the resulting
		// client and peer data connections are either pending or active, it
		// MUST return a 446 (Connection Already Exists) error.
		if errors.Is(err, allocation.ErrDupeTCPConnection) {
			return buildAndSendErr(req.Conn, req.SrcAddr, err, buildMsg(
				stunMsg.TransactionID,
				stun.NewType(stun.MethodConnect, stun.ClassErrorResponse),
				&stun.ErrorCodeAttribute{Code: stun.CodeConnAlreadyExists}, messageIntegrity)...)
		}

		// Otherwise, the server MUST initiate an outgoing TCP connection.  The
		// local endpoint is the relayed transport address associated with the
		// allocation.  The remote endpoint is the one indicated by the XOR-
		// PEER-ADDRESS attribute.  If the connection attempt fails or times
		// out, the server MUST return a 447 (Connection Timeout or Failure)
		// error.  The timeout value MUST be at least 30 seconds.
		if errors.Is(err, allocation.ErrTCPConnectionTimeoutOrFailure) {
			return buildAndSendErr(req.Conn, req.SrcAddr, err, buildMsg(
				stunMsg.TransactionID,
				stun.NewType(stun.MethodConnect, stun.ClassErrorResponse),
				&stun.ErrorCodeAttribute{Code: stun.CodeConnTimeoutOrFailure}, messageIntegrity)...)
		}

		return err
	}

	// The server MUST include the CONNECTION-ID attribute in the Connect
	// success response.  The attribute's value MUST uniquely identify the
	// peer data connection.
	return buildAndSend(req.Conn, req.SrcAddr, buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodConnect, stun.ClassSuccessResponse),
		connectionID,
		messageIntegrity,
	)...)
}

func handleConnectionBindRequest(req Request, stunMsg *stun.Message) error {
	req.Log.Debugf("Received ConnectBind from %s", req.SrcAddr)
	messageIntegrity, hasAuth, userID, err := authenticateRequest(req, stunMsg, stun.MethodConnectionBind)
	if !hasAuth {
		return err
	}

	badRequestMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodConnectionBind, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest}, messageIntegrity)

	var connectionID proto.ConnectionID
	if err = connectionID.GetFrom(stunMsg); err != nil {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	// Authentication of the client by the server MUST use the same method
	// and credentials as for the control connection.
	//
	// GetTCPConnection asserts that userName used for auth is same as allocation
	tcpConn := req.AllocationManager.GetTCPConnection(userID, connectionID)
	if tcpConn == nil {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	stunConn, ok := req.Conn.(*proto.STUNConn)
	if !ok {
		return buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	if err = buildAndSend(req.Conn, req.SrcAddr, buildMsg(
		stunMsg.TransactionID,
		stun.NewType(stun.MethodConnectionBind, stun.ClassSuccessResponse),
		connectionID,
		messageIntegrity,
	)...); err != nil {
		return err
	}

	copyCompleteCtx, copyCompleteCancel := context.WithCancel(context.Background())
	go func() {
		if _, ioErr := io.Copy(tcpConn, stunConn.Conn()); ioErr != nil {
			req.Log.Debugf("Exit tcpConn->stunConn read loop on error: %s", ioErr)
		}
		copyCompleteCancel()
	}()

	go func() {
		if _, ioErr := io.Copy(stunConn.Conn(), tcpConn); ioErr != nil {
			req.Log.Debugf("Exit stunConn->tcpConn read loop on error: %s", ioErr)
		}
		copyCompleteCancel()
	}()

	// When either side has failed close both
	<-copyCompleteCtx.Done()
	if err = tcpConn.Close(); err != nil {
		req.Log.Debugf("Close tcpConn error: %s", err)
	}
	if err = stunConn.Conn().Close(); err != nil {
		req.Log.Debugf("Close stunConn error: %s", err)
	}

	req.AllocationManager.RemoveTCPConnection(connectionID)

	return nil
}

// ipMatchesFamily checks if an IP address matches the given address family.
func ipMatchesFamily(ip net.IP, family proto.RequestedAddressFamily) bool {
	if family == proto.RequestedFamilyIPv4 {
		return ip.To4() != nil
	}
	if family == proto.RequestedFamilyIPv6 {
		return ip.To4() == nil && ip.To16() != nil
	}

	return false
}

func defaultAllocationAddressFamily(req Request) proto.RequestedAddressFamily {
	if req.StrictAddressFamily {
		return proto.RequestedFamilyIPv4
	}

	ip, _, err := ipnet.AddrIPPort(req.Conn.LocalAddr())
	if err != nil {
		return proto.RequestedFamilyIPv4
	}

	// some dual-stack wildcard sockets can report [::] as LocalAddr even for IPv4 or
	// ipv6-mapped IPv4 addresses.
	if ip.IsUnspecified() {
		if family, ok := addressFamilyFromAddr(req.SrcAddr); ok {
			return family
		}
	}

	if family, ok := addressFamilyFromIP(ip); ok {
		return family
	}

	return proto.RequestedFamilyIPv4
}

func addressFamilyFromAddr(addr net.Addr) (proto.RequestedAddressFamily, bool) {
	ip, _, err := ipnet.AddrIPPort(addr)
	if err != nil {
		return 0, false
	}

	return addressFamilyFromIP(ip)
}

func addressFamilyFromIP(ip net.IP) (proto.RequestedAddressFamily, bool) {
	if ip.To4() != nil {
		return proto.RequestedFamilyIPv4, true
	}
	if ip.To16() != nil {
		return proto.RequestedFamilyIPv6, true
	}

	return 0, false
}
