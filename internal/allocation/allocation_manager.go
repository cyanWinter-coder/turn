// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package allocation

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/randutil"
	"github.com/pion/turn/v5/internal/proto"
)

// If no ConnectionBind request associated with this peer data
// connection is received after 30 seconds, the peer data connection
// MUST be closed.
const defaultTCPConnectionBindTimeout = time.Second * 30

// AllocateListenerConfig contains the parameters passed to the relay address allocator
// when creating a new UDP or TCP allocation.
type AllocateListenerConfig struct {
	// Network specifies the network type for the allocation: "udp4", "udp6", "tcp4", or "tcp6".
	Network string
	// UserID is the authenticated user's identifier as returned by the AuthHandler.
	//
	// Note: The UserID is typcally the same as the TURN username, except for authentication
	// schemes that overload the username field with additional info (e.g., the lifetime of the
	// credential, as in the time-windowed credential mechanism in
	// https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00.
	UserID string
	// Realm is the TURN realm for this allocation.
	Realm string
	// RequestedPort is the port requested by the client in the TURN Allocate request.
	// A value of 0 indicates that the client did not request a specific port and any
	// available port may be used.
	RequestedPort int
	// Generation identifies the admission attempt that triggered this call. It is
	// incremented for every attempt, so a generator that keeps state can tell a
	// retry from the original request.
	Generation uint64
}

// AllocateConnConfig contains the parameters passed to the relay address allocator
// when creating a new outbound TCP connection for RFC 6062 (TURN TCP) Connect requests.
type AllocateConnConfig struct {
	// Network specifies the network type for the connection: "tcp4" or "tcp6".
	Network string
	// UserID is the authenticated user's identifier as returned by the AuthHandler.
	//
	// Note: The UserID is typcally the same as the TURN username, except for authentication
	// schemes that overload the username field with additional info (e.g., the lifetime of the
	// credential, as in the time-windowed credential mechanism in
	// https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00.
	UserID string
	// Realm is the TURN realm for this allocation.
	Realm string
	// LocalAddr is the relay address to bind the local side of the connection
	// to. Implementations must allocate the local address as requested.
	LocalAddr net.Addr
	// RemoteAddr is the peer address to connect to.
	RemoteAddr net.Addr
}

// ManagerConfig a bag of config params for Manager.
type ManagerConfig struct {
	LeveledLogger      logging.LeveledLogger
	AllocatePacketConn func(info AllocateListenerConfig) (net.PacketConn, net.Addr, error)
	AllocateListener   func(info AllocateListenerConfig) (net.Listener, net.Addr, error)
	AllocateConn       func(info AllocateConnConfig) (net.Conn, error)
	PermissionHandler  func(sourceAddr net.Addr, peerIP net.IP) bool
	EventHandler       EventHandler

	tcpConnectionBindTimeout time.Duration
}

type reservation struct {
	token string
	port  int
	timer *time.Timer
}

// Admission is the right to create the single allocation for a five-tuple. It
// is obtained from Manager.BeginAdmission after authentication has passed and
// before any relay port or quota slot is consumed. While it is held, other
// Allocate requests for the same five-tuple are rejected with
// ErrAdmissionInProgress, so only one relay address is ever reserved for it.
//
// An Admission must be finished by CreateAllocationWithAdmission. If that is
// not possible, Abort releases it so a later retry can use a fresh generation.
// Abort is idempotent.
type Admission struct {
	manager     *Manager
	fiveTuple   *FiveTuple
	fingerprint FiveTupleFingerprint
	generation  uint64
	committed   bool // guarded by manager lock
	aborted     bool // guarded by manager lock
}

// Generation identifies this admission attempt. It increases monotonically for
// every admission the manager grants, including retries after a failed attempt.
func (a *Admission) Generation() uint64 {
	return a.generation
}

// Abort releases the admission if it has not been committed. It is safe to call
// multiple times and after a successful commit (where it is a no-op).
func (a *Admission) Abort() {
	if a == nil || a.manager == nil {
		return
	}

	a.manager.abortAdmission(a)
}

// Manager is used to hold active allocations.
type Manager struct {
	lock                     sync.RWMutex
	log                      logging.LeveledLogger
	tcpConnectionBindTimeout time.Duration

	allocations  map[FiveTupleFingerprint]*Allocation
	admitting    map[FiveTupleFingerprint]*Admission
	reservations []*reservation
	generation   uint64
	closed       bool

	allocatePacketConn func(conf AllocateListenerConfig) (net.PacketConn, net.Addr, error)
	allocateListener   func(conf AllocateListenerConfig) (net.Listener, net.Addr, error)
	allocateConn       func(conf AllocateConnConfig) (net.Conn, error)
	permissionHandler  func(sourceAddr net.Addr, peerIP net.IP) bool
	EventHandler       EventHandler
}

// NewManager creates a new instance of Manager.
func NewManager(config ManagerConfig) (*Manager, error) {
	switch {
	case config.AllocatePacketConn == nil:
		return nil, errAllocatePacketConnMustBeSet
	case config.AllocateListener == nil:
		return nil, errAllocateListenerMustBeSet
	case config.AllocateConn == nil:
		return nil, errAllocateConnMustBeSet
	case config.LeveledLogger == nil:
		return nil, errLeveledLoggerMustBeSet
	}

	tcpConnectionBindTimeout := config.tcpConnectionBindTimeout
	if tcpConnectionBindTimeout == 0 {
		tcpConnectionBindTimeout = defaultTCPConnectionBindTimeout
	}

	return &Manager{
		log:                      config.LeveledLogger,
		allocations:              make(map[FiveTupleFingerprint]*Allocation, 64),
		admitting:                make(map[FiveTupleFingerprint]*Admission),
		allocatePacketConn:       config.AllocatePacketConn,
		allocateListener:         config.AllocateListener,
		allocateConn:             config.AllocateConn,
		permissionHandler:        config.PermissionHandler,
		EventHandler:             config.EventHandler,
		tcpConnectionBindTimeout: tcpConnectionBindTimeout,
	}, nil
}

// BeginAdmission reserves the right to create the allocation for fiveTuple.
//
// It must be called after authentication has passed and before the relay
// address is obtained from the generator, so a request that is going to be
// rejected never consumes a relay port or a quota slot. While the admission is
// held, concurrent Allocate requests for the same five-tuple fail with
// ErrAdmissionInProgress instead of each reserving their own relay address. A
// failed attempt must call Abort so that a retry gets a new generation.
func (m *Manager) BeginAdmission(fiveTuple *FiveTuple) (*Admission, error) {
	switch {
	case fiveTuple == nil:
		return nil, errNilFiveTuple
	case fiveTuple.SrcAddr == nil:
		return nil, errNilFiveTupleSrcAddr
	case fiveTuple.DstAddr == nil:
		return nil, errNilFiveTupleDstAddr
	}

	fingerprint := fiveTuple.Fingerprint()

	m.lock.Lock()
	defer m.lock.Unlock()

	switch {
	case m.closed:
		return nil, errManagerClosed
	case m.allocations[fingerprint] != nil:
		return nil, fmt.Errorf("%w: %v", ErrAllocationExists, fiveTuple)
	}

	if _, inProgress := m.admitting[fingerprint]; inProgress {
		return nil, fmt.Errorf("%w: %v", ErrAdmissionInProgress, fiveTuple)
	}

	m.generation++
	admission := &Admission{
		manager:     m,
		fiveTuple:   fiveTuple,
		fingerprint: fingerprint,
		generation:  m.generation,
	}
	m.admitting[fingerprint] = admission

	return admission, nil
}

func (m *Manager) abortAdmission(admission *Admission) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if admission.committed || admission.aborted {
		return
	}
	admission.aborted = true

	if current, ok := m.admitting[admission.fingerprint]; ok && current == admission {
		delete(m.admitting, admission.fingerprint)
	}
}

// AdmissionInProgress reports whether an Allocate request for fiveTuple is
// currently being admitted.
func (m *Manager) AdmissionInProgress(fiveTuple *FiveTuple) bool {
	if fiveTuple == nil {
		return false
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	_, inProgress := m.admitting[fiveTuple.Fingerprint()]

	return inProgress
}

// AdmissionCount returns the number of Allocate requests currently being
// admitted.
func (m *Manager) AdmissionCount() int {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return len(m.admitting)
}

// GetAllocation fetches the allocation matching the passed FiveTuple.
func (m *Manager) GetAllocation(fiveTuple *FiveTuple) *Allocation {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.allocations[fiveTuple.Fingerprint()]
}

// GetAllocationForUserID fetches the allocation matching the passed FiveTuple and Username.
func (m *Manager) GetAllocationForUserID(fiveTuple *FiveTuple, userID string) *Allocation {
	allocation := m.GetAllocation(fiveTuple)
	if allocation != nil && allocation.userID == userID {
		return allocation
	}

	return nil
}

// AllocationCount returns the number of existing allocations.
func (m *Manager) AllocationCount() int {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return len(m.allocations)
}

// Close closes the manager and closes all allocations it manages.
func (m *Manager) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.closed = true
	// Abort every in-flight admission so their failure paths cannot leave
	// reservations behind and retries fail fast against a closed manager.
	for _, admission := range m.admitting {
		admission.aborted = true
	}
	clear(m.admitting)

	for _, r := range m.reservations {
		if r.timer != nil {
			r.timer.Stop()
		}
	}
	clear(m.reservations)

	for _, a := range m.allocations {
		if err := a.Close(); err != nil {
			return err
		}
	}
	clear(m.allocations)

	return nil
}

// CreateAllocation creates a new allocation and starts relaying. It is
// equivalent to BeginAdmission followed by CreateAllocationWithAdmission, and is
// kept for callers that have no checks to run between the two steps.
func (m *Manager) CreateAllocation( // nolint: cyclop
	fiveTuple *FiveTuple,
	turnSocket net.PacketConn,
	protocol proto.Protocol,
	requestedPort int,
	lifetime time.Duration,
	userID, realm string,
	addressFamily proto.RequestedAddressFamily,
) (*Allocation, error) {
	admission, err := m.BeginAdmission(fiveTuple)
	if err != nil {
		return nil, err
	}

	return m.CreateAllocationWithAdmission(
		admission, turnSocket, protocol, requestedPort, lifetime, userID, realm, addressFamily,
	)
}

// CreateAllocationWithAdmission reserves the relay address and publishes the
// allocation for an admission obtained from BeginAdmission.
//
// Nothing is retained unless the whole transaction succeeds: a generator
// failure, a concurrent publication or a closed manager aborts the admission and
// closes any relay socket that was already created, so no relay port or quota
// slot is leaked. Any failure also frees the five-tuple for a retry with a fresh
// generation.
func (m *Manager) CreateAllocationWithAdmission( // nolint: cyclop
	admission *Admission,
	turnSocket net.PacketConn,
	protocol proto.Protocol,
	requestedPort int,
	lifetime time.Duration,
	userID, realm string,
	addressFamily proto.RequestedAddressFamily,
) (*Allocation, error) {
	if admission == nil || admission.manager != m {
		return nil, errAdmissionRequired
	}
	fiveTuple := admission.fiveTuple

	switch {
	case turnSocket == nil:
		admission.Abort()

		return nil, errNilTurnSocket
	case lifetime == 0:
		admission.Abort()

		return nil, errLifetimeZero
	}

	switch protocol {
	case proto.ProtoUDP, proto.ProtoTCP:
	default:
		admission.Abort()

		return nil, errUnsupportedTransport
	}

	// Abort is a no-op after a successful commit, so every failure path below
	// unlocks the five-tuple exactly once.
	defer admission.Abort()

	alloc := NewAllocation(turnSocket, fiveTuple, m.EventHandler, m.log)
	alloc.userID = userID
	alloc.realm = realm
	alloc.addressFamily = addressFamily
	alloc.generation = admission.generation

	switch protocol {
	case proto.ProtoUDP:
		network := "udp4"
		if addressFamily == proto.RequestedFamilyIPv6 {
			network = "udp6"
		}
		conn, relayAddr, err := m.allocatePacketConn(AllocateListenerConfig{
			Network:       network,
			UserID:        userID,
			Realm:         realm,
			RequestedPort: requestedPort,
			Generation:    admission.generation,
		})
		if err != nil {
			return nil, err
		}
		alloc.relayPacketConn = conn
		alloc.RelayAddr = relayAddr
	case proto.ProtoTCP:
		network := "tcp4"
		if addressFamily == proto.RequestedFamilyIPv6 {
			network = "tcp6"
		}
		ln, relayAddr, err := m.allocateListener(AllocateListenerConfig{
			Network:       network,
			UserID:        userID,
			Realm:         realm,
			RequestedPort: requestedPort,
			Generation:    admission.generation,
		})
		if err != nil {
			return nil, err
		}
		alloc.relayListener = ln
		alloc.RelayAddr = relayAddr
	}

	m.log.Debugf("Listening on relay address: %s", alloc.RelayAddr)

	// Publish and commit under the same lock that guards admission lookups, so a
	// concurrent Allocate either sees the allocation or sees the admission still
	// in progress, never a half-published allocation.
	m.lock.Lock()
	if m.closed {
		m.lock.Unlock()
		closeUnpublishedAllocation(alloc, m.log)
		m.log.Debugf("Manager closed while admitting allocation for %v", fiveTuple)

		return nil, errManagerClosed
	}
	if existing := m.allocations[admission.fingerprint]; existing != nil {
		m.lock.Unlock()
		closeUnpublishedAllocation(alloc, m.log)
		m.log.Debugf("Allocation for %v was published concurrently, discarding duplicate", fiveTuple)

		return nil, fmt.Errorf("%w: %v", ErrAllocationExists, fiveTuple)
	}

	alloc.lifetimeTimer = time.AfterFunc(lifetime, func() {
		m.DeleteAllocationIf(alloc)
	})
	m.allocations[admission.fingerprint] = alloc
	admission.committed = true
	delete(m.admitting, admission.fingerprint)
	m.lock.Unlock()

	if m.EventHandler.OnAllocationCreated != nil {
		m.EventHandler.OnAllocationCreated(fiveTuple.SrcAddr, fiveTuple.DstAddr,
			fiveTuple.Protocol.String(), userID, realm, alloc.RelayAddr, requestedPort)
	}

	// Only start the UDP relay loop for UDP allocations.
	if alloc.relayPacketConn != nil {
		go alloc.packetConnHandler(m)
	}
	// For TCP allocations, accept inbound connections on the relayed listener and notify the client.
	if alloc.relayListener != nil {
		go alloc.connHandler(m)
	}

	return alloc, nil
}

// closeUnpublishedAllocation closes the relay sockets of an allocation that was
// never published. It must not touch the manager, so it is safe on every early
// return path.
func closeUnpublishedAllocation(alloc *Allocation, log logging.LeveledLogger) {
	if err := alloc.Close(); err != nil {
		log.Errorf("Failed to close unpublished allocation %v: %v", alloc.fiveTuple, err)
	}
}

// DeleteAllocation removes an allocation.
func (m *Manager) DeleteAllocation(fiveTuple *FiveTuple) {
	if fiveTuple == nil {
		return
	}

	m.removeAllocation(fiveTuple.Fingerprint(), nil)
}

// DeleteAllocationIf removes the allocation only if it is still the one the
// caller observed. Lifetime timers and relay loops use it so a stale generation
// can never tear down the allocation that replaced it.
func (m *Manager) DeleteAllocationIf(allocation *Allocation) {
	if allocation == nil {
		return
	}

	m.removeAllocation(allocation.fiveTuple.Fingerprint(), allocation)
}

// DeleteAllocationForConn is like DeleteAllocationForSocket for a stream control
// connection; the allocation's TURN socket may be a wrapper (such as
// proto.STUNConn) around the connection that carried the request.
func (m *Manager) DeleteAllocationForConn(fiveTuple *FiveTuple, turnConn net.Conn) {
	if fiveTuple == nil || turnConn == nil {
		return
	}

	m.deleteAllocationServedBy(fiveTuple.Fingerprint(), func(a *Allocation) bool {
		return turnSocketWraps(a.TurnSocket, turnConn)
	})
}

// turnSocketWraps reports whether turnSocket is turnConn or a packet conn that
// wraps it. TURN over TCP/TLS allocates against a *proto.STUNConn, so a plain
// identity check would miss the connection that owns the allocation.
func turnSocketWraps(turnSocket net.PacketConn, turnConn net.Conn) bool {
	if turnSocket == nil {
		return false
	}

	if conn, ok := turnSocket.(net.Conn); ok && conn == turnConn {
		return true
	}

	if unwrapper, ok := turnSocket.(interface{ Conn() net.Conn }); ok {
		return unwrapper.Conn() == turnConn
	}

	return false
}

func (m *Manager) deleteAllocationServedBy(fingerprint FiveTupleFingerprint, serves func(*Allocation) bool) {
	m.lock.RLock()
	current := m.allocations[fingerprint]
	m.lock.RUnlock()

	if current == nil || !serves(current) {
		return
	}

	m.removeAllocation(fingerprint, current)
}

// removeAllocation detaches and closes the allocation for fingerprint. When
// expected is non-nil the allocation is only removed if it is still the same
// object. The manager lock is held across the identity check and the close so a
// lifetime timer or relay-loop error from an older generation cannot remove its
// replacement, and a fresh admission cannot interleave with teardown. All
// reclaim paths therefore observe the same order: detach, stop timers and
// permissions, close the relay socket, call OnAllocationDeleted exactly once.
func (m *Manager) removeAllocation(fingerprint FiveTupleFingerprint, expected *Allocation) {
	m.lock.Lock()

	allocation := m.allocations[fingerprint]
	if allocation == nil || (expected != nil && allocation != expected) {
		m.lock.Unlock()

		return
	}
	delete(m.allocations, fingerprint)

	if err := allocation.Close(); err != nil {
		m.log.Errorf("Failed to close allocation: %v", err)
	}
	m.lock.Unlock()

	if m.EventHandler.OnAllocationDeleted != nil {
		m.EventHandler.OnAllocationDeleted(allocation.fiveTuple.SrcAddr, allocation.fiveTuple.DstAddr,
			allocation.fiveTuple.Protocol.String(), allocation.userID, allocation.realm)
	}
}

// CreateReservation stores the reservation for the token+port.
func (m *Manager) CreateReservation(reservationToken string, port int) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.closed {
		return
	}

	m.reservations = append(m.reservations, m.newReservationLocked(reservationToken, port))
}

// RestoreReservation puts back a reservation that was taken by TakeReservation
// but could not be used, with a fresh expiry window. The reserved port itself is
// not bound by the reservation, so the reservation can still be honored by a
// retry.
func (m *Manager) RestoreReservation(reservationToken string, port int) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.closed {
		return
	}

	for _, r := range m.reservations {
		if r.token == reservationToken {
			return
		}
	}

	m.reservations = append(m.reservations, m.newReservationLocked(reservationToken, port))
}

// newReservationLocked builds a reservation with its expiry timer. The manager
// lock must be held.
func (m *Manager) newReservationLocked(reservationToken string, port int) *reservation {
	r := &reservation{
		token: reservationToken,
		port:  port,
	}
	r.timer = time.AfterFunc(30*time.Second, func() {
		m.expireReservation(r)
	})

	return r
}

func (m *Manager) expireReservation(target *reservation) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for i, r := range m.reservations {
		if r == target {
			m.reservations = append(m.reservations[:i], m.reservations[i+1:]...)

			return
		}
	}
}

// GetReservation returns the port for a given reservation if it exists.
func (m *Manager) GetReservation(reservationToken string) (int, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	for _, r := range m.reservations {
		if r.token == reservationToken {
			return r.port, true
		}
	}

	return 0, false
}

// TakeReservation consumes a reservation, returning its port. A reservation can
// only be used once, so a retried Allocate with the same token does not hand out
// a relay address that has already been claimed.
func (m *Manager) TakeReservation(reservationToken string) (int, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	r := m.takeReservationLocked(func(r *reservation) bool { return r.token == reservationToken })
	if r == nil {
		return 0, false
	}

	return r.port, true
}

// RemoveReservation drops a reservation that can no longer be honored, for
// example because the Allocate response that carried it could not be sent.
func (m *Manager) RemoveReservation(reservationToken string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.takeReservationLocked(func(r *reservation) bool { return r.token == reservationToken })
}

// takeReservationLocked removes and returns the first reservation matching
// match, stopping its expiry timer. The manager lock must be held.
func (m *Manager) takeReservationLocked(match func(*reservation) bool) *reservation {
	for i, r := range m.reservations {
		if !match(r) {
			continue
		}

		if r.timer != nil {
			r.timer.Stop()
		}
		m.reservations = append(m.reservations[:i], m.reservations[i+1:]...)

		return r
	}

	return nil
}

// GetRandomEvenPort returns a random un-allocated udp4 port.
func (m *Manager) GetRandomEvenPort() (int, error) {
	for range 128 {
		conn, addr, err := m.allocatePacketConn(AllocateListenerConfig{Network: "udp4"})
		if err != nil {
			return 0, err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		err = conn.Close()
		if err != nil {
			return 0, err
		}

		if !ok {
			return 0, errFailedToCastUDPAddr
		}
		if udpAddr.Port%2 == 0 {
			return udpAddr.Port, nil
		}
	}

	return 0, errFailedToAllocateEvenPort
}

// GrantPermission handles permission requests by calling the permission handler callback
// associated with the TURN server listener socket.
func (m *Manager) GrantPermission(sourceAddr net.Addr, peerIP net.IP) error {
	// No permission handler: open
	if m.permissionHandler == nil {
		return nil
	}

	if m.permissionHandler(sourceAddr, peerIP) {
		return nil
	}

	return errAdminProhibited
}

// CreateTCPConnection creates a new outbound TCP Connection and returns the Connection-ID
// if it succeeds.
func (m *Manager) CreateTCPConnection( // nolint: cyclop
	allocation *Allocation,
	peerAddress proto.PeerAddress,
) (proto.ConnectionID, error) {
	if len(peerAddress.IP) == 0 || peerAddress.Port == 0 {
		return 0, errInvalidPeerAddress
	}

	relayAddr := allocation.RelayAddr
	if allocation.RelayAddr == nil {
		m.log.Warn("Failed to create TCP Connection: Relay address not available")

		return 0, ErrTCPConnectionTimeoutOrFailure
	}

	remoteAddr := &net.TCPAddr{IP: peerAddress.IP, Port: peerAddress.Port}

	m.lock.Lock()
	isDupe := m.isDupeTCPConnection(allocation, remoteAddr)
	m.lock.Unlock()
	if isDupe {
		return 0, ErrDupeTCPConnection
	}

	// RFC 6156:
	// "After the request has been successfully authenticated, the TURN
	// server allocates a transport address of the type indicated in the
	// REQUESTED-ADDRESS-FAMILY attribute."
	network := "tcp4"
	if allocation.AddressFamily() == proto.RequestedFamilyIPv6 {
		network = "tcp6"
	}

	conn, err := m.allocateConn(AllocateConnConfig{
		Network:    network,
		UserID:     allocation.userID,
		Realm:      allocation.realm,
		LocalAddr:  relayAddr,
		RemoteAddr: remoteAddr,
	}) // nolint: noctx
	if err != nil {
		m.log.Warnf("Failed to create TCP Connection: %v", err)

		return 0, ErrTCPConnectionTimeoutOrFailure
	}

	connectionID, err := m.addTCPConnection(allocation, conn)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			m.log.Warnf("Failed to close TCP connection after ConnectionID generation failed: %v", closeErr)
		}
	}

	return connectionID, err
}

func (m *Manager) addTCPConnection(allocation *Allocation, conn net.Conn) (proto.ConnectionID, error) {
	rand64, err := randutil.CryptoUint64()
	if err != nil {
		return 0, err
	}

	connectionID := proto.ConnectionID(uint32(rand64 >> 32)) // nolint: gosec

	m.lock.Lock()
	defer m.lock.Unlock()

	for _, a := range m.allocations {
		if _, ok := a.tcpConnections[connectionID]; ok {
			return 0, errFailedToGenerateConnectionID
		}
	}

	newConnAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0, ErrDupeTCPConnection
	}

	if m.isDupeTCPConnection(allocation, newConnAddr) {
		return 0, ErrDupeTCPConnection
	}

	tcpConn := &tcpConnection{conn, atomic.Bool{}, nil}
	allocation.tcpConnections[connectionID] = tcpConn
	tcpConn.bindTimer = time.AfterFunc(m.tcpConnectionBindTimeout, func() {
		if !tcpConn.isBound.Load() {
			m.log.Warnf("Removing TCP Connection that was never bound %v %v", connectionID, allocation.fiveTuple)
			allocation.RemoveTCPConnection(m, connectionID)
		}
	})

	return connectionID, nil
}

func (m *Manager) isDupeTCPConnection(allocation *Allocation, remoteAddr *net.TCPAddr) bool {
	for i := range allocation.tcpConnections {
		tcpAddr, ok := allocation.tcpConnections[i].RemoteAddr().(*net.TCPAddr)
		if !ok {
			return true
		} else if tcpAddr.IP.Equal(remoteAddr.IP) && tcpAddr.Port == remoteAddr.Port {
			return true
		}
	}

	return false
}

// GetTCPConnection returns the TCP Connection for the given ConnectionID.
func (m *Manager) GetTCPConnection(userID string, connectionID proto.ConnectionID) net.Conn {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, a := range m.allocations {
		if tcpConnection, ok := a.tcpConnections[connectionID]; ok {
			if a.userID != userID || tcpConnection.isBound.Swap(true) {
				return nil
			}

			tcpConnection.bindTimer.Stop()

			return tcpConnection
		}
	}

	return nil
}

func (m *Manager) RemoveTCPConnection(connectionID proto.ConnectionID) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, a := range m.allocations {
		if _, ok := a.tcpConnections[connectionID]; ok {
			a.removeTCPConnection(connectionID)
		}
	}
}
