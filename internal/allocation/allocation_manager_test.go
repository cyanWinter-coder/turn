// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package allocation

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v5/reuseport"
	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestGeneratorUnavailable = errors.New("relay generator unavailable")

func TestNewManagerValidation(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	cfg := ManagerConfig{}

	manager, err := NewManager(cfg)
	assert.Nil(t, manager)
	assert.ErrorIs(t, err, errAllocatePacketConnMustBeSet)

	cfg.AllocatePacketConn = func(AllocateListenerConfig) (net.PacketConn, net.Addr, error) { return nil, nil, nil }
	manager, err = NewManager(cfg)
	assert.Nil(t, manager)
	assert.ErrorIs(t, err, errAllocateListenerMustBeSet)

	cfg.AllocateListener = func(AllocateListenerConfig) (net.Listener, net.Addr, error) { return nil, nil, nil }
	manager, err = NewManager(cfg)
	assert.Nil(t, manager)
	assert.ErrorIs(t, err, errAllocateConnMustBeSet)

	cfg.AllocateConn = func(AllocateConnConfig) (net.Conn, error) { return nil, nil } //nolint:nilnil
	manager, err = NewManager(cfg)
	assert.Nil(t, manager)
	assert.ErrorIs(t, err, errLeveledLoggerMustBeSet)

	cfg.LeveledLogger = loggerFactory.NewLogger("test")
	manager, err = NewManager(cfg)
	assert.NotNil(t, manager)
	assert.NoError(t, err)
	assert.NoError(t, manager.Close())
}

// Test invalid Allocation creations.
func TestCreateInvalidAllocation(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	alloc, err := manager.CreateAllocation(nil, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.Nil(t, alloc, "Illegally created allocation with nil FiveTuple")
	assert.Error(t, err, "Illegally created allocation with nil FiveTuple")

	alloc, err = manager.CreateAllocation(randomFiveTuple(), nil, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.Nil(t, alloc, "Illegally created allocation with nil turnSocket")
	assert.Error(t, err, "Illegally created allocation with nil turnSocket")

	alloc, err = manager.CreateAllocation(randomFiveTuple(), turnSocket, proto.ProtoUDP,
		0, 0, "", "", proto.RequestedFamilyIPv4)
	assert.Nil(t, alloc, "Illegally created allocation with 0 lifetime")
	assert.Error(t, err, "Illegally created allocation with 0 lifetime")

	assert.NoError(t, manager.Close())
	assert.NoError(t, turnSocket.Close())
}

// Test valid Allocation creations.
func TestCreateAllocation(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	alloc, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NotNil(t, alloc, "Failed to create allocation")
	assert.NoError(t, err, "Failed to create allocation")

	alloc = manager.GetAllocation(fiveTuple)
	assert.NotNil(t, alloc, "Failed to get allocation right after creation")

	assert.NoError(t, manager.Close())
	assert.NoError(t, turnSocket.Close())
}

// Test that two allocations can't be created with the same FiveTuple.
func TestCreateAllocationDuplicateFiveTuple(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	alloc, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NotNil(t, alloc, "Failed to create allocation")
	assert.NoError(t, err, "Failed to create allocation")

	alloc, err = manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.Nil(t, alloc, "Was able to create allocation with same FiveTuple twice")
	assert.Error(t, err, "Was able to create allocation with same FiveTuple twice")

	assert.NoError(t, manager.Close())
	assert.NoError(t, turnSocket.Close())
}

func TestDeleteAllocation(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	alloc, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NotNil(t, alloc, "Failed to create allocation")
	assert.NoError(t, err, "Failed to create allocation")

	alloc = manager.GetAllocation(fiveTuple)
	assert.NotNil(t, alloc, "Failed to get allocation right after creation")

	manager.DeleteAllocation(fiveTuple)
	alloc = manager.GetAllocation(fiveTuple)
	assert.Nilf(t, alloc, "Failed to delete allocation %v", fiveTuple)

	assert.NoError(t, manager.Close())
	assert.NoError(t, turnSocket.Close())
}

// Test that allocation should be closed if timeout.
func TestAllocationTimeout(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	allocations := make([]*Allocation, 5)
	lifetime := time.Second

	for index := range allocations {
		fiveTuple := randomFiveTuple()

		alloc, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
			0, lifetime, "", "", proto.RequestedFamilyIPv4)
		assert.NoErrorf(t, err, "Failed to create allocation with %v", fiveTuple)

		allocations[index] = alloc
	}

	// Make sure all allocations timeout
	time.Sleep(lifetime + time.Second)
	for _, alloc := range allocations {
		assert.True(t, isClose(alloc.relayPacketConn), "Allocation relay socket should be closed if lifetime timeout")
	}

	assert.NoError(t, manager.Close())
	assert.NoError(t, turnSocket.Close())
}

// Test for manager close.
func TestManagerClose(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	allocations := make([]*Allocation, 2)

	a1, _ := manager.CreateAllocation(randomFiveTuple(), turnSocket, proto.ProtoUDP,
		0, time.Second, "", "", proto.RequestedFamilyIPv4)
	allocations[0] = a1
	a2, _ := manager.CreateAllocation(randomFiveTuple(), turnSocket, proto.ProtoUDP,
		0, time.Minute, "", "", proto.RequestedFamilyIPv4)
	allocations[1] = a2

	// Make a1 timeout
	time.Sleep(2 * time.Second)
	assert.NoError(t, manager.Close())

	for _, alloc := range allocations {
		assert.True(t, isClose(alloc.relayPacketConn), "Manager's allocations should be closed")
	}

	assert.NoError(t, turnSocket.Close())
}

func randomFiveTuple() *FiveTuple {
	// nolint
	return &FiveTuple{
		SrcAddr: &net.UDPAddr{IP: nil, Port: rand.Int()},
		DstAddr: &net.UDPAddr{IP: nil, Port: rand.Int()},
	}
}

func newTestManager() (*Manager, error) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	config := ManagerConfig{
		LeveledLogger: loggerFactory.NewLogger("test"),
		AllocatePacketConn: func(_ AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			conn, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
			if err != nil {
				return nil, nil, err
			}

			return conn, conn.LocalAddr(), nil
		},
		AllocateListener: func(AllocateListenerConfig) (net.Listener, net.Addr, error) { return nil, nil, nil },
		AllocateConn: func(info AllocateConnConfig) (net.Conn, error) {
			dialer := net.Dialer{
				LocalAddr: info.LocalAddr,
				Control:   reuseport.Control,
			}

			return dialer.Dial(info.Network, info.RemoteAddr.String())
		},
	}

	return NewManager(config)
}

func isClose(conn io.Closer) bool {
	closeErr := conn.Close()

	return closeErr != nil && strings.Contains(closeErr.Error(), "use of closed network connection")
}

func TestGetRandomEvenPort(t *testing.T) {
	manager, err := newTestManager()
	assert.NoError(t, err)

	port, err := manager.GetRandomEvenPort()
	assert.NoError(t, err)
	assert.True(t, port > 0)
	assert.True(t, port%2 == 0)

	assert.NoError(t, manager.Close())
}

func TestCreateTCPConnection(t *testing.T) {
	lns := make([]net.Listener, 3)
	mu := sync.Mutex{} // make the race detector happy
	acceptedConns := make([]net.Conn, 3)
	wg := sync.WaitGroup{}
	errMu := sync.Mutex{}
	acceptErrs := []error{}

	var err error
	for i := range 3 {
		lns[i], err = net.Listen("tcp", "127.0.0.1:0") // nolint: noctx
		assert.NoError(t, err)

		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			conn, connErr := lns[j].Accept()
			if connErr != nil {
				errMu.Lock()
				acceptErrs = append(acceptErrs, connErr)
				errMu.Unlock()

				return
			}

			mu.Lock()
			acceptedConns[j] = conn
			mu.Unlock()
		}(i)
	}

	manager, err := newTestManager()
	assert.NoError(t, err)

	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	allocation, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)
	allocation.RelayAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rand.Intn(60999-32768+1) + 32768} //nolint:gosec

	for i := range 3 {
		addr, ok := lns[i].Addr().(*net.TCPAddr)
		assert.True(t, ok)
		peer := proto.PeerAddress{IP: addr.IP, Port: addr.Port}

		connectionID, err := manager.CreateTCPConnection(allocation, peer)
		assert.NoError(t, err)
		assert.NotZero(t, connectionID)

		conn := manager.GetTCPConnection("", connectionID)
		assert.NotNil(t, conn)

		laddr, ok := conn.LocalAddr().(*net.TCPAddr)
		assert.True(t, ok)
		relayAddr, ok := allocation.RelayAddr.(*net.TCPAddr)
		assert.True(t, ok)
		assert.Equal(t, laddr.IP.String(), relayAddr.IP.String())
		assert.Equal(t, laddr.IP.String(), relayAddr.IP.String())

		assert.NoError(t, conn.Close())
	}

	wg.Wait()
	errMu.Lock()
	for _, err := range acceptErrs {
		assert.NoError(t, err)
	}
	errMu.Unlock()

	assert.NoError(t, turnSocket.Close())

	for i := range 3 {
		mu.Lock()
		conn := acceptedConns[i]
		mu.Unlock()
		if assert.NotNil(t, conn) {
			assert.NoError(t, conn.Close())
		}
		assert.NoError(t, lns[i].Close())
	}
}

// RFC 6156:
// "After the request has been successfully authenticated, the TURN
// server allocates a transport address of the type indicated in the
// REQUESTED-ADDRESS-FAMILY attribute.".
func TestCreateTCPConnectionUsesAddressFamily(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()
	var networks []string

	manager, err := NewManager(ManagerConfig{
		LeveledLogger: loggerFactory.NewLogger("test"),
		AllocatePacketConn: func(conf AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			addr := "0.0.0.0:0"
			if conf.Network == "udp6" {
				addr = "[::]:0"
			}

			conn, listenErr := net.ListenPacket(conf.Network, addr) // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return conn, conn.LocalAddr(), nil
		},
		AllocateListener: func(AllocateListenerConfig) (net.Listener, net.Addr, error) {
			return nil, nil, nil
		},
		AllocateConn: func(conf AllocateConnConfig) (net.Conn, error) {
			networks = append(networks, conf.Network)

			return &mockConn{localAddr: conf.LocalAddr, remoteAddr: conf.RemoteAddr}, nil
		},
	})
	assert.NoError(t, err)

	turnSocket4, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket4.Close())
	}()

	turnSocket6, err := net.ListenPacket("udp6", "[::]:0") // nolint: noctx
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket6.Close())
	}()

	fiveTuple4 := &FiveTuple{
		SrcAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
		DstAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5001},
	}
	alloc4, err := manager.CreateAllocation(fiveTuple4, turnSocket4, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)
	alloc4.RelayAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5002}

	_, err = manager.CreateTCPConnection(alloc4, proto.PeerAddress{IP: net.ParseIP("127.0.0.1"), Port: 5003})
	assert.NoError(t, err)

	fiveTuple6 := &FiveTuple{
		SrcAddr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5004},
		DstAddr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5005},
	}
	alloc6, err := manager.CreateAllocation(fiveTuple6, turnSocket6, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv6)
	assert.NoError(t, err)
	alloc6.RelayAddr = &net.TCPAddr{IP: net.ParseIP("::1"), Port: 5006}

	_, err = manager.CreateTCPConnection(alloc6, proto.PeerAddress{IP: net.ParseIP("::1"), Port: 5007})
	assert.NoError(t, err)

	assert.Equal(t, []string{"tcp4", "tcp6"}, networks)
}

func TestCreateTCPConnectionDuplicateDoesNotBlockManager(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, ln.Close())
	}()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	addr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)

	peer := proto.PeerAddress{IP: addr.IP, Port: addr.Port}

	manager, err := newTestManager()
	require.NoError(t, err)

	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket.Close())
	}()

	fiveTuple := randomFiveTuple()
	allocation, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	require.NoError(t, err)

	allocation.RelayAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rand.Intn(60999-32768+1) + 32768} //nolint:gosec
	connectionID, err := manager.CreateTCPConnection(allocation, peer)
	require.NoError(t, err)
	require.NotZero(t, connectionID)

	var acceptedConn net.Conn
	select {
	case result := <-accepted:
		require.NoError(t, result.err)
		require.NotNil(t, result.conn)
		acceptedConn = result.conn
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for TCP connection")
	}
	defer func() {
		assert.NoError(t, acceptedConn.Close())
	}()

	_, err = manager.CreateTCPConnection(allocation, peer)
	require.ErrorIs(t, err, ErrDupeTCPConnection)

	allocationCount := make(chan int, 1)
	go func() {
		allocationCount <- manager.AllocationCount()
	}()

	select {
	case count := <-allocationCount:
		assert.Equal(t, 1, count)
	case <-time.After(time.Second):
		require.FailNow(t, "manager remained blocked after rejecting duplicate TCP connection")
	}

	tcpConn := manager.GetTCPConnection("", connectionID)
	require.NotNil(t, tcpConn)
	assert.NoError(t, tcpConn.Close())
	assert.NoError(t, manager.Close())
}

func TestCreateTCPConnectionInvalidPeerAddress(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	allocation, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)
	allocation.RelayAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rand.Intn(60999-32768+1) + 32768} //nolint:gosec

	_, err = manager.CreateTCPConnection(allocation, proto.PeerAddress{IP: nil, Port: 1234})
	assert.ErrorIs(t, err, errInvalidPeerAddress)

	_, err = manager.CreateTCPConnection(allocation, proto.PeerAddress{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	assert.ErrorIs(t, err, errInvalidPeerAddress)

	assert.NoError(t, turnSocket.Close())
}

func TestCreateTCPConnectionInvalid(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	manager, err := newTestManager()
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	allocation, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)
	allocation.RelayAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rand.Intn(60999-32768+1) + 32768} //nolint:gosec

	peerAddress := proto.PeerAddress{IP: net.ParseIP("127.0.0.1"), Port: 5000}

	connectionID, err := manager.CreateTCPConnection(allocation, peerAddress)
	assert.ErrorIs(t, err, ErrTCPConnectionTimeoutOrFailure)
	assert.Zero(t, connectionID)

	assert.NoError(t, turnSocket.Close())
}

func TestCreateTCPConnectionTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // nolint: noctx
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var acceptedConn net.Conn
	var acceptErr error
	go func() {
		acceptedConn, acceptErr = ln.Accept()
		cancel()
	}()

	addr, ok := ln.Addr().(*net.TCPAddr)
	assert.True(t, ok)

	peer := proto.PeerAddress{IP: addr.IP, Port: addr.Port}

	manager, err := newTestManager()
	assert.NoError(t, err)
	manager.tcpConnectionBindTimeout = time.Millisecond

	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	assert.NoError(t, err)

	fiveTuple := randomFiveTuple()
	allocation, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoTCP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)
	allocation.RelayAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rand.Intn(60999-32768+1) + 32768} //nolint:gosec

	connectionID, err := manager.CreateTCPConnection(allocation, peer)
	assert.NoError(t, err)
	assert.NotZero(t, connectionID)

	time.Sleep(time.Millisecond * 100)
	assert.Nil(t, manager.GetTCPConnection("", connectionID))

	<-ctx.Done()
	assert.NoError(t, acceptErr)
	assert.NoError(t, acceptedConn.Close())
	assert.NoError(t, ln.Close())
	assert.NoError(t, turnSocket.Close())
}

func TestCreateAllocationIPv6(t *testing.T) {
	manager, err := newTestManager()
	assert.NoError(t, err)

	// Create a UDP6 socket for TURN
	turnSocket, err := net.ListenPacket("udp6", "[::]:0") // nolint: noctx
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket.Close())
	}()

	fiveTuple := randomFiveTuple()
	// Change the source address to IPv6
	fiveTuple.SrcAddr = &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000}

	// Create an IPv6 allocation
	allocation, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "", "", proto.RequestedFamilyIPv6)
	assert.NoError(t, err)
	assert.NotNil(t, allocation)
	assert.Equal(t, proto.RequestedFamilyIPv6, allocation.AddressFamily())

	// Verify allocation is retrievable
	foundAllocation := manager.GetAllocation(fiveTuple)
	assert.NotNil(t, foundAllocation)
	assert.Equal(t, proto.RequestedFamilyIPv6, foundAllocation.AddressFamily())

	// Delete allocation
	manager.DeleteAllocation(fiveTuple)
	assert.Nil(t, manager.GetAllocation(fiveTuple))
}

// TestAdmissionConcurrentSameFiveTuple verifies that only one of many concurrent
// admissions for the same five-tuple can reserve a relay address, and that a
// failed attempt frees the five-tuple for a retry with a new generation.
func TestAdmissionConcurrentSameFiveTuple(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket.Close())
	}()

	var allocations atomic.Int32
	manager, err := NewManager(ManagerConfig{
		LeveledLogger: logging.NewDefaultLoggerFactory().NewLogger("test"),
		AllocatePacketConn: func(AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			allocations.Add(1)
			conn, listenErr := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return conn, conn.LocalAddr(), nil
		},
		AllocateListener: func(AllocateListenerConfig) (net.Listener, net.Addr, error) { return nil, nil, nil },
		AllocateConn:     func(AllocateConnConfig) (net.Conn, error) { return nil, nil }, //nolint:nilnil
	})
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, manager.Close())
	}()

	fiveTuple := randomFiveTuple()

	admission, err := manager.BeginAdmission(fiveTuple)
	require.NoError(t, err)
	require.NotNil(t, admission)
	require.True(t, manager.AdmissionInProgress(fiveTuple))
	require.Equal(t, 1, manager.AdmissionCount())

	// A concurrent request for the same five-tuple must not start a second
	// admission while the first is in flight.
	_, err = manager.BeginAdmission(fiveTuple)
	require.ErrorIs(t, err, ErrAdmissionInProgress)
	assert.Equal(t, 1, manager.AdmissionCount())

	// A failure releases the five-tuple and lets the retry use a new generation.
	admission.Abort()
	admission.Abort() // idempotent
	assert.False(t, manager.AdmissionInProgress(fiveTuple))
	assert.Equal(t, 0, manager.AdmissionCount())

	retry, err := manager.BeginAdmission(fiveTuple)
	require.NoError(t, err)
	assert.Greater(t, retry.Generation(), admission.Generation())

	alloc, err := manager.CreateAllocationWithAdmission(
		retry, turnSocket, proto.ProtoUDP, 0, proto.DefaultLifetime, "user", "realm", proto.RequestedFamilyIPv4,
	)
	require.NoError(t, err)
	require.NotNil(t, alloc)
	assert.Equal(t, retry.Generation(), alloc.Generation())
	assert.Equal(t, int32(1), allocations.Load(), "only one relay address may be reserved")
	assert.Equal(t, 1, manager.AllocationCount())
	assert.False(t, manager.AdmissionInProgress(fiveTuple))

	// The committed admission no longer holds the five-tuple but the allocation
	// does, so another admission is rejected as a duplicate.
	_, err = manager.BeginAdmission(fiveTuple)
	require.ErrorIs(t, err, ErrAllocationExists)
}

// TestAdmissionGeneratorFailureReleasesFiveTuple verifies that a relay generator
// failure leaves no socket, allocation or admission behind.
func TestAdmissionGeneratorFailureReleasesFiveTuple(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket.Close())
	}()

	generatorErr := errTestGeneratorUnavailable
	var fail atomic.Bool
	fail.Store(true)
	manager, err := NewManager(ManagerConfig{
		LeveledLogger: logging.NewDefaultLoggerFactory().NewLogger("test"),
		AllocatePacketConn: func(AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			if fail.Load() {
				return nil, nil, generatorErr
			}
			conn, listenErr := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return conn, conn.LocalAddr(), nil
		},
		AllocateListener: func(AllocateListenerConfig) (net.Listener, net.Addr, error) { return nil, nil, nil },
		AllocateConn:     func(AllocateConnConfig) (net.Conn, error) { return nil, nil }, //nolint:nilnil
	})
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, manager.Close())
	}()

	fiveTuple := randomFiveTuple()

	_, err = manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "user", "realm", proto.RequestedFamilyIPv4)
	require.ErrorIs(t, err, generatorErr)
	assert.Equal(t, 0, manager.AllocationCount())
	assert.False(t, manager.AdmissionInProgress(fiveTuple))

	// The retry proceeds with a new generation.
	fail.Store(false)
	alloc, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "user", "realm", proto.RequestedFamilyIPv4)
	require.NoError(t, err)
	require.NotNil(t, alloc)
	assert.Equal(t, uint64(2), alloc.Generation())
	assert.Equal(t, 1, manager.AllocationCount())
}

// TestAdmissionLifetimeZeroReleasesFiveTuple verifies that a request rejected
// for LIFETIME 0 does not hold the five-tuple.
func TestAdmissionLifetimeZeroReleasesFiveTuple(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket.Close())
	}()

	manager, err := newTestManager()
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, manager.Close())
	}()

	fiveTuple := randomFiveTuple()
	_, err = manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, 0, "user", "realm", proto.RequestedFamilyIPv4)
	require.ErrorIs(t, err, errLifetimeZero)
	assert.False(t, manager.AdmissionInProgress(fiveTuple))
	assert.Equal(t, 0, manager.AllocationCount())

	_, err = manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "user", "realm", proto.RequestedFamilyIPv4)
	require.NoError(t, err)
}

// TestDeleteAllocationIfIgnoresStaleGeneration verifies that a stale lifetime
// timer or relay loop cannot remove the allocation that replaced it.
func TestDeleteAllocationIfIgnoresStaleGeneration(t *testing.T) {
	turnSocket, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, turnSocket.Close())
	}()

	manager, err := newTestManager()
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, manager.Close())
	}()

	fiveTuple := randomFiveTuple()
	stale, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "user", "realm", proto.RequestedFamilyIPv4)
	require.NoError(t, err)

	manager.DeleteAllocationIf(stale)
	require.Nil(t, manager.GetAllocation(fiveTuple))

	current, err := manager.CreateAllocation(fiveTuple, turnSocket, proto.ProtoUDP,
		0, proto.DefaultLifetime, "user", "realm", proto.RequestedFamilyIPv4)
	require.NoError(t, err)
	require.NotNil(t, current)

	// A late teardown for the previous allocation must be a no-op.
	manager.DeleteAllocationIf(stale)
	require.Same(t, current, manager.GetAllocation(fiveTuple))
	require.False(t, current.IsClosed())
}

// TestAllocationCloseIdempotent verifies that teardown is idempotent and that a
// closed allocation cannot be revived by late data or refresh.
func TestAllocationCloseIdempotent(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0") // nolint: noctx
	require.NoError(t, err)

	fiveTuple := randomFiveTuple()
	alloc := NewAllocation(nil, fiveTuple, EventHandler{}, logging.NewDefaultLoggerFactory().NewLogger("test"))
	alloc.relayPacketConn = conn
	alloc.lifetimeTimer = time.NewTimer(time.Hour)

	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478}
	alloc.AddPermission(NewPermission(peer, alloc.log, time.Hour))
	permTimer := alloc.GetPermission(peer).lifetimeTimer

	require.NoError(t, alloc.Close())
	require.NoError(t, alloc.Close())
	require.True(t, alloc.IsClosed())
	require.False(t, alloc.Refresh(time.Hour), "refresh must not revive a closed allocation")
	alloc.AddPermission(NewPermission(peer, alloc.log, time.Hour))
	require.Nil(t, alloc.GetPermission(peer), "permission must not be revived after close")
	require.ErrorIs(t, alloc.AddChannelBind(NewChannelBind(proto.MinChannelNumber, peer, alloc.log),
		proto.DefaultLifetime, time.Hour), errAllocationClosed)
	require.Nil(t, alloc.GetChannelByNumber(proto.MinChannelNumber))
	_, err = alloc.WriteTo([]byte("late"), peer)
	require.ErrorIs(t, err, errAllocationClosed)
	require.False(t, permTimer.Stop(), "permission timer must already be stopped")
}

// TestPermissionRemovalReportsOnce verifies that a permission timer firing while
// the allocation is torn down reports the deletion only once.
func TestPermissionRemovalReportsOnce(t *testing.T) {
	var deletions atomic.Int32
	alloc := NewAllocation(nil, &FiveTuple{}, EventHandler{
		OnPermissionDeleted: func(_, _ net.Addr, _, _, _ string, _ net.Addr, _ net.IP) {
			deletions.Add(1)
		},
	}, logging.NewDefaultLoggerFactory().NewLogger("test"))

	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478}
	alloc.AddPermission(NewPermission(peer, alloc.log, time.Hour))

	require.NoError(t, alloc.Close())
	alloc.RemovePermission(peer)

	require.Equal(t, int32(1), deletions.Load())
}

// TestReservationLifecycle verifies that a reservation can only be taken once and
// that a failed attempt can put it back for a retry.
func TestReservationLifecycle(t *testing.T) {
	manager, err := newTestManager()
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, manager.Close())
	}()

	manager.CreateReservation("token", 5000)

	port, ok := manager.GetReservation("token")
	require.True(t, ok)
	require.Equal(t, 5000, port)

	port, ok = manager.TakeReservation("token")
	require.True(t, ok)
	require.Equal(t, 5000, port)

	// A consumed token must not be handed out a second time.
	_, ok = manager.TakeReservation("token")
	require.False(t, ok)
	_, ok = manager.GetReservation("token")
	require.False(t, ok)

	// A failed request can restore the token for a retry.
	manager.RestoreReservation("token", port)
	port, ok = manager.GetReservation("token")
	require.True(t, ok)
	require.Equal(t, 5000, port)

	manager.RemoveReservation("token")
	_, ok = manager.GetReservation("token")
	require.False(t, ok)
}
