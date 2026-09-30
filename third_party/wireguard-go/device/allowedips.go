/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"unsafe"
)

type parentIndirection struct {
	parentBit     **trieEntry
	parentBitType uint8
}

type trieEntry struct {
	peer        *Peer
	child       [2]*trieEntry
	parent      parentIndirection
	cidr        uint8
	bitAtByte   uint8
	bitAtShift  uint8
	bits        []byte
	perPeerElem *list.Element
}

func commonBits(ip1, ip2 []byte) uint8 {
	size := len(ip1)
	if size == net.IPv4len {
		a := binary.BigEndian.Uint32(ip1)
		b := binary.BigEndian.Uint32(ip2)
		x := a ^ b
		return uint8(bits.LeadingZeros32(x))
	} else if size == net.IPv6len {
		a := binary.BigEndian.Uint64(ip1)
		b := binary.BigEndian.Uint64(ip2)
		x := a ^ b
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		a = binary.BigEndian.Uint64(ip1[8:])
		b = binary.BigEndian.Uint64(ip2[8:])
		x = a ^ b
		return 64 + uint8(bits.LeadingZeros64(x))
	} else {
		panic("Wrong size bit string")
	}
}

func commonBits4(ip1 []byte, ip2 [4]byte) uint8 {
	a := binary.BigEndian.Uint32(ip1)
	b := binary.BigEndian.Uint32(ip2[:])
	return uint8(bits.LeadingZeros32(a ^ b))
}

func commonBits6(ip1 []byte, ip2 [16]byte) uint8 {
	a := binary.BigEndian.Uint64(ip1)
	b := binary.BigEndian.Uint64(ip2[:])
	x := a ^ b
	if x != 0 {
		return uint8(bits.LeadingZeros64(x))
	}
	a = binary.BigEndian.Uint64(ip1[8:])
	b = binary.BigEndian.Uint64(ip2[8:])
	x = a ^ b
	return 64 + uint8(bits.LeadingZeros64(x))
}

func (node *trieEntry) addToPeerEntries() {
	node.perPeerElem = node.peer.trieEntries.PushBack(node)
}

func (node *trieEntry) removeFromPeerEntries() {
	if node.perPeerElem != nil {
		node.peer.trieEntries.Remove(node.perPeerElem)
		node.perPeerElem = nil
	}
}

func (node *trieEntry) choose(ip []byte) byte {
	return (ip[node.bitAtByte] >> node.bitAtShift) & 1
}

func (node *trieEntry) maskSelf() {
	mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
	for i := 0; i < len(mask); i++ {
		node.bits[i] &= mask[i]
	}
}

func (node *trieEntry) zeroizePointers() {
	// Make the garbage collector's life slightly easier
	node.peer = nil
	node.child[0] = nil
	node.child[1] = nil
	node.parent.parentBit = nil
}

func (node *trieEntry) nodePlacement(ip []byte, cidr uint8) (parent *trieEntry, exact bool) {
	for node != nil && node.cidr <= cidr && commonBits(node.bits, ip) >= node.cidr {
		parent = node
		if parent.cidr == cidr {
			exact = true
			return
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return
}

func (trie parentIndirection) insert(ip []byte, cidr uint8, peer *Peer) {
	if *trie.parentBit == nil {
		node := &trieEntry{
			peer:       peer,
			parent:     trie,
			bits:       ip,
			cidr:       cidr,
			bitAtByte:  cidr / 8,
			bitAtShift: 7 - (cidr % 8),
		}
		node.maskSelf()
		node.addToPeerEntries()
		*trie.parentBit = node
		return
	}
	node, exact := (*trie.parentBit).nodePlacement(ip, cidr)
	if exact {
		node.removeFromPeerEntries()
		node.peer = peer
		node.addToPeerEntries()
		return
	}

	newNode := &trieEntry{
		peer:       peer,
		bits:       ip,
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	newNode.maskSelf()
	newNode.addToPeerEntries()

	var down *trieEntry
	if node == nil {
		down = *trie.parentBit
	} else {
		bit := node.choose(ip)
		down = node.child[bit]
		if down == nil {
			newNode.parent = parentIndirection{&node.child[bit], bit}
			node.child[bit] = newNode
			return
		}
	}
	common := commonBits(down.bits, ip)
	if common < cidr {
		cidr = common
	}
	parent := node

	if newNode.cidr == cidr {
		bit := newNode.choose(down.bits)
		down.parent = parentIndirection{&newNode.child[bit], bit}
		newNode.child[bit] = down
		if parent == nil {
			newNode.parent = trie
			*trie.parentBit = newNode
		} else {
			bit := parent.choose(newNode.bits)
			newNode.parent = parentIndirection{&parent.child[bit], bit}
			parent.child[bit] = newNode
		}
		return
	}

	node = &trieEntry{
		bits:       append([]byte{}, newNode.bits...),
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	node.maskSelf()

	bit := node.choose(down.bits)
	down.parent = parentIndirection{&node.child[bit], bit}
	node.child[bit] = down
	bit = node.choose(newNode.bits)
	newNode.parent = parentIndirection{&node.child[bit], bit}
	node.child[bit] = newNode
	if parent == nil {
		node.parent = trie
		*trie.parentBit = node
	} else {
		bit := parent.choose(node.bits)
		node.parent = parentIndirection{&parent.child[bit], bit}
		parent.child[bit] = node
	}
}

func (node *trieEntry) lookup4(ip [4]byte) *Peer {
	var found *Peer
	for node != nil && commonBits4(node.bits, ip) >= node.cidr {
		if node.peer != nil {
			found = node.peer
		}
		if node.bitAtByte == 4 {
			break
		}
		bit := (ip[node.bitAtByte] >> node.bitAtShift) & 1
		node = node.child[bit]
	}
	return found
}

func (node *trieEntry) lookup6(ip [16]byte) *Peer {
	var found *Peer
	for node != nil && commonBits6(node.bits, ip) >= node.cidr {
		if node.peer != nil {
			found = node.peer
		}
		if node.bitAtByte == 16 {
			break
		}
		bit := (ip[node.bitAtByte] >> node.bitAtShift) & 1
		node = node.child[bit]
	}
	return found
}

func (node *trieEntry) lookup(ip net.IP) *Peer {
	var found *Peer
	size := uint8(len(ip))
	for node != nil && commonBits(node.bits, ip) >= node.cidr {
		if node.peer != nil {
			found = node.peer
		}
		if node.bitAtByte == size {
			break
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return found
}

type AllowedIPs struct {
	mu   sync.RWMutex
	ipv4 *trieEntry
	ipv6 *trieEntry

	peerByIPPacketFunc PeerByIPPacketFunc // if non-nil, called to look up peers by IP
	device             *Device            // back-reference to parent device; non-nil only if peerByIPPacketFunc is set
}

func (table *AllowedIPs) EntriesForPeer(peer *Peer, cb func(prefix netip.Prefix) bool) {
	table.mu.RLock()
	defer table.mu.RUnlock()

	for elem := peer.trieEntries.Front(); elem != nil; elem = elem.Next() {
		node := elem.Value.(*trieEntry)
		a, _ := netip.AddrFromSlice(node.bits)
		if !cb(netip.PrefixFrom(a, int(node.cidr))) {
			return
		}
	}
}

func (node *trieEntry) remove() {
	node.removeFromPeerEntries()
	node.peer = nil
	if node.child[0] != nil && node.child[1] != nil {
		return
	}
	bit := 0
	if node.child[0] == nil {
		bit = 1
	}
	child := node.child[bit]
	if child != nil {
		child.parent = node.parent
	}
	*node.parent.parentBit = child
	if node.child[0] != nil || node.child[1] != nil || node.parent.parentBitType > 1 {
		node.zeroizePointers()
		return
	}
	parent := (*trieEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(node.parent.parentBit)) - unsafe.Offsetof(node.child) - unsafe.Sizeof(node.child[0])*uintptr(node.parent.parentBitType)))
	if parent.peer != nil {
		node.zeroizePointers()
		return
	}
	child = parent.child[node.parent.parentBitType^1]
	if child != nil {
		child.parent = parent.parent
	}
	*parent.parent.parentBit = child
	node.zeroizePointers()
	parent.zeroizePointers()
}

func (table *AllowedIPs) Remove(prefix netip.Prefix, peer *Peer) {
	table.mu.Lock()
	defer table.mu.Unlock()
	var node *trieEntry
	var exact bool

	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		node, exact = table.ipv6.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		node, exact = table.ipv4.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else {
		panic(errors.New("removing unknown address type"))
	}
	if !exact || node == nil || peer != node.peer {
		return
	}
	node.remove()
}

// setPeerPrefixes atomically removes all of peer's existing prefixes and adds
// the provided ones.
func (table *AllowedIPs) setPeerPrefixes(peer *Peer, prefixes []netip.Prefix) {
	table.mu.Lock()
	defer table.mu.Unlock()

	table.removeByPeerLocked(peer)
	for _, prefix := range prefixes {
		table.insertLocked(prefix, peer)
	}
}

func (table *AllowedIPs) RemoveByPeer(peer *Peer) {
	table.mu.Lock()
	defer table.mu.Unlock()
	table.removeByPeerLocked(peer)
}

func (table *AllowedIPs) removeByPeerLocked(peer *Peer) {
	var next *list.Element
	for elem := peer.trieEntries.Front(); elem != nil; elem = next {
		next = elem.Next()
		elem.Value.(*trieEntry).remove()
	}
}

func (table *AllowedIPs) Insert(prefix netip.Prefix, peer *Peer) {
	table.mu.Lock()
	defer table.mu.Unlock()
	table.insertLocked(prefix, peer)
}

func (table *AllowedIPs) insertLocked(prefix netip.Prefix, peer *Peer) {
	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parentIndirection{&table.ipv6, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parentIndirection{&table.ipv4, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}

// LookupFromPacket looks up the peer to which an outbound IP packet should be
// sent. It lives on [AllowedIPs] for legacy/structural reasons: historically
// WireGuard's only peer-selection mechanism was the AllowedIPs trie, and the
// send path already had a reference to the table. When a [PeerByIPPacketFunc]
// has been registered via [Device.SetPeerByIPPacketFunc], that callback is used
// instead of the trie and the AllowedIPs table is not consulted at all.
//
// When no callback is registered, only dst is used (standard WireGuard
// AllowedIPs trie lookup). When a callback is registered, all three
// parameters are forwarded to it; see [PeerByIPPacketFunc] for details.
func (table *AllowedIPs) LookupFromPacket(src, dst netip.Addr, ipPkt []byte) *Peer {
	table.mu.RLock()
	if f := table.peerByIPPacketFunc; f != nil {
		device := table.device
		table.mu.RUnlock()

		if pubk, ok := f(src, dst, ipPkt); ok {
			return device.LookupPeer(pubk)
		}
		return nil
	}
	defer table.mu.RUnlock()

	switch {
	case dst.Is6():
		return table.ipv6.lookup6(dst.As16())
	case dst.Is4():
		return table.ipv4.lookup4(dst.As4())
	default:
		panic(errors.New("looking up unknown address type"))
	}
}

// Deprecated: Lookup is only used by legacy tests. It does not call
// [PeerByIPPacketFunc]; use [AllowedIPs.LookupFromPacket] for production lookups.
func (table *AllowedIPs) Lookup(ip []byte) *Peer {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return table.lookupLocked(ip)
}

// lookupLocked looks up the peer associated with the given IP address.
// It assumes the caller holds the read lock (or doesn't hold it, but also
// doesn't concurrently mutate AllowedIP).
//
// It returns nil if no peer is associated with the given IP address.
func (table *AllowedIPs) lookupLocked(ip []byte) *Peer {
	switch len(ip) {
	case net.IPv6len:
		return table.ipv6.lookup(ip)
	case net.IPv4len:
		return table.ipv4.lookup(ip)
	default:
		panic(errors.New("looking up unknown address type"))
	}
}

// AllowedPeerSourceIP reports whether the given source IP address is allowed
// for the given peer.
func (peer *Peer) AllowedPeerSourceIP(src netip.Addr) bool {
	if f := peer.state.testAllowedIP.Load(); f != nil {
		return (*f)(src)
	}

	table := &peer.device.allowedips
	table.mu.RLock()
	defer table.mu.RUnlock()
	switch {
	case src.Is6():
		return table.ipv6.lookup6(src.As16()) == peer
	case src.Is4():
		return table.ipv4.lookup4(src.As4()) == peer
	}
	return false
}

// fakePeer is a zero Peer used only as a placeholder in tries used by mkIPInCIDRsTestFunc.
var fakePeer Peer

// mkIPInCIDRsTestFunc returns a function that tests whether an IP address is
// contained in any of the given CIDRs.
func mkIPInCIDRsTestFunc(cidrs []netip.Prefix) func(netip.Addr) bool {
	if len(cidrs) == 0 {
		return func(netip.Addr) bool { return false }
	}
	if len(cidrs) == 1 {
		return func(addr netip.Addr) bool { return cidrs[0].Contains(addr) }
	}
	if len(cidrs) <= 4 {
		// For small numbers of CIDRs, just do a linear search. The trie construction
		// is more expensive than the linear search, and the test function is faster
		// than the trie lookup, so this is a net win.
		return func(addr netip.Addr) bool {
			for _, c := range cidrs {
				if c.Contains(addr) {
					return true
				}
			}
			return false
		}
	}
	// Make a trie for faster lookups. We use a dummy Peer.
	var a AllowedIPs
	for _, c := range cidrs {
		a.Insert(c, &fakePeer)
	}
	return func(addr netip.Addr) bool {
		switch {
		case addr.Is4():
			return a.ipv4.lookup4(addr.As4()) == &fakePeer
		default:
			return a.ipv6.lookup6(addr.As16()) == &fakePeer
		}
	}
}
