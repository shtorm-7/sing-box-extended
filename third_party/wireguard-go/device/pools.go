/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"

	"github.com/sagernet/sing/common/buf"
)

type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count uint32 // Get calls not yet Put back
	max   uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) hasAccounting() bool {
	return p != nil && p.max != 0
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}

func (device *Device) PopulatePools() {
	device.pool.inboundElementsContainer = &sync.Pool{New: func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	}}
	device.pool.outboundElementsContainer = &sync.Pool{New: func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	}}
	device.pool.messageBuffers = NewWaitPool(device.preallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	device.pool.inboundElements = &sync.Pool{New: func() any {
		return new(QueueInboundElement)
	}}
	device.pool.outboundElements = &sync.Pool{New: func() any {
		return new(QueueOutboundElement)
	}}
}

func (device *Device) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := device.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	return c
}

func (device *Device) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.inboundElementsContainer.Put(c)
}

func (device *Device) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := device.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	return c
}

func (device *Device) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.outboundElementsContainer.Put(c)
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

// Outbound buffers come from the sing allocator instead of the bounded
// messageBuffers pool: the injection paths (InputPacket/InputPackets) run on
// the caller's shared read loop, which must never block on pool exhaustion,
// and their packets are far smaller than MaxMessageSize, so they are allocated
// by actual size. This also keeps the bounded pool exclusively for the receive
// path, so outbound backlog can no longer starve it.
func (device *Device) GetOutboundBuffer(size int) []byte {
	return buf.Get(size)
}

func (device *Device) PutOutboundBuffer(buffer []byte) {
	_ = buf.Put(buffer)
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
