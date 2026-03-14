package interrupt

import (
	"io"
	"net"
	"sync"

	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	access      sync.Mutex
	connections list.List[*groupConnItem]
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
	isProvider bool
}

func NewGroup() *Group {
	return &Group{}
}

func (g *Group) NewConn(conn net.Conn, isExternal, isProvider bool) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal, isProvider})
	return &Conn{Conn: conn, group: g, element: item}
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal, isProvider bool) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal, isProvider})
	return &PacketConn{PacketConn: conn, group: g, element: item}
}

func (g *Group) NewSingPacketConn(conn N.PacketConn, isExternal bool, isProvider bool) N.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal, isProvider})
	return &SingPacketConn{PacketConn: conn, group: g, element: item}
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	defer g.access.Unlock()
	var toDelete []*list.Element[*groupConnItem]
	for element := g.connections.Front(); element != nil; element = element.Next() {
		if !element.Value.isProvider && !element.Value.isExternal || interruptExternalConnections {
			element.Value.conn.Close()
			toDelete = append(toDelete, element)
		}
	}
	for _, element := range toDelete {
		g.connections.Remove(element)
	}
}
