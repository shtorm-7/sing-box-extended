package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	returnDevice   *returnDeviceWrapper
	device         *device.Device
	allowedIPs     *device.AllowedIPs
	egressPool     *tun.UDPEgressPool
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsDomain() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		peer.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	deviceOptions := DeviceOptions{
		Context:         options.Context,
		Logger:          options.Logger,
		System:          options.System,
		Handler:         options.Handler,
		UDPTimeout:      options.UDPTimeout,
		ICMPTimeout:     options.ICMPTimeout,
		UDPMapping:      options.UDPMapping,
		UDPFiltering:    options.UDPFiltering,
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: options.InterfaceFinder,
		CreateDialer:    options.CreateDialer,
		Name:            options.Name,
		MTU:             options.MTU,
		Address:         options.Address,
		AllowedAddress:  allowedAddresses,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		tunDevice:      tunDevice,
		returnDevice:   &returnDeviceWrapper{Device: tunDevice},
	}, nil
}

func (e *Endpoint) Start(postStart bool) error {
	hasDomainPeer := common.Any(e.peers, func(peer peerConfig) bool {
		return peer.destination.IsDomain()
	})
	if postStart != hasDomainPeer {
		return nil
	}
	var bind conn.Bind
	udpListener, isUDPListener := common.Cast[dialer.UDPListener](e.options.Dialer)
	if isUDPListener {
		listenerControl, _ := udpListener.UDPListenerControl()
		bind = conn.NewDefaultBind(listenerControl)
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
		)
		if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			isConnect = true
			connectAddr = e.peers[0].endpoint
		}
		bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr)
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.options.Context, e.returnDevice, bind, logger, e.options.Workers, e.options.PreallocatedBuffersPerPool, e.options.DisablePauses)
	e.tunDevice.SetDevice(wgDevice)
	var ipcConf strings.Builder
	ipcConf.WriteString(e.ipcConf)
	if e.options.Amnezia != nil {
		if e.options.Amnezia.JC > 0 {
			ipcConf.WriteString("\njc=" + strconv.Itoa(e.options.Amnezia.JC))
		}
		if e.options.Amnezia.JMin > 0 {
			ipcConf.WriteString("\njmin=" + strconv.Itoa(e.options.Amnezia.JMin))
		}
		if e.options.Amnezia.JMax > 0 {
			ipcConf.WriteString("\njmax=" + strconv.Itoa(e.options.Amnezia.JMax))
		}
		if e.options.Amnezia.S1 > 0 {
			ipcConf.WriteString("\ns1=" + strconv.Itoa(e.options.Amnezia.S1))
		}
		if e.options.Amnezia.S2 > 0 {
			ipcConf.WriteString("\ns2=" + strconv.Itoa(e.options.Amnezia.S2))
		}
		if e.options.Amnezia.S3 > 0 {
			ipcConf.WriteString("\ns3=" + strconv.Itoa(e.options.Amnezia.S3))
		}
		if e.options.Amnezia.S4 > 0 {
			ipcConf.WriteString("\ns4=" + strconv.Itoa(e.options.Amnezia.S4))
		}
		if e.options.Amnezia.H1 != nil {
			ipcConf.WriteString("\nh1=" + e.options.Amnezia.H1.String())
		}
		if e.options.Amnezia.H2 != nil {
			ipcConf.WriteString("\nh2=" + e.options.Amnezia.H2.String())
		}
		if e.options.Amnezia.H3 != nil {
			ipcConf.WriteString("\nh3=" + e.options.Amnezia.H3.String())
		}
		if e.options.Amnezia.H4 != nil {
			ipcConf.WriteString("\nh4=" + e.options.Amnezia.H4.String())
		}
		if e.options.Amnezia.I1 != "" {
			ipcConf.WriteString("\ni1=" + e.options.Amnezia.I1)
		}
		if e.options.Amnezia.I2 != "" {
			ipcConf.WriteString("\ni2=" + e.options.Amnezia.I2)
		}
		if e.options.Amnezia.I3 != "" {
			ipcConf.WriteString("\ni3=" + e.options.Amnezia.I3)
		}
		if e.options.Amnezia.I4 != "" {
			ipcConf.WriteString("\ni4=" + e.options.Amnezia.I4)
		}
		if e.options.Amnezia.I5 != "" {
			ipcConf.WriteString("\ni5=" + e.options.Amnezia.I5)
		}
		if e.options.Amnezia.HeaderProtectionKey != "" {
			headerProtectionKeyBytes, err := base64.StdEncoding.DecodeString(e.options.Amnezia.HeaderProtectionKey)
			if err != nil {
				return E.Cause(err, "decode header protection key")
			}
			ipcConf.WriteString("\nheader_protection_key=" + hex.EncodeToString(headerProtectionKeyBytes))
		}
		if e.options.Amnezia.ContentPaddingAddition != nil {
			ipcConf.WriteString("\ncontent_padding_addition=" + e.options.Amnezia.ContentPaddingAddition.String())
		}
		if e.options.Amnezia.RekeyAfterTime != nil {
			ipcConf.WriteString("\nrekey_after_time=" + e.options.Amnezia.RekeyAfterTime.String())
		}
		if e.options.Amnezia.RekeyTimeout != nil {
			ipcConf.WriteString("\nrekey_timeout=" + e.options.Amnezia.RekeyTimeout.String())
		}
		if e.options.Amnezia.RejectAfterTime != nil {
			ipcConf.WriteString("\nreject_after_time=" + e.options.Amnezia.RejectAfterTime.String())
		}
		if e.options.Amnezia.KeepaliveTimeout != nil {
			ipcConf.WriteString("\nkeepalive_timeout=" + e.options.Amnezia.KeepaliveTimeout.String())
		}
		if e.options.Amnezia.MaxHandshakeAttempts != nil {
			ipcConf.WriteString("\nmax_handshake_attempts=" + e.options.Amnezia.MaxHandshakeAttempts.String())
		}
		if e.options.Amnezia.RandomTrailers {
			ipcConf.WriteString("\nrandom_trailers=1")
		}
		if e.options.Amnezia.DisableCookies {
			ipcConf.WriteString("\ndisable_cookies=1")
		}
	}
	for _, peer := range e.peers {
		ipcConf.WriteString(peer.GenerateIpcLines())
	}
	err = wgDevice.IpcSet(ipcConf.String())
	if err != nil {
		wgDevice.Close()
		return E.Cause(err, "setup wireguard: \n", ipcConf.String())
	}
	for _, peer := range e.peers {
		if !peer.destination.IsDomain() {
			continue
		}
		var publicKey device.NoisePublicKey
		common.Must(publicKey.FromHex(peer.publicKeyHex))
		wgPeer, found := wgDevice.LookupActivePeer(publicKey)
		if !found {
			wgDevice.Close()
			return E.New("missing configured peer: ", peer.destination)
		}
		wgPeer.SetEndpointResolver(func() ([]conn.Endpoint, error) {
			addresses, lookupErr := e.options.ResolvePeer(peer.destination.Fqdn)
			if lookupErr != nil {
				return nil, lookupErr
			}
			endpoints := make([]conn.Endpoint, 0, len(addresses))
			for _, address := range addresses {
				destination := netip.AddrPortFrom(address, peer.destination.Port)
				endpoint, parseErr := bind.ParseEndpoint(destination.String())
				if parseErr != nil {
					return nil, parseErr
				}
				endpoints = append(endpoints, endpoint)
			}
			return endpoints, nil
		})
	}
	e.device = wgDevice
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	e.allowedIPs = wgDevice.AllowedIPs()
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) Close() error {
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
		e.pauseCallback = nil
	}
	if e.egressPool != nil {
		e.egressPool.Close()
		e.egressPool = nil
	}
	if e.device != nil {
		e.device.Down()
		e.device.Close()
		e.device = nil
		return nil
	}
	return e.tunDevice.Close()
}

func (e *Endpoint) Lookup(address netip.Addr) *device.Peer {
	if e.allowedIPs == nil {
		return nil
	}
	return e.allowedIPs.LookupFromPacket(netip.Addr{}, address, nil)
}

func (e *Endpoint) BindUpdate() error {
	if e.device == nil {
		return nil
	}
	return e.device.BindUpdate()
}

func (e *Endpoint) onPauseUpdated(event int) {
	switch event {
	case pause.EventNetworkPause:
		e.device.Down()
	case pause.EventNetworkWake:
		e.device.Up()
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
}

func (c peerConfig) GenerateIpcLines() string {
	var ipcLines strings.Builder
	ipcLines.WriteString("\npublic_key=" + c.publicKeyHex)
	if c.endpoint.IsValid() {
		ipcLines.WriteString("\nendpoint=" + c.endpoint.String())
	}
	if c.preSharedKeyHex != "" {
		ipcLines.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if c.keepalive > 0 {
		ipcLines.WriteString("\npersistent_keepalive_interval=" + F.ToString(c.keepalive))
	}
	return ipcLines.String()
}
