/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"net/netip"
	"sync"
	"testing"

	"github.com/GFW-knocker/wireguard/conn"
	"github.com/GFW-knocker/wireguard/tun/tuntest"
)

// noiseBind captures what sendRandomPackets actually puts on the wire, and
// feeds it the Wnoise settings under test via Get_extra_data.
type noiseBind struct {
	conn.Bind

	wnoise  string
	wheader []byte

	mu   sync.Mutex
	sent [][]byte
}

func (b *noiseBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, port, nil
}
func (b *noiseBind) Close() error              { return nil }
func (b *noiseBind) SetMark(mark uint32) error { return nil }
func (b *noiseBind) BatchSize() int            { return 1 }

func (b *noiseBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

func (b *noiseBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	return b.Send_without_modify(bufs, ep)
}

func (b *noiseBind) Send_without_modify(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, buf := range bufs {
		b.sent = append(b.sent, append([]byte(nil), buf...))
	}
	return nil
}

// Wnoise, Wheader, countFrom, countTo, delayFrom, delayTo, payloadFrom, payloadTo
func (b *noiseBind) Get_extra_data() (string, []byte, int, int, int, int, int, int) {
	return b.wnoise, b.wheader, 1, 1, 0, 0, 5, 5
}

func (b *noiseBind) packets() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}

// noisePeer wires a real Device and Peer to the capture bind, so the packets
// come out of the production sendRandomPackets path.
func noisePeer(t *testing.T, wnoise string, wheader []byte) (*Peer, *noiseBind) {
	t.Helper()
	bind := &noiseBind{wnoise: wnoise, wheader: wheader}
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bind, NewLogger(LogLevelSilent, "noise: "))
	t.Cleanup(dev.Close)

	if err := dev.IpcSet(`private_key=0000000000000000000000000000000000000000000000000000000000000001
public_key=0000000000000000000000000000000000000000000000000000000000000002
endpoint=127.0.0.1:12345
`); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	var peer *Peer
	dev.peers.RLock()
	for _, p := range dev.peers.keyMap {
		peer = p
		break
	}
	dev.peers.RUnlock()
	if peer == nil {
		t.Fatal("no peer configured")
	}
	return peer, bind
}

func TestQuicNoiseVersion(t *testing.T) {
	// "quic" must emit QUIC v2 (RFC 9369) and "quicv1" the old v1 (RFC 9000).
	// Everything else about the 18-byte header is unchanged.
	for _, tc := range []struct {
		wnoise  string
		version string
	}{
		{"quic", "6b3343cf"},
		{"quicv1", "00000001"},
	} {
		t.Run(tc.wnoise, func(t *testing.T) {
			peer, bind := noisePeer(t, tc.wnoise, nil)
			peer.sendRandomPackets()

			pkts := bind.packets()
			if len(pkts) == 0 {
				t.Fatal("no noise packet sent")
			}
			p := pkts[0]
			if len(p) != 18+5 {
				t.Fatalf("length = %d, want 23 (18 header + 5 payload)", len(p))
			}
			if got := hex.EncodeToString(p[1:5]); got != tc.version {
				t.Errorf("version = %s, want %s", got, tc.version)
			}
			// the rest of the header layout must be untouched
			if p[0]>>4 != 0xD && p[0]>>4 != 0xE {
				t.Errorf("first byte = %#x, want high nibble 0xD or 0xE", p[0])
			}
			if p[5] != 0x08 {
				t.Errorf("DCID length = %#x, want 0x08", p[5])
			}
			if got := hex.EncodeToString(p[14:18]); got != "000044d0" {
				t.Errorf("trailer = %s, want 000044d0", got)
			}
		})
	}
}

func TestQuicInitNoise(t *testing.T) {
	// "quicinit" must emit a complete, structurally valid 1200-byte QUIC v2
	// client Initial. All three of size, first byte and version are what make
	// the prime work, so all three are asserted.
	peer, bind := noisePeer(t, "quicinit", nil)
	peer.sendRandomPackets()

	pkts := bind.packets()
	if len(pkts) == 0 {
		t.Fatal("no noise packet sent")
	}
	p := pkts[0]
	// Wpayloadsize (5 in the test bind) must not be appended to it.
	if len(p) != quicInitSize {
		t.Fatalf("length = %d, want %d", len(p), quicInitSize)
	}
	if p[0]&0xF0 != 0xC0 {
		t.Errorf("first byte = %#x, want 0xc0-0xcf (long header, Initial)", p[0])
	}
	if got := hex.EncodeToString(p[1:5]); got != "6b3343cf" {
		t.Errorf("version = %s, want 6b3343cf (QUIC v2)", got)
	}
	if p[5] != 8 {
		t.Errorf("DCID length = %#x, want 0x08", p[5])
	}
	if p[14] != 8 {
		t.Errorf("SCID length = %#x, want 0x08", p[14])
	}
	if p[23] != 0x00 {
		t.Errorf("token length = %#x, want 0x00", p[23])
	}
	if got := hex.EncodeToString(p[24:26]); got != "4400" {
		t.Errorf("length varint = %s, want 4400", got)
	}
}

func TestQuicInitNoiseVaries(t *testing.T) {
	// Every datagram is rebuilt, so two bursts must not be the same bytes: a
	// constant connection ID would itself be something to match on.
	peer, bind := noisePeer(t, "quicinit", nil)
	for i := 0; i < 8; i++ {
		peer.sendRandomPackets()
	}
	pkts := bind.packets()
	if len(pkts) < 2 {
		t.Fatalf("sent %d packets, want at least 2", len(pkts))
	}
	seen := map[string]bool{}
	for _, p := range pkts {
		// the DCID, which a real client re-rolls per connection
		seen[hex.EncodeToString(p[6:14])] = true
		if len(p) != quicInitSize {
			t.Fatalf("length = %d, want %d", len(p), quicInitSize)
		}
		if p[0]&0xF0 != 0xC0 {
			t.Fatalf("first byte = %#x, want 0xc0-0xcf", p[0])
		}
		if got := hex.EncodeToString(p[1:5]); got != "6b3343cf" {
			t.Fatalf("version drifted to %s", got)
		}
	}
	if len(seen) != len(pkts) {
		t.Errorf("%d distinct connection IDs over %d packets, want all distinct", len(seen), len(pkts))
	}
}

func TestQuicNoiseFirstByteSpread(t *testing.T) {
	// The first byte is a random pick from clist; make sure both families
	// still appear and the version stays fixed across picks.
	peer, bind := noisePeer(t, "quic", nil)
	for i := 0; i < 60; i++ {
		peer.sendRandomPackets()
	}
	seen := map[byte]bool{}
	for _, p := range bind.packets() {
		seen[p[0]] = true
		if got := hex.EncodeToString(p[1:5]); got != "6b3343cf" {
			t.Fatalf("version drifted to %s", got)
		}
	}
	if len(seen) < 4 {
		t.Errorf("only %d distinct first bytes over 60 packets, want >=4", len(seen))
	}
	for b := range seen {
		switch b {
		case 0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3:
		default:
			t.Errorf("first byte %#x is not in clist", b)
		}
	}
}

func TestOtherNoiseModesUnchanged(t *testing.T) {
	// random / hex / none / "" must behave exactly as before.
	t.Run("random", func(t *testing.T) {
		peer, bind := noisePeer(t, "random", nil)
		peer.sendRandomPackets()
		pkts := bind.packets()
		if len(pkts) == 0 {
			t.Fatal("no packet sent")
		}
		if len(pkts[0]) != 18+5 {
			t.Errorf("length = %d, want 23", len(pkts[0]))
		}
	})

	t.Run("hex", func(t *testing.T) {
		hdr, _ := hex.DecodeString("d06b3343cf")
		peer, bind := noisePeer(t, "d06b3343cf", hdr)
		peer.sendRandomPackets()
		pkts := bind.packets()
		if len(pkts) == 0 {
			t.Fatal("no packet sent")
		}
		if got := hex.EncodeToString(pkts[0][:5]); got != "d06b3343cf" {
			t.Errorf("header = %s, want the custom hex verbatim", got)
		}
		if len(pkts[0]) != 5+5 {
			t.Errorf("length = %d, want 10 (5 header + 5 payload)", len(pkts[0]))
		}
	})

	for _, off := range []string{"", "none"} {
		t.Run("off/"+off, func(t *testing.T) {
			peer, bind := noisePeer(t, off, nil)
			peer.sendRandomPackets()
			if n := len(bind.packets()); n != 0 {
				t.Errorf("sent %d packets, want 0", n)
			}
		})
	}
}
