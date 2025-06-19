package minecraft2

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	ErrVarintTooLong  = errors.New("varint is too long")
	ErrVarintTooShort = errors.New("varint is too short")
	STATE_STATUS      = 1
	STATE_LOGIN       = 2
	STATE_CONFIG      = 3
	STATE_PLAY        = 4
)

type ConnectionData struct {
	State int
}

type varintReadResult struct {
	value int
	bytes []byte
}

func packVarint(val int) []byte {
	var out []byte
	for {
		temp := byte(val & 0x7F)
		val >>= 7
		if val != 0 {
			out = append(out, temp|0x80)
		} else {
			out = append(out, temp)
			break
		}
	}
	return out
}

// packString encodes a UTF-8 string as VarInt length + bytes
func packString(s string) []byte {
	strBytes := []byte(s)
	var out []byte
	out = append(out, packVarint(len(strBytes))...)
	out = append(out, strBytes...)
	return out
}

// packByteArray => VarInt length + raw bytes
func packByteArray(b []byte) []byte {
	out := append(packVarint(len(b)), b...)
	return out
}

func sendHandshakeWithParams(conn net.Conn, c *ConnectionData, host string, port uint16, protocolVersion int) error {
	var buf bytes.Buffer
	buf.Write(packVarint(0x00))            // handshake packet ID
	buf.Write(packVarint(protocolVersion)) // protocol version
	buf.Write(packString(host))            // hostname
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf.Write(portBytes)     // port
	buf.Write(packVarint(2)) // next state = 2 (login)

	data := packVarint(buf.Len())
	data = append(data, buf.Bytes()...)

	_, err := conn.Write(data)
	return err
}

func readVarint(b []byte) (varintReadResult, error) {
	value := 0
	for i, byteValue := range b {
		value |= int(byteValue&0x7F) << (7 * i)
		if byteValue&0x80 == 0 {
			return varintReadResult{value: value, bytes: b[:i+1]}, nil
		}
		if i == 4 { // Varint is at most 5 bytes long
			return varintReadResult{}, ErrVarintTooLong
		}
	}
	return varintReadResult{}, ErrVarintTooShort
}

// parseUUID returns a big-endian 16-byte representation of the hex-dash string
func parseUUID(uuid string) ([]byte, error) {
	trim := strings.ReplaceAll(uuid, "-", "")
	if len(trim) != 32 {
		return nil, fmt.Errorf("invalid UUID format: %s", uuid)
	}
	raw, err := hex.DecodeString(trim)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func sendLoginStart(conn net.Conn, c *ConnectionData, botUsername string, botUUID string, activeProtocolVersion int) error {
	// 1.8 - 1.18.2: username only (47 - 758)
	// 1.19: username, Has Sig Data (759)
	// 1.19.2: username, Has Sig Data, has UUID, uuid (760)
	// 1.19.3 - 1.20.1: username, has UUID, uuid (761 - 763)
	// 1.20.2+: username, uuid (764+)

	// 0x00, name:String, uuid(16 bytes)
	var buf bytes.Buffer
	var err error
	buf.Write(packVarint(0x00))        // packet id
	buf.Write(packString(botUsername)) // username

	if activeProtocolVersion >= 47 && activeProtocolVersion <= 758 {
		// 1.8 - 1.18.2: username only
	} else if activeProtocolVersion == 759 {
		// 1.19: username, Has Sig Data only
		buf.WriteByte(0x00) // Has Sig Data field (false)
	} else if activeProtocolVersion == 760 {
		// 1.19.2: username, Has Sig Data, has UUID, uuid
		buf.WriteByte(0x00) // Has Sig Data field (false)
		buf.WriteByte(0x01) // has UUID field (true)
		uuidBytes, err := parseUUID(botUUID)
		if err != nil {
			return err
		}
		buf.Write(uuidBytes)
	} else if activeProtocolVersion >= 761 && activeProtocolVersion <= 763 {
		// 1.19.3 - 1.20.1: username, has uuid field, uuid (no Has Sig Data)
		buf.WriteByte(0x01) // has UUID field (true)
		uuidBytes, err := parseUUID(botUUID)
		if err != nil {
			return err
		}
		buf.Write(uuidBytes)
	} else if activeProtocolVersion >= 764 {
		// 1.20.2+: username, uuid (no Has Sig Data, no has uuid field)
		uuidBytes, err := parseUUID(botUUID)
		if err != nil {
			return err
		}
		buf.Write(uuidBytes)
	}

	packet := buf.Bytes()
	fullPacket := append(packVarint(len(packet)), packet...)
	_, err = conn.Write(fullPacket)
	return err
}

func readLoop(ctx context.Context, conn net.Conn, c *ConnectionData, disconnected chan struct{}, authMode chan int) {
	defer close(disconnected)
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 1)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read bytes one by one to parse VarInt packet length
		buf = buf[:0]
		for {
			_, err := conn.Read(tmp)
			if err != nil {
				if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				fmt.Println("Error reading packet length:", err)
				return
			}
			buf = append(buf, tmp[0])
			if tmp[0]&0x80 == 0 {
				break
			}
			if len(buf) > 5 {
				fmt.Println("VarInt too long (packet length)")
				return
			}
		}

		// Read full packet data based on packet length
		lengthVarint, err := readVarint(buf)
		if err != nil {
			fmt.Println("Error decoding packet length:", err)
			return
		}
		packetLen := lengthVarint.value
		packetData := make([]byte, packetLen)
		_, err = io.ReadFull(conn, packetData)
		if err != nil {
			fmt.Println("Error reading packet body:", err)
			return
		}

		// Extract packet ID
		packetIDResult, err := readVarint(packetData)
		if err != nil {
			fmt.Println("Error decoding packet ID:", err)
			return
		}
		packetID := packetIDResult.value

		// Check for auth mode packets and stop reading once detected
		switch packetID {
		case 0x01:
			// 0x01 Means auth mode is premium/online
			select {
			case authMode <- 1: // 1 for premium/online
			case <-ctx.Done():
			}
			return // Stop the read loop immediately
		case 0x02, 0x03:
			// 0x03 or 0x02 Means auth mode is offline
			select {
			case authMode <- 0: // 0 for offline
			case <-ctx.Done():
			}
			return // Stop the read loop immediately
		case 0x00:
			// 0x00 Means auth mode is whitelisted
			select {
			case authMode <- 2: // 2 for whitelisted
			case <-ctx.Done():
			}
			return // Stop the read loop immediately
		default:
			// do nothing for other packet IDs
		}
	}
}

func getAuthMode(conn net.Conn, protocolVersion int, host string, port uint16) (int, error) {
	disconnectingGracefully := false
	connection := &ConnectionData{
		State: STATE_STATUS,
	}
	if err := sendHandshakeWithParams(conn, connection, host, port, protocolVersion); err != nil {
		return -1, err
	}

	// 2) Send Login Start
	if err := sendLoginStart(conn, connection, "MCScans", "00000000-0000-0000-0000-000000000000", protocolVersion); err != nil {
		return -1, err
	}
	connection.State = STATE_LOGIN

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	disconnected := make(chan struct{})
	authMode := make(chan int, 1) // Buffered channel to receive auth mode

	wg.Add(1)
	go func() {
		defer wg.Done()
		readLoop(ctx, conn, connection, disconnected, authMode)
	}()

	select {
	case <-time.After(30 * time.Second):
		cancel()
		wg.Wait()
		return -1, errors.New("timeout waiting for auth mode")
	case mode := <-authMode:
		cancel()
		wg.Wait()
		return mode, nil
	case <-disconnected:
		if !disconnectingGracefully {
			cancel()
			wg.Wait()
			return -1, errors.New("disconnected by server")
		}
		cancel()
		wg.Wait()
		return -1, errors.New("disconnected gracefully but no auth mode received")
	}
}
