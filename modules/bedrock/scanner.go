// Minecraft module to grab the server's MOTD and version for bedrock edition
package bedrock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
)

// Network Util Functions

// ReadBigInt64BE reads a big-endian encoded int64 from the buffer at the specified offset.
func ReadBigInt64BE(buffer []byte, offset int) int64 {
	return int64(binary.BigEndian.Uint64(buffer[offset:]))
}

// ReadStringFromBuffer reads a string from the buffer at the specified offset.
func ReadStringFromBuffer(buffer []byte, offset int) string {
	length := int(binary.BigEndian.Uint16(buffer[offset:]))
	return string(buffer[offset+2 : offset+2+length])
}

// ParseUnconnectedPong extracts the Server ID string from raw Unconnected Pong packet bytes
func ParseUnconnectedPong(packetData []byte) (string, error) {
	if len(packetData) < 33 { // Minimum: 1 byte packet ID + 32 bytes headers
		return "", errors.New("packet too short to be a valid Unconnected Pong packet")
	}

	// Check packet ID (should be 0x1c for Unconnected Pong)
	if packetData[0] != 0x1c {
		return "", fmt.Errorf("invalid packet ID: expected 0x1c, got 0x%02x", packetData[0])
	}

	offset := 1

	// Skip Time (8 bytes)
	offset += 8

	// Skip Server GUID (8 bytes)
	offset += 8

	// Skip MAGIC (16 bytes)
	offset += 16

	// Read string length (2 bytes, unsigned short, big-endian)
	if len(packetData) < offset+2 {
		return "", errors.New("packet too short to contain string length")
	}

	stringLength := binary.BigEndian.Uint16(packetData[offset : offset+2])
	offset += 2

	// Read the Server ID string
	if len(packetData) < offset+int(stringLength) {
		return "", fmt.Errorf("packet too short to contain Server ID string of length %d", stringLength)
	}

	serverIDString := string(packetData[offset : offset+int(stringLength)])

	return serverIDString, nil
}

// ParseAdvertiseString parses the advertise string into a struct.
func ParseAdvertiseString(advertiseStr string) (*AdvertiseData, error) {
	parts := strings.Split(advertiseStr, ";")
	if len(parts) < 9 {
		return nil, errors.New("advertise string is missing required fields")
	}

	data := &AdvertiseData{
		Edition:         parts[0],
		MOTDLine1:       parts[1],
		ProtocolVersion: parts[2],
		VersionName:     parts[3],
		PlayerCount:     parts[4],
		MaxPlayerCount:  parts[5],
		ServerGUID:      parts[6],
		MOTDLine2:       parts[7],
		GameMode:        parts[8],
		GameModeNumeric: -1, // default fallback
	}

	if len(parts) > 9 {
		if modeNum, err := strconv.Atoi(parts[9]); err == nil {
			data.GameModeNumeric = modeNum
		}
	}

	if len(parts) > 10 {
		if port4, err := strconv.Atoi(parts[10]); err == nil {
			data.PortIPv4 = port4
		}
	}

	if len(parts) > 11 {
		if port6, err := strconv.Atoi(parts[11]); err == nil {
			data.PortIPv6 = port6
		}
	}

	return data, nil
}

// AdvertiseData represents the parsed advertise data.
type AdvertiseData struct {
	Edition         string
	MOTDLine1       string
	ProtocolVersion string
	VersionName     string
	PlayerCount     string
	MaxPlayerCount  string
	ServerGUID      string
	MOTDLine2       string
	GameMode        string
	GameModeNumeric int
	PortIPv4        int
	PortIPv6        int
}

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	MaxTries int `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type Results struct {
	Edition         string `json:"edition"`
	MOTDLine1       string `json:"motd_line1"`
	ProtocolVersion string `json:"protocol"`
	VersionName     string `json:"version"`
	ServerGUID      string `json:"serverGuid"`
	MOTDLine2       string `json:"motd_line2"`
	GameMode        string `json:"mode"`
	GameModeNumeric int    `json:"modeNumeric"`
	PortIPv4        int    `json:"portIpv4"`
	PortIPv6        int    `json:"portIpv6"`

	PlayerStats struct {
		MaxPlayers    int `json:"maxPlayers"`
		OnlinePlayers int `json:"onlinePlayers"`
	} `json:"playerstats"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("bedrock", "bedrock", module.Description(), 19132, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Read the Minecraft Bedrock Ping Packet from the server."
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "bedrock"
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

func Receive(sock net.Conn) (int, []byte, error) {
	var received int
	ReceiveChunkSize := 8192
	buffer := bytes.NewBuffer(nil)
	for {
		chunk := make([]byte, ReceiveChunkSize)
		read, err := sock.Read(chunk)
		if err != nil {
			return received, buffer.Bytes(), err
		}
		received += read
		buffer.Write(chunk[:read])

		if read == 0 || read < ReceiveChunkSize {
			break
		}
	}
	return received, buffer.Bytes(), nil
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var panicErr error // this seems to not really work, but we do recover from panics in the main loop

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
			panicErr = fmt.Errorf("panic occurred: %v", r)
		}
	}()

	sock, err := target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer sock.Close()

	result := &Results{}
	for i := 0; i < scanner.config.MaxTries; i++ {
		// Send packet
		_, err = sock.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		// recv
		buffer := make([]byte, 65535)
		length, err := sock.Read(buffer)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		buffer = buffer[:length]

		// FIXED: Use proper packet parsing instead of hardcoded offset
		bufData, err := ParseUnconnectedPong(buffer)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		parsedData, err := ParseAdvertiseString(bufData)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		// convert CurrentPlayers and MaxPlayers to PlayerStats[MaxPlayers, OnlinePlayers] - mcscans internal format
		playerstats := struct {
			MaxPlayers    int `json:"maxPlayers"`
			OnlinePlayers int `json:"onlinePlayers"`
		}{}

		playerstats.MaxPlayers, _ = strconv.Atoi(parsedData.MaxPlayerCount)
		playerstats.OnlinePlayers, _ = strconv.Atoi(parsedData.PlayerCount)

		*result = Results{
			Edition:         parsedData.Edition,
			MOTDLine1:       parsedData.MOTDLine1,
			ProtocolVersion: parsedData.ProtocolVersion,
			VersionName:     parsedData.VersionName,
			ServerGUID:      parsedData.ServerGUID,
			MOTDLine2:       parsedData.MOTDLine2,
			GameMode:        parsedData.GameMode,
			GameModeNumeric: parsedData.GameModeNumeric,
			PortIPv4:        parsedData.PortIPv4,
			PortIPv6:        parsedData.PortIPv6,
		}

		result.PlayerStats.MaxPlayers = playerstats.MaxPlayers
		result.PlayerStats.OnlinePlayers = playerstats.OnlinePlayers
	}

	if panicErr != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, panicErr
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
