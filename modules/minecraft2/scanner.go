// Minecraft module to grab the server's MOTD and version
package minecraft2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	_ "io"
	"log"
	"net"
	"os"
	"runtime"
	"time"
	_ "time"

	"github.com/iverly/go-mcping/api/types"
	"github.com/zmap/zgrab2"
)

const (
	VERSION_FLAG_IGNORESERVERONLY = 0b1
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	MaxTries      int  `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
	MaxTimeout    int  `long:"max-timeout" default:"2" description:"Number of seconds to wait before timing out."`
	EnableLatency bool `long:"enable-latency" description:"Enable latency measurement. May drastically increase scan time."`
	GrabAuthMode  bool `long:"grab-auth-mode" description:"Enable auth mode grab. This will add the auth mode to the results."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type Results struct {
	Latency     string `json:"latency",omitempty`
	Protocol    string `json:"protocol"`
	Favicon     string `json:"favicon"`
	Motd        string `json:"motd"`
	Version     string `json:"version"`
	PlayerStats struct {
		MaxPlayers    int `json:"maxPlayers"`
		OnlinePlayers int `json:"onlinePlayers"`
	} `json:"playerstats"`
	Players  []Player `json:"players",omitempty`
	ModList  []FMLMod `json:"modlist",omitempty`
	AuthMode int      `json:"authMode"` // -1 = unknown, 0 = offline, 1 = online, 2 = whitelist
}

type Player struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type CustomPingResponse struct {
	Latency     uint                 // Latency between you and the server
	PlayerCount types.PlayerCount    // Players count information of the server
	Protocol    int                  // Protocol number of the server
	Favicon     string               // Favicon in base64 of the server
	Motd        string               // Motd of the server without color
	Version     string               // Version of the server
	Sample      []types.PlayerSample // List of connected players on the server
	ModList     []FMLMod             // List of FML mods on the server
}

type ModChannel struct {
	Name     string `json:"name"`
	Version  uint64 `json:"version"`
	Required bool   `json:"required"`
}

type FMLMod struct {
	ModId    string `json:"modId"`
	Version  string `json:"version"`
	Channels []Channel
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("minecraft2", "minecraft2", module.Description(), 25565, &module)
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
	return "Grab Minecraft server info from the target host"
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
	return "minecraft"
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

func ConvertPlayerSampleToPlayer(playersSample []types.PlayerSample) []Player {
	var players []Player
	for _, sample := range playersSample {
		players = append(players, Player{UUID: sample.UUID, Name: sample.Name})
	}
	return players
}

func sendPacket(host string, port uint16, conn *net.Conn) {
	var dataBuf bytes.Buffer
	var finBuf bytes.Buffer

	writeProtocol(&dataBuf, "\x6D") // 1.9 protocol
	writeHost(&dataBuf, host)
	writePort(&dataBuf, port)
	dataBuf.Write([]byte("\x01")) // end of packet

	// Prepend packet length with data
	packetLength := []byte{uint8(dataBuf.Len())}
	finBuf.Write(append(packetLength, dataBuf.Bytes()...))

	// Sending packet
	(*conn).Write(finBuf.Bytes())
	(*conn).Write([]byte("\x01\x00"))
}

func writeProtocol(b *bytes.Buffer, protocol string) {
	b.Write([]byte("\x00")) // Packet ID
	b.Write([]byte(protocol))
}

func writeHost(b *bytes.Buffer, host string) {
	b.Write([]uint8{uint8(len(host))})
	b.Write([]byte(host))
}

func writePort(b *bytes.Buffer, port uint16) {
	a := make([]byte, 2)
	binary.BigEndian.PutUint16(a, port)
	b.Write(a)
}

type Channel struct {
	Name     string
	Version  string
	Required bool
}

var minecraftColors = map[string]string{
	"black":        "§0",
	"dark_blue":    "§1",
	"dark_green":   "§2",
	"dark_aqua":    "§3",
	"dark_red":     "§4",
	"dark_purple":  "§5",
	"gold":         "§6",
	"gray":         "§7",
	"dark_gray":    "§8",
	"blue":         "§9",
	"green":        "§a",
	"aqua":         "§b",
	"red":          "§c",
	"light_purple": "§d",
	"yellow":       "§e",
	"white":        "§f",
}

func convertColorToMinecraftColor(color string) string {
	return minecraftColors[color]
}

const maxExtraDepth = 50 // prevent infinite recursion in extra parsing

func parseExtra(extra interface{}, depth int) string {
	if depth > maxExtraDepth {
		return "[...]"
	}

	result := ""

	switch value := extra.(type) {
	case string:
		result += value

	case map[string]interface{}:
		if color, ok := value["color"].(string); ok {
			result += convertColorToMinecraftColor(color)
		}
		if text, ok := value["text"].(string); ok {
			result += text
		}
		if nestedExtra, ok := value["extra"]; ok {
			result += parseExtra(nestedExtra, depth+1)
		}

	case []interface{}:
		for _, item := range value {
			result += parseExtra(item, depth+1)
		}
	}

	return result
}

func decodeResponse(response string, hostAddress string) (*CustomPingResponse, error) {
	var panicErr error

	// panic recovery
	defer func() {
		if r := recover(); r != nil {
			trace := make([]byte, 1<<16)
			n := runtime.Stack(trace, true)
			trace = trace[:n]

			file, err := os.Create("traceback_" + hostAddress + ".txt")
			if err == nil {
				defer file.Close()
				trace = append([]byte(hostAddress+" - "), trace...)
				file.WriteString(string(trace))
			}

			panicErr = fmt.Errorf("Recovered: %v\n%s", r, trace)
		}
	}()

	// helpers
	getMap := func(v interface{}) (map[string]interface{}, bool) {
		m, ok := v.(map[string]interface{})
		return m, ok
	}
	getArr := func(v interface{}) ([]interface{}, bool) {
		a, ok := v.([]interface{})
		return a, ok
	}
	getString := func(m map[string]interface{}, key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}
	getInt := func(m map[string]interface{}, key string, def int) int {
		if v, ok := m[key].(float64); ok {
			return int(v)
		}
		return def
	}

	var data interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		return nil, err
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("Invalid JSON response")
	}

	// Version
	version := "Unknown"
	if vMap, ok := getMap(dataMap["version"]); ok {
		if name := getString(vMap, "name"); name != "" {
			version = name
		}
	}

	// MOTD
	parseTextArray := func(arr []interface{}) (out string) {
		for _, v := range arr {
			switch val := v.(type) {
			case string:
				out += val
			case map[string]interface{}:
				if text, ok := val["text"].(string); ok {
					out += text
				}
			}
		}
		return
	}

	motd := ""
	if desc, ok := dataMap["description"]; ok {
		switch d := desc.(type) {
		case string:
			motd = d

		case map[string]interface{}:
			motd = getString(d, "text")
			if extra, ok := getArr(d["extra"]); ok {
				motd += parseTextArray(extra)
			}

		case []interface{}:
			motd = parseTextArray(d)
		}
	}

	if motd == "" {
		motd = "Unknown"
	}

	// PLAYERS
	playerCount := types.PlayerCount{Max: -1, Online: -1}
	if pMap, ok := getMap(dataMap["players"]); ok {
		playerCount.Max = getInt(pMap, "max", -1)
		playerCount.Online = getInt(pMap, "online", -1)
	}

	// PROTOCOL
	protocol := -1
	if vMap, ok := getMap(dataMap["version"]); ok {
		protocol = getInt(vMap, "protocol", -1)
	}

	// FAVICON
	favicon := ""
	if f, ok := dataMap["favicon"].(string); ok {
		favicon = f
	}

	// SAMPLE PLAYERS
	var playerSamples []types.PlayerSample
	if pMap, ok := getMap(dataMap["players"]); ok {
		if sampleArr, ok := getArr(pMap["sample"]); ok {
			for _, v := range sampleArr {
				if m, ok := getMap(v); ok {
					playerSamples = append(playerSamples, types.PlayerSample{
						UUID: getString(m, "id"),
						Name: getString(m, "name"),
					})
				}
			}
		}
	}

	// MODS
	var forgeModList []FMLMod

	if modinfo, ok := getMap(dataMap["modinfo"]); ok {
		if modList, ok := getArr(modinfo["modList"]); ok {
			for _, v := range modList {
				if m, ok := getMap(v); ok {
					forgeModList = append(forgeModList, FMLMod{
						ModId:   getString(m, "modid"),
						Version: getString(m, "version"),
					})
				}
			}
		}
	}

	if mp, ok := getMap(dataMap["modpackData"]); ok {
		version = "Fabric " + version
		forgeModList = append(forgeModList, FMLMod{
			ModId:   getString(mp, "name"),
			Version: getString(mp, "version"),
		})
	}

	if fd, ok := getMap(dataMap["forgeData"]); ok {
		isModern := false
		if v, ok := fd["fmlNetworkVersion"].(float64); ok && v == 0 {
			isModern = true
		}

		version = "Forge " + version

		if d, ok := fd["d"].(string); ok {
			if decompressed, err := decodeOptimized(d); err == nil {
				if mods, err := decodeForgePayload(decompressed, isModern); err == nil {
					forgeModList = append(forgeModList, mods...)
				}
			}
		}
	}

	if _, ok := dataMap["isModded"]; ok {
		version = "NeoForge " + version
	}

	// FINAL
	return &CustomPingResponse{
		Latency:     0,
		PlayerCount: playerCount,
		Protocol:    protocol,
		Favicon:     favicon,
		Motd:        motd,
		Version:     version,
		Sample:      playerSamples,
		ModList:     forgeModList,
	}, panicErr
}

/***
 * Function to get the latency of a Minecraft server (in milliseconds)
 * Connects via tcp and returns the time it took to connect
 * @param host string
 * @param port uint16
 * @return time.Duration
 */
func getLatency(host string, port uint16) time.Duration {
	// start timer
	start := time.Now()
	// connect to server
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return -1
	}
	// close connection
	conn.Close()
	// return time it took to connect
	return time.Since(start)
}

// read_varint reads a varint from the given byte[]
func read_varint(data []byte) (uint64, int, error) {
	var value uint64
	var shift uint
	for i, b := range data {
		value |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, 0, errors.New("varint is too long")
		}
	}
	return 0, 0, errors.New("incomplete varint")
}

// decodeOptimized decodes a Java-style UTF-16 encoded string into a byte buffer.
func decodeOptimized(s string) ([]byte, error) {
	runes := []rune(s) // each rune represents a Java char (UTF-16 code unit)
	if len(runes) < 2 {
		return nil, fmt.Errorf("string too short")
	}

	size0 := int(runes[0])
	size1 := int(runes[1])
	size := size0 | (size1 << 15)

	var buf bytes.Buffer
	stringIndex := 2
	buffer := 0
	bitsInBuf := 0

	for stringIndex < len(runes) {
		for bitsInBuf >= 8 {
			buf.WriteByte(byte(buffer & 0xFF))
			buffer >>= 8
			bitsInBuf -= 8
		}

		c := int(runes[stringIndex])
		buffer |= (c & 0x7FFF) << bitsInBuf
		bitsInBuf += 15
		stringIndex++
	}

	for buf.Len() < size {
		buf.WriteByte(byte(buffer & 0xFF))
		buffer >>= 8
		bitsInBuf -= 8
	}

	return buf.Bytes(), nil
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, err error) {

	// panic recovery
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			status = zgrab2.TryGetScanStatus(err)
			result = nil
		}
	}()

	// connect
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	sendPacket(target.Host(), uint16(scanner.GetPort()), &conn)

	waitTime := 2 * time.Second
	if scanner.config.MaxTimeout != 0 {
		waitTime = time.Duration(scanner.config.MaxTimeout) * time.Second
	}

	ret, _ := zgrab2.ReadAvailableWithOptions(conn, 65535, waitTime, waitTime, 65535)

	if len(ret) < 3 {
		err = errors.New("response too small")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// remove packet length
	_, n, err := read_varint(ret)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, errors.New("error reading packet length")
	}
	ret = ret[n:]

	// remove packet id
	_, n, err = read_varint(ret)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, errors.New("error reading packet id")
	}
	ret = ret[n:]

	if len(ret) < 10 {
		err = errors.New("response too small")
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if len(ret) > 700000 {
		err = errors.New("response too large")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// extract JSON object
	start := bytes.IndexByte(ret, '{')
	end := bytes.LastIndexByte(ret, '}')
	if start == -1 || end == -1 || start >= end {
		err = errors.New("invalid json")
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	ret = ret[start : end+1]

	decode, err := decodeResponse(string(ret), target.Host())
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// latency
	var scanLatency string
	if scanner.config.EnableLatency {
		scanLatency = getLatency(target.Host(), uint16(scanner.GetPort())).String()
	}

	// auth mode
	serverAuthMode := -1
	if scanner.config.GrabAuthMode {
		if newConn, err := target.Open(&scanner.config.BaseFlags); err == nil {
			defer newConn.Close()
			if authMode, err := getAuthMode(newConn, decode.Protocol, target.Host(), uint16(scanner.GetPort())); err == nil {
				serverAuthMode = authMode
			}
		}
	}

	return zgrab2.SCAN_SUCCESS, &Results{
		Latency:  scanLatency,
		Protocol: fmt.Sprintf("%d", decode.Protocol),
		Favicon:  decode.Favicon,
		Motd:     decode.Motd,
		Version:  decode.Version,
		PlayerStats: struct {
			MaxPlayers    int `json:"maxPlayers"`
			OnlinePlayers int `json:"onlinePlayers"`
		}{
			decode.PlayerCount.Max,
			decode.PlayerCount.Online,
		},
		Players:  ConvertPlayerSampleToPlayer(decode.Sample),
		ModList:  decode.ModList,
		AuthMode: serverAuthMode,
	}, nil
}

/**
 * MC Helper Functions
 **/
func read_boolean(data []byte, offset int) (bool, int) {
	return data[offset] == 1, 1
}

func read_unsigned_short(data []byte, offset int) (uint16, int) {
	value := uint16(data[offset])<<8 | uint16(data[offset+1])
	return value, 2
}

func read_varint_new(data []byte, offset int) (uint32, int) {
	var result uint32
	var shift uint32
	var bytesRead int

	for {
		if offset+bytesRead >= len(data) {
			panic("read_varint: buffer overrun")
		}

		b := data[offset+bytesRead]
		result |= uint32(b&0x7F) << shift
		bytesRead++

		if (b & 0x80) == 0 {
			break
		}
		shift += 7

		if shift >= 35 {
			panic("read_varint: varint too big")
		}
	}

	return result, bytesRead
}

func ReadMCString(data []byte, offset int, maxCodeUnits int) (string, int, error) {
	strLen, bytesRead := read_varint_new(data, offset) // now returns the length and bytes consumed
	totalOffset := offset + bytesRead

	if totalOffset+int(strLen) > len(data) {
		return "", offset, errors.New("not enough bytes to read the string")
	}

	strBytes := data[totalOffset : totalOffset+int(strLen)]
	str := string(strBytes)

	if countUTF16CodeUnits(str) > maxCodeUnits {
		return "", offset, errors.New("string exceeds UTF-16 code unit limit")
	}

	// Return the string, and total bytes consumed (length of varint + string bytes)
	return str, bytesRead + int(strLen), nil
}

func countUTF16CodeUnits(s string) int {
	count := 0
	for _, r := range s {
		if r <= 0xFFFF {
			count++
		} else {
			count += 2 // surrogate pair
		}
	}
	return count
}

func decodeForgePayload(data []byte, isModernNetworkVersion bool) ([]FMLMod, error) {
	var modList []FMLMod
	// Extract if the data is Truncated first (Bool)
	var offset int = 0

	truncated, bytesRead := read_boolean(data, offset)

	if truncated {
		return nil, fmt.Errorf("data is truncated")
	}
	offset += bytesRead // now += 1

	modCount, bytesRead := read_unsigned_short(data, offset)
	offset += bytesRead

	for i := 0; i < int(modCount); i++ {
		// read varint: channelSizeAndVersionFlag
		channelSizeAndVersionFlag, bytesRead := read_varint_new(data, offset)
		offset += bytesRead
		channelSize := channelSizeAndVersionFlag >> 1
		// var isIgnoreServerOnly = (channelSizeAndVersionFlag & VERSION_FLAG_IGNORESERVERONLY) != 0;
		isIgnoreServerOnly := (channelSizeAndVersionFlag & VERSION_FLAG_IGNORESERVERONLY) != 0

		// read varint prefixed string: modId
		modId, bytesRead, err := ReadMCString(data, offset, 32767)
		if err != nil {
			return nil, fmt.Errorf("failed to read modId: %w", err)
		}
		offset += bytesRead

		// var modVersion = isIgnoreServerOnly ? IExtensionPoint.DisplayTest.IGNORESERVERONLY : buf.readUtf();
		var modVersion string
		if !isIgnoreServerOnly {
			modVersion, bytesRead, err = ReadMCString(data, offset, 32767)
			if err != nil {
				return nil, fmt.Errorf("failed to read modVersion: %w", err)
			}
			offset += bytesRead
		} else {
			modVersion = "IGNORESERVERONLY"
		}

		var channels []Channel

		for i1 := 0; i1 < int(channelSize); i1++ {
			channelName, bytesRead, err := ReadMCString(data, offset, 32767)
			if err != nil {
				return nil, fmt.Errorf("failed to read channelName: %w", err)
			}
			offset += bytesRead

			// read channel version
			var channelVersion string
			if isModernNetworkVersion {
				chVer, bytesRead := read_varint_new(data, offset)
				offset += bytesRead
				channelVersion = fmt.Sprintf("%d", chVer)
			} else {
				channelVersion, bytesRead, err = ReadMCString(data, offset, 32767)
				if err != nil {
					return nil, fmt.Errorf("failed to read channelVersion: %w", err)
				}
				offset += bytesRead
			}

			// read requiredOnClient bool
			requiredOnClient, bytesRead := read_boolean(data, offset)
			offset += bytesRead

			// append channel to channels
			channels = append(channels, Channel{
				Name:     channelName,
				Version:  channelVersion,
				Required: requiredOnClient,
			})
		}

		// append mod to modList
		modList = append(modList, FMLMod{
			ModId:    modId,
			Version:  modVersion,
			Channels: channels,
		})
	}

	// var nonModChannelCount = buf.readVarInt();
	nonModChannelCount, bytesRead := read_varint_new(data, offset)
	offset += bytesRead

	for i := 0; i < int(nonModChannelCount); i++ {
		channelName, bytesRead, err := ReadMCString(data, offset, 32767)
		if err != nil {
			return nil, fmt.Errorf("failed to read non-mod channelName: %w", err)
		}
		offset += bytesRead

		var chanVer string
		if isModernNetworkVersion {
			channelVersion, bytesRead := read_varint_new(data, offset)
			offset += bytesRead
			chanVer = fmt.Sprintf("%d", channelVersion)
		} else {
			channelVersion, bytesRead, err := ReadMCString(data, offset, 32767)
			if err != nil {
				return nil, fmt.Errorf("failed to read non-mod channelVersion: %w", err)
			}
			offset += bytesRead
			chanVer = channelVersion
		}

		requiredOnClient, bytesRead := read_boolean(data, offset)
		offset += bytesRead

		_ = channelName
		_ = chanVer
		_ = requiredOnClient
	}

	return modList, nil
}
