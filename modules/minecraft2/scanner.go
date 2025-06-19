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

func convertColorToMinecraftColor(color string) string {
	// convert color name to § character
	switch color {
	case "black":
		return "§0"
	case "dark_blue":
		return "§1"
	case "dark_green":
		return "§2"
	case "dark_aqua":
		return "§3"
	case "dark_red":
		return "§4"
	case "dark_purple":
		return "§5"
	case "gold":
		return "§6"
	case "gray":
		return "§7"
	case "dark_gray":
		return "§8"
	case "blue":
		return "§9"
	case "green":
		return "§a"
	case "aqua":
		return "§b"
	case "red":
		return "§c"
	case "light_purple":
		return "§d"
	case "yellow":
		return "§e"
	case "white":
		return "§f"
	default:
		// if color is not recognized, return empty string
		return ""
	}
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
	// prevent panics
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)

			// Get the traceback
			trace := make([]byte, 1<<16)
			n := runtime.Stack(trace, true)
			trace = trace[:n]

			// Write the traceback to a file
			file, err := os.Create("traceback_" + hostAddress + ".txt")
			if err != nil {
				fmt.Println("Error creating file:", err)
				return
			}
			defer file.Close()

			// append hostAddress to traceback
			trace = append([]byte(hostAddress+" - "), trace...)

			_, err = file.WriteString(string(trace))
			if err != nil {
				fmt.Println("Error writing to file:", err)
				return
			}

			// Set the error message
			panicErr = fmt.Errorf("Recovered in f: %v\nTraceback:\n%s", r, trace)
		}
	}()

	if panicErr != nil {
		return nil, panicErr
	}

	// {"enforcesSecureChat":false,"description":{"text":"A Minecraft Server"},"players":{"max":20,"online":1,"sample":[{"id":"d331d3ab-cd55-3c58-ab6f-e75b1e27b6d0","name":"xSpeziato"}]},"version":{"name":"Paper 1.19.3","protocol":761}}
	var data interface{}
	json.Unmarshal([]byte(response), &data)

	if dataMap, ok := data.(map[string]interface{}); ok {
		// create new PingResponse
		pingResponse := CustomPingResponse{}

		// check if version field exists
		var version = "Unknown"
		if _, ok := dataMap["version"]; ok {
			// if name exists under version, use it
			if _, ok := dataMap["version"].(map[string]interface{})["name"]; ok {
				version = dataMap["version"].(map[string]interface{})["name"].(string)
			}
		}

		var motd = ""
		if _, ok := dataMap["description"]; ok {
			// check if description is a map or a string (BungeeCord)
			if _, ok := dataMap["description"].(map[string]interface{}); ok {
				// if text exists under description, use it
				if _, ok := dataMap["description"].(map[string]interface{})["text"]; ok {
					motd = dataMap["description"].(map[string]interface{})["text"].(string)
				}

				// check "extra" array exists under description
				descMap := dataMap["description"].(map[string]interface{})

				if extra, ok := descMap["extra"]; ok {
					motd += parseExtra(extra, 0)
				}
			} else {
				if _, ok := dataMap["description"].(string); ok {
					motd = dataMap["description"].(string)
				}
			}
		}

		// check if MOTD is empty, this is the case for BungeeCord & its forks
		if motd == "" {
			// if description is a map
			if _, ok := dataMap["description"].(map[string]interface{}); ok {
				if _, ok := dataMap["description"].(map[string]interface{})["extra"]; ok {
					if _, ok := dataMap["description"].(map[string]interface{})["extra"].([]interface{}); ok {
						extraArray := dataMap["description"].(map[string]interface{})["extra"].([]interface{})
						for _, value := range extraArray {
							// In some strange cases, the extra array contains strings

							// TODO: What if the extra array has both a string and a map?
							if _, ok := value.(string); ok {
								motd += value.(string)
								continue
							}

							if _, ok := value.(map[string]interface{})["text"]; ok {
								// if text is a string
								if _, ok := value.(map[string]interface{})["text"].(string); ok {
									motd += value.(map[string]interface{})["text"].(string)
								}
							}
						}
					}
				}
			} else {
				// if motd is an array of objects
				if _, ok := dataMap["description"].([]interface{}); ok {
					extraArray := dataMap["description"].([]interface{})
					for _, value := range extraArray {
						if _, ok := value.(map[string]interface{})["text"]; ok {
							// if text is a string
							if _, ok := value.(map[string]interface{})["text"].(string); ok {
								motd += value.(map[string]interface{})["text"].(string)
							}
						}
					}
				}
			}
		}

		if motd == "" {
			motd = "Unknown"
		}

		// create new PlayerCount
		playerCount := types.PlayerCount{}

		// check if players field exists
		if _, ok := dataMap["players"]; ok {
			// check if max and online fields exist
			if _, ok := dataMap["players"].(map[string]interface{})["max"]; ok {
				playerCount.Max = int(dataMap["players"].(map[string]interface{})["max"].(float64))
			} else {
				playerCount.Max = -1
			}
			if _, ok := dataMap["players"].(map[string]interface{})["online"]; ok {
				playerCount.Online = int(dataMap["players"].(map[string]interface{})["online"].(float64))
			} else {
				playerCount.Online = -1
			}
		}

		// check if Protocol field exists
		var protocol = -1
		// if version exists
		if _, ok := dataMap["version"]; ok {
			// if protocol exists under version, use it
			if _, ok := dataMap["version"].(map[string]interface{})["protocol"]; ok {
				protocol = int(dataMap["version"].(map[string]interface{})["protocol"].(float64))
			}
		}

		// check if favicon field exists
		var favicon string
		if _, ok := dataMap["favicon"]; ok {
			favicon = dataMap["favicon"].(string)
		} else {
			favicon = ""
		}

		var playerSamples []types.PlayerSample
		// check if sample field exists under players
		if playersMap, ok := dataMap["players"].(map[string]interface{}); ok {
			if sample, ok := playersMap["sample"].([]interface{}); ok {
				for _, v := range sample {
					sample := types.PlayerSample{}
					if id, ok := v.(map[string]interface{})["id"].(string); ok {
						sample.UUID = id
					} else {
						sample.UUID = ""
					}
					if name, ok := v.(map[string]interface{})["name"].(string); ok {
						sample.Name = name
					} else {
						sample.Name = ""
					}
					playerSamples = append(playerSamples, sample)
				}
			}
		}

		// set fml
		var forgeModList []FMLMod
		if _, ok := dataMap["modinfo"]; ok {
			// check if modinfo["modList"] exists
			if modList, ok := dataMap["modinfo"].(map[string]interface{})["modList"].([]interface{}); ok {
				for _, v := range modList {
					// create new FMLMod
					fmlMod := FMLMod{}
					if modid, ok := v.(map[string]interface{})["modid"].(string); ok {
						fmlMod.ModId = modid
					} else {
						fmlMod.ModId = ""
					}

					if version, ok := v.(map[string]interface{})["version"].(string); ok {
						fmlMod.Version = version
					} else {
						fmlMod.Version = ""
					}
					forgeModList = append(forgeModList, fmlMod)
				}
			}
		}

		// check if "modpackData" is present
		if _, ok := dataMap["modpackData"]; ok {
			// change "Version" to begin with "Fabric"
			version = "Fabric " + version

			fmlMod := FMLMod{}
			if _, ok := dataMap["modpackData"].(map[string]interface{})["name"]; ok {
				fmlMod.ModId = dataMap["modpackData"].(map[string]interface{})["name"].(string)
			}
			if _, ok := dataMap["modpackData"].(map[string]interface{})["version"]; ok {
				fmlMod.Version = dataMap["modpackData"].(map[string]interface{})["version"].(string)
			}
			forgeModList = append(forgeModList, fmlMod)
		}

		// apparently forge also uses "forgeData" now
		if _, ok := dataMap["forgeData"]; ok {
			// print fmlNetworkVersion
			isModernNetworkVersion := false
			if _, ok := dataMap["forgeData"].(map[string]interface{})["fmlNetworkVersion"]; ok {
				version := dataMap["forgeData"].(map[string]interface{})["fmlNetworkVersion"].(float64)
				if version == 0 {
					isModernNetworkVersion = true
				}
			}
			// change "Version" to begin with "Forge"
			version = "Forge " + version
			// decompress forgeData "d" field
			if _, ok := dataMap["forgeData"].(map[string]interface{})["d"]; ok {
				decompressed, err := decodeOptimized(dataMap["forgeData"].(map[string]interface{})["d"].(string))
				if err != nil {
					fmt.Println("Error decompressing forgeData:", err, " - ", hostAddress)
				}

				// use forge's custom decoding
				mods, err := decodeForgePayload(decompressed, isModernNetworkVersion)
				if err != nil {
					fmt.Println("Error decoding forgeData:", err, " - ", hostAddress)
				} else {
					forgeModList = append(forgeModList, mods...)
				}
			}
		}

		// neoforge is special and uses the "isModded" field
		if _, ok := dataMap["isModded"]; ok {
			// change "Version" to begin with "NeoForge"
			version = "NeoForge " + version
		}

		pingResponse.Latency = 0
		pingResponse.PlayerCount = playerCount
		pingResponse.Protocol = protocol
		pingResponse.Favicon = favicon
		pingResponse.Motd = motd
		pingResponse.Version = version
		pingResponse.Sample = playerSamples
		pingResponse.ModList = forgeModList

		return &pingResponse, nil
	} else {
		return nil, errors.New("Invalid JSON response")
	}
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

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	hasPanic := false

	/* In case of a panic, recover and return a ScanError */
	defer func() {
		if r := recover(); r != nil {
			hasPanic = true
		}
	}()

	if hasPanic {
		panicErr := errors.New("Panic")
		return zgrab2.TryGetScanStatus(panicErr), nil, panicErr
	}

	/* Begin new Minecraft scan */
	var (
		conn net.Conn
		err  error
		ret  []byte
	)

	// Connect to the server
	conn, err = target.Open(&scanner.config.BaseFlags)

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	sendPacket(target.Host(), uint16(scanner.GetPort()), &conn)

	var waitTime = 2 * time.Second
	if scanner.config.MaxTimeout != 0 {
		waitTime = time.Duration(scanner.config.MaxTimeout) * time.Second
	}

	ret, _ = zgrab2.ReadAvailableWithOptions(conn, 65535, waitTime, waitTime, 65535)
	defer conn.Close()

	if len(ret) < 3 {
		err = errors.New("error to small response")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// Length: varint, Packet ID: varint, Data: byte[]
	// attempt to read length of packet
	_, varint_size, err := read_varint(ret)
	if err != nil {
		err = errors.New("error reading varint (packet len)")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// truncate first varint
	ret = ret[varint_size:]
	// attempt to read packet ID
	_, varint_size, err = read_varint(ret)
	if err != nil {
		err = errors.New("error reading varint (packet id)")
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// truncate second varint
	ret = ret[varint_size:]

	if len(ret) < 10 {
		err = errors.New("error to small response")
		return zgrab2.TryGetScanStatus(err), nil, err
	} else if len(ret) > 700000 {
		err = errors.New("error to big response")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// remove all characters until the first '{'

	// check if '{' or '}' exists within the first 10 bytes
	if bytes.IndexByte(ret, '{') == -1 || bytes.IndexByte(ret, '}') == -1 {
		err = errors.New("error no json")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	ret = ret[bytes.IndexByte(ret, '{'):]
	// remove all characters after last '}'
	ret = ret[:bytes.LastIndexByte(ret, '}')+1]

	decode, err := decodeResponse(string(ret), target.Host())
	// TODO: Add proper error handling

	if err != nil {
		err = errors.New("panic")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	var scanLatency = ""
	if scanner.config.EnableLatency {
		scanLatency = getLatency(target.Host(), uint16(scanner.GetPort())).String()
	}

	serverAuthMode := -1 // Default to -1 (unknown)
	if scanner.config.GrabAuthMode {
		new_conn, err := target.Open(&scanner.config.BaseFlags)
		if err != nil {
			serverAuthMode = -1 // Default to -1 (unknown) if we can't connect
		}
		defer new_conn.Close()
		authMode, err := getAuthMode(new_conn, decode.Protocol, target.Host(), uint16(scanner.GetPort()))
		if err != nil {
			serverAuthMode = -1 // Default to -1 (unknown) if we can't get the auth mode
		}
		serverAuthMode = authMode
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
		}{decode.PlayerCount.Max, decode.PlayerCount.Online},
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
