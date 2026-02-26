package kms

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// UUID represents a 16-byte UUID in KMS wire format (bytes_le).
type UUID [16]byte

func (u UUID) String() string {
	// Convert from bytes_le format to standard UUID string.
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(u[0:4]),
		binary.LittleEndian.Uint16(u[4:6]),
		binary.LittleEndian.Uint16(u[6:8]),
		u[8:10],
		u[10:16])
}

func UUIDFromString(s string) (UUID, error) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return UUID{}, fmt.Errorf("invalid UUID string length: %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return UUID{}, err
	}
	var u UUID
	// Convert to bytes_le format: first 3 groups are little-endian.
	u[0] = b[3]
	u[1] = b[2]
	u[2] = b[1]
	u[3] = b[0]
	u[4] = b[5]
	u[5] = b[4]
	u[6] = b[7]
	u[7] = b[6]
	copy(u[8:], b[8:])
	return u, nil
}

func MustUUID(s string) UUID {
	u, err := UUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return u
}

func RandomUUID() UUID {
	var u UUID
	rand.Read(u[:])
	return u
}

// KMSRequest represents the client's activation request (wire format).
type KMSRequest struct {
	VersionMinor            uint16
	VersionMajor            uint16
	IsClientVM              uint32
	LicenseStatus           uint32
	GraceTime               uint32
	ApplicationID           UUID
	SKUID                   UUID
	KMSCountedID            UUID
	ClientMachineID         UUID
	RequiredClientCount     uint32
	RequestTime             uint64
	PreviousClientMachineID UUID
	MachineNameRaw          []byte // UTF-16LE encoded, padded to 126 bytes total
}

func (r *KMSRequest) MachineName() string {
	u16s := make([]uint16, len(r.MachineNameRaw)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(r.MachineNameRaw[i*2:])
	}
	// Trim null terminators.
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

func ParseKMSRequest(data []byte) (*KMSRequest, error) {
	r := &KMSRequest{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, &r.VersionMinor); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.VersionMajor); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.IsClientVM); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.LicenseStatus); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.GraceTime); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.ApplicationID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.SKUID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.KMSCountedID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.ClientMachineID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.RequiredClientCount); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.RequestTime); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.PreviousClientMachineID); err != nil {
		return nil, err
	}

	// Read machine name (UTF-16LE, variable length up to 126 bytes).
	remaining := buf.Len()
	machineData := make([]byte, remaining)
	if _, err := buf.Read(machineData); err != nil {
		return nil, err
	}
	r.MachineNameRaw = machineData

	return r, nil
}

func (r *KMSRequest) Marshal() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, r.VersionMinor)
	binary.Write(&buf, binary.LittleEndian, r.VersionMajor)
	binary.Write(&buf, binary.LittleEndian, r.IsClientVM)
	binary.Write(&buf, binary.LittleEndian, r.LicenseStatus)
	binary.Write(&buf, binary.LittleEndian, r.GraceTime)
	binary.Write(&buf, binary.LittleEndian, r.ApplicationID)
	binary.Write(&buf, binary.LittleEndian, r.SKUID)
	binary.Write(&buf, binary.LittleEndian, r.KMSCountedID)
	binary.Write(&buf, binary.LittleEndian, r.ClientMachineID)
	binary.Write(&buf, binary.LittleEndian, r.RequiredClientCount)
	binary.Write(&buf, binary.LittleEndian, r.RequestTime)
	binary.Write(&buf, binary.LittleEndian, r.PreviousClientMachineID)
	buf.Write(r.MachineNameRaw)
	return buf.Bytes()
}

// KMSResponse represents the server's activation response (wire format).
type KMSResponse struct {
	VersionMinor         uint16
	VersionMajor         uint16
	EPIDLen              uint32
	KMSEpid              []byte // UTF-16LE encoded
	ClientMachineID      UUID
	ResponseTime         uint64
	CurrentClientCount   uint32
	VLActivationInterval uint32
	VLRenewalInterval    uint32
}

func (r *KMSResponse) Marshal() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, r.VersionMinor)
	binary.Write(&buf, binary.LittleEndian, r.VersionMajor)
	epidLen := uint32(len(r.KMSEpid) + 2) // +2 for null terminator
	binary.Write(&buf, binary.LittleEndian, epidLen)
	buf.Write(r.KMSEpid)
	buf.Write([]byte{0, 0}) // null terminator (UTF-16LE)
	binary.Write(&buf, binary.LittleEndian, r.ClientMachineID)
	binary.Write(&buf, binary.LittleEndian, r.ResponseTime)
	binary.Write(&buf, binary.LittleEndian, r.CurrentClientCount)
	binary.Write(&buf, binary.LittleEndian, r.VLActivationInterval)
	binary.Write(&buf, binary.LittleEndian, r.VLRenewalInterval)
	return buf.Bytes()
}

func ParseKMSResponse(data []byte) (*KMSResponse, error) {
	r := &KMSResponse{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, &r.VersionMinor); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.VersionMajor); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.EPIDLen); err != nil {
		return nil, err
	}
	epid := make([]byte, r.EPIDLen)
	if _, err := buf.Read(epid); err != nil {
		return nil, err
	}
	r.KMSEpid = epid
	if err := binary.Read(buf, binary.LittleEndian, &r.ClientMachineID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.ResponseTime); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.CurrentClientCount); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.VLActivationInterval); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &r.VLRenewalInterval); err != nil {
		return nil, err
	}
	return r, nil
}

// GenericRequestHeader is used to detect the KMS protocol version.
type GenericRequestHeader struct {
	BodyLength1  uint32
	BodyLength2  uint32
	VersionMinor uint16
	VersionMajor uint16
}

func ParseGenericRequestHeader(data []byte) (*GenericRequestHeader, error) {
	h := &GenericRequestHeader{}
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, h); err != nil {
		return nil, err
	}
	return h, nil
}

// License states.
var LicenseStates = map[uint32]string{
	0: "Unlicensed",
	1: "Activated",
	2: "Grace Period",
	3: "Out-of-Tolerance Grace Period",
	4: "Non-Genuine Grace Period",
	5: "Notifications Mode",
	6: "Extended Grace Period",
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	IP          string
	Port        int
	EPID        string
	LCID        int
	ClientCount *int
	Activation  int
	Renewal     int
	HWID        []byte
	SQLite      bool
	LogLevel    string
}

func DefaultServerConfig() *ServerConfig {
	hwid, _ := hex.DecodeString("364F463A8863D35F")
	return &ServerConfig{
		IP:         "0.0.0.0",
		Port:       1688,
		LCID:       1033,
		Activation: 120,
		Renewal:    10080,
		HWID:       hwid,
		LogLevel:   "ERROR",
	}
}

// GetPadding calculates the padding needed after a body.
func GetPadding(bodyLength int) int {
	return 4 + (((^bodyLength & 3) + 1) & 3)
}

// ServerLogic processes a KMS request and generates a response.
func ServerLogic(kmsRequest *KMSRequest, config *ServerConfig) *KMSResponse {
	log.Printf("Machine Name: %s", kmsRequest.MachineName())
	log.Printf("Client Machine ID: %s", kmsRequest.ClientMachineID)
	log.Printf("Application ID: %s", kmsRequest.ApplicationID)
	log.Printf("SKU ID: %s", kmsRequest.SKUID)
	log.Printf("KMS Counted ID: %s", kmsRequest.KMSCountedID)
	log.Printf("License Status: %s", LicenseStates[kmsRequest.LicenseStatus])
	log.Printf("Request Time: %s", FileTimeToTime(int64(kmsRequest.RequestTime)))

	// Activation threshold calculation.
	minClients := kmsRequest.RequiredClientCount
	requiredClients := minClients * 2
	var currentClientCount uint32

	if config.ClientCount != nil {
		cc := uint32(*config.ClientCount)
		if cc > 0 && cc < minClients {
			currentClientCount = minClients + 1
		} else if cc >= minClients && cc < requiredClients {
			currentClientCount = cc
		} else if cc >= requiredClients {
			currentClientCount = requiredClients
		}
	} else {
		currentClientCount = requiredClients
	}

	// Generate ePID.
	var epidUTF16 []byte
	if config.EPID == "" {
		epid := GenerateEPID(kmsRequest.KMSCountedID, kmsRequest.VersionMajor, config.LCID)
		epidUTF16 = EncodeUTF16LE(epid)
	} else {
		epidUTF16 = EncodeUTF16LE(config.EPID)
	}

	log.Printf("Server ePID: %s", DecodeUTF16LE(epidUTF16))

	response := &KMSResponse{
		VersionMinor:         kmsRequest.VersionMinor,
		VersionMajor:         kmsRequest.VersionMajor,
		KMSEpid:              epidUTF16,
		ClientMachineID:      kmsRequest.ClientMachineID,
		ResponseTime:         kmsRequest.RequestTime,
		CurrentClientCount:   currentClientCount,
		VLActivationInterval: uint32(config.Activation),
		VLRenewalInterval:    uint32(config.Renewal),
	}

	return response
}

// EncodeUTF16LE encodes a string to UTF-16LE bytes.
func EncodeUTF16LE(s string) []byte {
	u16s := utf16.Encode([]rune(s))
	b := make([]byte, len(u16s)*2)
	for i, v := range u16s {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// DecodeUTF16LE decodes UTF-16LE bytes to a string.
func DecodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Trim null terminators.
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

// GenerateKMSResponseData dispatches to the appropriate version handler.
func GenerateKMSResponseData(data []byte, config *ServerConfig) ([]byte, error) {
	header, err := ParseGenericRequestHeader(data)
	if err != nil {
		return nil, err
	}

	version := header.VersionMajor
	log.Printf("Received V%d request on %s.", version, time.Now().Format("Mon Jan 02 15:04:05 2006"))

	switch version {
	case 4:
		return HandleV4Request(data, config)
	case 5:
		return HandleV5Request(data, config)
	case 6:
		return HandleV6Request(data, config)
	default:
		log.Printf("Unhandled KMS version V%d.", version)
		return HandleUnknownRequest()
	}
}

// --- KMS Database XML Parsing ---

type KmsDataBase struct {
	WinBuilds []WinBuild
	CsvlkItems []CsvlkItem
	AppItems  []AppItem
}

type WinBuild struct {
	WinBuildIndex string `xml:"WinBuildIndex,attr"`
	BuildNumber   string `xml:"BuildNumber,attr"`
	PlatformId    string `xml:"PlatformId,attr"`
	MinDate       string `xml:"MinDate,attr"`
}

type CsvlkItem struct {
	GroupId         string `xml:"GroupId,attr"`
	MinKeyId        string `xml:"MinKeyId,attr"`
	MaxKeyId        string `xml:"MaxKeyId,attr"`
	InvalidWinBuild string `xml:"InvalidWinBuild,attr"`
	Activates       []string
}

type AppItem struct {
	Id          string `xml:"Id,attr"`
	DisplayName string `xml:"DisplayName,attr"`
	KmsItems    []KmsItem
}

type KmsItem struct {
	Id                 string `xml:"Id,attr"`
	DisplayName        string `xml:"DisplayName,attr"`
	NCountPolicy       string `xml:"NCountPolicy,attr"`
	DefaultKmsProtocol string `xml:"DefaultKmsProtocol,attr"`
	SkuItems           []SkuItem
}

type SkuItem struct {
	Id          string `xml:"Id,attr"`
	DisplayName string `xml:"DisplayName,attr"`
}

// XML structures for parsing.
type xmlRoot struct {
	XMLName   xml.Name      `xml:"KmsData"`
	WinBuilds []xmlWinBuild `xml:"WinBuild"`
	CsvlkItems []xmlCsvlk   `xml:"CsvlkItem"`
	AppItems  []xmlApp      `xml:"AppItem"`
}

type xmlWinBuild struct {
	WinBuildIndex string `xml:"WinBuildIndex,attr"`
	BuildNumber   string `xml:"BuildNumber,attr"`
	PlatformId    string `xml:"PlatformId,attr"`
	MinDate       string `xml:"MinDate,attr"`
}

type xmlCsvlk struct {
	GroupId         string        `xml:"GroupId,attr"`
	MinKeyId        string        `xml:"MinKeyId,attr"`
	MaxKeyId        string        `xml:"MaxKeyId,attr"`
	InvalidWinBuild string        `xml:"InvalidWinBuild,attr"`
	Activates       []xmlActivate `xml:"Activate"`
}

type xmlActivate struct {
	KmsItem string `xml:"KmsItem,attr"`
}

type xmlApp struct {
	Id          string       `xml:"Id,attr"`
	DisplayName string       `xml:"DisplayName,attr"`
	KmsItems    []xmlKmsItem `xml:"KmsItem"`
}

type xmlKmsItem struct {
	Id                 string       `xml:"Id,attr"`
	DisplayName        string       `xml:"DisplayName,attr"`
	NCountPolicy       string       `xml:"NCountPolicy,attr"`
	DefaultKmsProtocol string       `xml:"DefaultKmsProtocol,attr"`
	SkuItems           []xmlSkuItem `xml:"SkuItem"`
}

type xmlSkuItem struct {
	Id          string `xml:"Id,attr"`
	DisplayName string `xml:"DisplayName,attr"`
}

var kmsDBPath string

func SetKmsDBPath(path string) {
	kmsDBPath = path
}

func LoadKmsDB() (*KmsDataBase, error) {
	path := kmsDBPath
	if path == "" {
		exe, err := os.Executable()
		if err == nil {
			path = filepath.Join(filepath.Dir(exe), "KmsDataBase.xml")
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read KmsDataBase.xml: %w", err)
	}

	var root xmlRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse KmsDataBase.xml: %w", err)
	}

	db := &KmsDataBase{}

	for _, wb := range root.WinBuilds {
		db.WinBuilds = append(db.WinBuilds, WinBuild{
			WinBuildIndex: wb.WinBuildIndex,
			BuildNumber:   wb.BuildNumber,
			PlatformId:    wb.PlatformId,
			MinDate:       wb.MinDate,
		})
	}

	for _, csvlk := range root.CsvlkItems {
		item := CsvlkItem{
			GroupId:         csvlk.GroupId,
			MinKeyId:        csvlk.MinKeyId,
			MaxKeyId:        csvlk.MaxKeyId,
			InvalidWinBuild: csvlk.InvalidWinBuild,
		}
		for _, act := range csvlk.Activates {
			item.Activates = append(item.Activates, act.KmsItem)
		}
		db.CsvlkItems = append(db.CsvlkItems, item)
	}

	for _, app := range root.AppItems {
		appItem := AppItem{
			Id:          app.Id,
			DisplayName: app.DisplayName,
		}
		for _, ki := range app.KmsItems {
			kmsItem := KmsItem{
				Id:                 ki.Id,
				DisplayName:        ki.DisplayName,
				NCountPolicy:       ki.NCountPolicy,
				DefaultKmsProtocol: ki.DefaultKmsProtocol,
			}
			for _, si := range ki.SkuItems {
				kmsItem.SkuItems = append(kmsItem.SkuItems, SkuItem{
					Id:          si.Id,
					DisplayName: si.DisplayName,
				})
			}
			appItem.KmsItems = append(appItem.KmsItems, kmsItem)
		}
		db.AppItems = append(db.AppItems, appItem)
	}

	return db, nil
}

// GenerateEPID generates an ePID string.
func GenerateEPID(kmsId UUID, version uint16, lcid int) string {
	db, err := LoadKmsDB()
	if err != nil {
		// Fallback to Windows Server 2019 parameters.
		return generateFallbackEPID(lcid)
	}

	kmsIdStr := kmsId.String()

	// Find matching CSVLK.
	var groupId, minKeyId, maxKeyId, invalidBuild string
	found := false
	for _, csvlk := range db.CsvlkItems {
		for _, act := range csvlk.Activates {
			if strings.EqualFold(act, kmsIdStr) {
				groupId = csvlk.GroupId
				minKeyId = csvlk.MinKeyId
				maxKeyId = csvlk.MaxKeyId
				invalidBuild = csvlk.InvalidWinBuild
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		groupId = "206"
		minKeyId = "551000000"
		maxKeyId = "570999999"
		invalidBuild = "[0,1,2]"
	}

	gid, _ := strconv.Atoi(groupId)
	minKey, _ := strconv.Atoi(minKeyId)
	maxKey, _ := strconv.Atoi(maxKeyId)

	// Parse invalid builds.
	invalidBuilds := parseInvalidBuilds(invalidBuild)

	// Find valid host build.
	buildNumber := "17763"
	platformId := "3612"
	minDate := "02/10/2018"

	for _, wb := range db.WinBuilds {
		idx, _ := strconv.Atoi(wb.WinBuildIndex)
		isInvalid := false
		for _, inv := range invalidBuilds {
			if idx == inv {
				isInvalid = true
				break
			}
		}
		if !isInvalid {
			buildNumber = wb.BuildNumber
			platformId = wb.PlatformId
			minDate = wb.MinDate
			break
		}
	}

	// Generate product key ID.
	productKeyID := minKey + rand.Intn(maxKey-minKey+1)

	// License channel (always Volume).
	licenseChannel := 3

	// Parse min date.
	d, err := time.Parse("02/01/2006", minDate)
	if err != nil {
		d = time.Date(2018, 10, 2, 0, 0, 0, 0, time.UTC)
	}

	// Random date between min and now.
	now := time.Now()
	diff := now.Unix() - d.Unix()
	if diff <= 0 {
		diff = 1
	}
	randomDate := time.Unix(d.Unix()+rand.Int63n(diff), 0)
	firstOfYear := time.Date(randomDate.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	dayNumber := int(randomDate.Sub(firstOfYear).Hours()/24 + 0.5)

	return fmt.Sprintf("%05s-%05d-%03d-%06d-%02d-%d-%s.0000-%03d%04d",
		platformId,
		gid,
		productKeyID/1000000,
		productKeyID%1000000,
		licenseChannel,
		lcid,
		padLeft(buildNumber, 4, "0"),
		dayNumber,
		randomDate.Year())
}

func generateFallbackEPID(lcid int) string {
	productKeyID := 551000000 + rand.Intn(19999999)
	now := time.Now()
	firstOfYear := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	dayNumber := int(now.Sub(firstOfYear).Hours()/24 + 0.5)

	return fmt.Sprintf("03612-00206-%03d-%06d-03-%d-17763.0000-%03d%04d",
		productKeyID/1000000,
		productKeyID%1000000,
		lcid,
		dayNumber,
		now.Year())
}

func parseInvalidBuilds(s string) []int {
	s = strings.Trim(s, "[]")
	parts := strings.Split(s, ",")
	var result []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if v, err := strconv.Atoi(p); err == nil {
			result = append(result, v)
		}
	}
	return result
}

func padLeft(s string, length int, pad string) string {
	for len(s) < length {
		s = pad + s
	}
	return s
}

// HandleUnknownRequest returns an error response for unhandled versions.
func HandleUnknownRequest() ([]byte, error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0xC004F042)) // SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH
	return buf.Bytes(), nil
}
