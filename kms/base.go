package kms

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/xmdhs/go-kms/logger"
)

// UUID represents a 16-byte UUID in KMS wire format (bytes_le).
type UUID [16]byte

const hextable = "0123456789abcdef"

func (u UUID) String() string {
	// Layout: 8-4-4-4-12 hex chars + 4 dashes = 36 bytes
	var buf [36]byte

	// Group 1: bytes 0-3, little-endian uint32 → 8 hex chars
	v32 := binary.LittleEndian.Uint32(u[0:4])
	for i := 7; i >= 0; i-- {
		buf[i] = hextable[v32&0xf]
		v32 >>= 4
	}
	buf[8] = '-'

	// Group 2: bytes 4-5, little-endian uint16 → 4 hex chars
	v16 := binary.LittleEndian.Uint16(u[4:6])
	for i := 12; i >= 9; i-- {
		buf[i] = hextable[v16&0xf]
		v16 >>= 4
	}
	buf[13] = '-'

	// Group 3: bytes 6-7, little-endian uint16 → 4 hex chars
	v16 = binary.LittleEndian.Uint16(u[6:8])
	for i := 17; i >= 14; i-- {
		buf[i] = hextable[v16&0xf]
		v16 >>= 4
	}
	buf[18] = '-'

	// Group 4: bytes 8-9, big-endian → 4 hex chars
	for i, b := range u[8:10] {
		buf[19+i*2] = hextable[b>>4]
		buf[20+i*2] = hextable[b&0xf]
	}
	buf[23] = '-'

	// Group 5: bytes 10-15, big-endian → 12 hex chars
	for i, b := range u[10:16] {
		buf[24+i*2] = hextable[b>>4]
		buf[25+i*2] = hextable[b&0xf]
	}

	return string(buf[:])
}

// hexVal returns the nibble value of a hex character, or 255 on error.
func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

func UUIDFromString(s string) (UUID, error) {
	// Accept both "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" (32) and
	// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (36).
	if len(s) != 36 && len(s) != 32 {
		return UUID{}, fmt.Errorf("invalid UUID string length: %d", len(s))
	}

	// Decode directly into a [16]byte without allocations.
	var b [16]byte
	j := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c == '-' {
			i++
			continue
		}
		if i+1 >= len(s) {
			return UUID{}, fmt.Errorf("invalid UUID string")
		}
		hi := hexVal(c)
		lo := hexVal(s[i+1])
		if hi == 255 || lo == 255 {
			return UUID{}, fmt.Errorf("invalid hex character in UUID")
		}
		b[j] = hi<<4 | lo
		j++
		i += 2
	}
	if j != 16 {
		return UUID{}, fmt.Errorf("invalid UUID string")
	}

	var u UUID
	// bytes_le: first three groups are stored little-endian.
	u[0], u[1], u[2], u[3] = b[3], b[2], b[1], b[0]
	u[4], u[5] = b[5], b[4]
	u[6], u[7] = b[7], b[6]
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

type MachineName struct {
	MachineNameRaw []byte
}

func (r MachineName) String() string {
	raw := r.MachineNameRaw
	for i := 0; i < len(raw)-1; i += 2 {
		if raw[i] == 0 && raw[i+1] == 0 {
			raw = raw[:i]
			break
		}
	}
	// Decode UTF-16LE.
	u16s := make([]uint16, len(raw)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u16s))
}

func ParseKMSRequest(data []byte) (*KMSRequest, error) {
	const fixedSize = 108 // 2+2+4+4+4+16+16+16+16+4+8+16
	if len(data) < fixedSize {
		return nil, fmt.Errorf("KMS request data too short: %d", len(data))
	}

	offset := 0
	r := &KMSRequest{}
	r.VersionMinor = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	r.VersionMajor = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	r.IsClientVM = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	r.LicenseStatus = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	r.GraceTime = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	copy(r.ApplicationID[:], data[offset:offset+16])
	offset += 16
	copy(r.SKUID[:], data[offset:offset+16])
	offset += 16
	copy(r.KMSCountedID[:], data[offset:offset+16])
	offset += 16
	copy(r.ClientMachineID[:], data[offset:offset+16])
	offset += 16
	r.RequiredClientCount = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	r.RequestTime = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	copy(r.PreviousClientMachineID[:], data[offset:offset+16])
	offset += 16

	if len(data) > offset {
		r.MachineNameRaw = make([]byte, len(data)-offset)
		copy(r.MachineNameRaw, data[offset:])
	}

	return r, nil
}

func (r *KMSRequest) Marshal() []byte {
	const fixedSize = 108 // 2+2+4+4+4+16+16+16+16+4+8+16
	resp := make([]byte, fixedSize+len(r.MachineNameRaw))
	offset := 0
	binary.LittleEndian.PutUint16(resp[offset:offset+2], r.VersionMinor)
	offset += 2
	binary.LittleEndian.PutUint16(resp[offset:offset+2], r.VersionMajor)
	offset += 2
	binary.LittleEndian.PutUint32(resp[offset:offset+4], r.IsClientVM)
	offset += 4
	binary.LittleEndian.PutUint32(resp[offset:offset+4], r.LicenseStatus)
	offset += 4
	binary.LittleEndian.PutUint32(resp[offset:offset+4], r.GraceTime)
	offset += 4
	copy(resp[offset:offset+16], r.ApplicationID[:])
	offset += 16
	copy(resp[offset:offset+16], r.SKUID[:])
	offset += 16
	copy(resp[offset:offset+16], r.KMSCountedID[:])
	offset += 16
	copy(resp[offset:offset+16], r.ClientMachineID[:])
	offset += 16
	binary.LittleEndian.PutUint32(resp[offset:offset+4], r.RequiredClientCount)
	offset += 4
	binary.LittleEndian.PutUint64(resp[offset:offset+8], r.RequestTime)
	offset += 8
	copy(resp[offset:offset+16], r.PreviousClientMachineID[:])
	offset += 16
	copy(resp[offset:], r.MachineNameRaw)
	return resp
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
	epidLen := uint32(len(r.KMSEpid) + 2) // +2 for null terminator
	totalLen := 44 + int(epidLen)
	data := make([]byte, totalLen)

	offset := 0
	binary.LittleEndian.PutUint16(data[offset:offset+2], r.VersionMinor)
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:offset+2], r.VersionMajor)
	offset += 2
	binary.LittleEndian.PutUint32(data[offset:offset+4], epidLen)
	offset += 4

	copy(data[offset:offset+len(r.KMSEpid)], r.KMSEpid)
	offset += len(r.KMSEpid)
	data[offset] = 0
	data[offset+1] = 0 // UTF-16LE null terminator
	offset += 2

	copy(data[offset:offset+16], r.ClientMachineID[:])
	offset += 16
	binary.LittleEndian.PutUint64(data[offset:offset+8], r.ResponseTime)
	offset += 8
	binary.LittleEndian.PutUint32(data[offset:offset+4], r.CurrentClientCount)
	offset += 4
	binary.LittleEndian.PutUint32(data[offset:offset+4], r.VLActivationInterval)
	offset += 4
	binary.LittleEndian.PutUint32(data[offset:offset+4], r.VLRenewalInterval)

	return data
}

func ParseKMSResponse(data []byte) (*KMSResponse, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("KMS response data too short: %d", len(data))
	}

	offset := 0
	r := &KMSResponse{}
	r.VersionMinor = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	r.VersionMajor = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	r.EPIDLen = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	epidEnd := offset + int(r.EPIDLen)
	if epidEnd > len(data) {
		return nil, fmt.Errorf("KMS response EPID length mismatch")
	}
	r.KMSEpid = make([]byte, r.EPIDLen)
	copy(r.KMSEpid, data[offset:epidEnd])
	offset = epidEnd

	const tailSize = 16 + 8 + 4 + 4 + 4
	if offset+tailSize > len(data) {
		return nil, fmt.Errorf("KMS response data too short for fixed fields")
	}

	copy(r.ClientMachineID[:], data[offset:offset+16])
	offset += 16
	r.ResponseTime = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	r.CurrentClientCount = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	r.VLActivationInterval = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	r.VLRenewalInterval = binary.LittleEndian.Uint32(data[offset : offset+4])

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
	if len(data) < 12 {
		return nil, fmt.Errorf("generic request header too short: %d", len(data))
	}
	offset := 0
	h := &GenericRequestHeader{}
	h.BodyLength1 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	h.BodyLength2 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	h.VersionMinor = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	h.VersionMajor = binary.LittleEndian.Uint16(data[offset : offset+2])
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
	Logger      *slog.Logger
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
		LogLevel:   "DEBUG",
	}
}

// GetPadding calculates the padding needed after a body.
func GetPadding(bodyLength int) int {
	return 4 + (((^bodyLength & 3) + 1) & 3)
}

// ServerLogic processes a KMS request and generates a response.
func ServerLogic(ctx context.Context, kmsRequest *KMSRequest, config *ServerConfig) *KMSResponse {
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
	var epid string
	if config.EPID == "" {
		epid = GenerateEPID(kmsRequest.KMSCountedID, kmsRequest.VersionMajor, config.LCID)
	} else {
		epid = config.EPID
	}

	logger.LogAttrs(ctx, slog.LevelDebug, "Response",
		slog.Any("Machine Name", MachineName{kmsRequest.MachineNameRaw}),
		slog.Any("Client Machine ID", kmsRequest.ClientMachineID),
		slog.Any("Application ID", kmsRequest.ApplicationID),
		slog.Any("SKU ID", kmsRequest.SKUID),
		slog.Any("KMS Counted ID", kmsRequest.KMSCountedID),
		slog.String("License Status", LicenseStates[kmsRequest.LicenseStatus]),
		slog.Time("Request Time", FileTimeToTime(int64(kmsRequest.RequestTime))),
		slog.String("Server ePID", epid),
	)

	response := &KMSResponse{
		VersionMinor:         kmsRequest.VersionMinor,
		VersionMajor:         kmsRequest.VersionMajor,
		KMSEpid:              EncodeUTF16LE(epid),
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
func GenerateKMSResponseData(ctx context.Context, data []byte, config *ServerConfig) ([]byte, error) {
	header, err := ParseGenericRequestHeader(data)
	if err != nil {
		return nil, err
	}

	version := header.VersionMajor
	logger.LogAttrs(ctx, slog.LevelDebug, "Received request", slog.Uint64("version", uint64(version)))

	switch version {
	case 4:
		return HandleV4Request(ctx, data, config)
	case 5:
		return HandleV5Request(ctx, data, config)
	case 6:
		return HandleV6Request(ctx, data, config)
	default:
		logger.LogAttrs(ctx, slog.LevelWarn, "Unhandled KMS version", slog.Uint64("version", uint64(version)))
		return HandleUnknownRequest()
	}
}

// --- KMS Database XML Parsing ---

type KmsDataBase struct {
	WinBuilds  []WinBuild
	CsvlkItems []CsvlkItem
	AppItems   []AppItem
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
	XMLName    xml.Name      `xml:"KmsData"`
	WinBuilds  []xmlWinBuild `xml:"WinBuild"`
	CsvlkItems []xmlCsvlk    `xml:"CsvlkItem"`
	AppItems   []xmlApp      `xml:"AppItem"`
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

//go:embed KmsDataBase.xml
var kmsDataBaseFile []byte

var kmsDB = sync.OnceValues(LoadKmsDB)

func LoadKmsDB() (*KmsDataBase, error) {
	data := kmsDataBaseFile

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
	db, err := kmsDB()
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
		isInvalid := slices.Contains(invalidBuilds, idx)
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
	resp := make([]byte, 12)
	binary.LittleEndian.PutUint32(resp[0:4], 0)
	binary.LittleEndian.PutUint32(resp[4:8], 0)
	binary.LittleEndian.PutUint32(resp[8:12], 0xC004F042) // SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH
	return resp, nil
}
