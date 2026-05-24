package patch

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"pestr/internal/pe"
)

type Entry struct {
	Text   string `json:"text"`
	Offset string `json:"offset"`
}

const (
	imageSCN_CNTInitializedData = 0x00000040
	imageSCNMemRead             = 0x40000000
)

func Run(exePath, jsonPath, outPath string) error {
	if exePath == "" {
		return errors.New("missing exe file path")
	}
	if outPath == "" {
		return errors.New("missing output file path")
	}

	exeData, err := os.ReadFile(exePath)
	if err != nil {
		return err
	}

	entries, err := readEntries(jsonPath)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("json array is empty")
	}

	pf, err := pe.Parse(exeData)
	if err != nil {
		return err
	}

	for _, s := range pf.Sections {
		if s.Name == ".pestr" {
			return errors.New("file already contains .pestr section; use original exe file")
		}
	}
	if len(pf.Sections) == 0 {
		return errors.New("pe has no sections")
	}

	coffOff := int(pf.DOS.ELfanew) + 4
	optOff := coffOff + 20
	secTableOff := optOff + int(pf.Coff.SizeOfOptionalHeader)
	secTableEnd := secTableOff + int(pf.Coff.NumberOfSections)*40
	if secTableEnd+40 > int(pf.SizeOfHeaders) {
		return errors.New("no free space in PE headers for one more section")
	}

	patchOffsets := make([]int, len(entries))
	for i, e := range entries {
		if strings.TrimSpace(e.Text) == "" {
			return fmt.Errorf("entry %d: field text is required", i)
		}
		off, err := parseOffset(e.Offset)
		if err != nil {
			return fmt.Errorf("entry %d: invalid offset: %w", i, err)
		}
		if off < 0 || off >= len(exeData) {
			return fmt.Errorf("entry %d: offset out of range: 0x%x", i, off)
		}
		sec := pf.SectionForRawOffset(off)
		if sec == nil || sec.Name != ".text" {
			return fmt.Errorf("entry %d: offset 0x%x is not inside .text section", i, off)
		}
		patchOffsets[i] = off
	}

	payloadOffsets := make([]uint32, len(entries))
	payloadLen := 0
	for i, e := range entries {
		payloadOffsets[i] = uint32(payloadLen)
		payloadLen += len([]byte(e.Text)) + 1
	}

	last := pf.Sections[len(pf.Sections)-1]
	nextVA := alignUp(last.VirtualAddress+max(last.VirtualSize, last.SizeOfRawData), pf.SectionAlignment)
	nextRaw := alignUp(uint32(len(exeData)), pf.FileAlignment)
	newRawSize := alignUp(uint32(payloadLen), pf.FileAlignment)
	newSizeOfImage := alignUp(nextVA+uint32(payloadLen), pf.SectionAlignment)

	out := make([]byte, len(exeData))
	copy(out, exeData)

	if uint32(len(out)) < nextRaw {
		pad := make([]byte, int(nextRaw)-len(out))
		out = append(out, pad...)
	}
	sectionData := make([]byte, newRawSize)
	pos := 0
	for _, e := range entries {
		b := []byte(e.Text)
		copy(sectionData[pos:], b)
		pos += len(b)
		sectionData[pos] = 0
		pos++
	}
	out = append(out, sectionData...)

	newSecHeaderOff := secTableEnd
	writeSectionHeader(out, newSecHeaderOff, sectionHeader{
		Name:             ".pestr",
		VirtualSize:      uint32(payloadLen),
		VirtualAddress:   nextVA,
		SizeOfRawData:    newRawSize,
		PointerToRawData: nextRaw,
		Characteristics:  imageSCN_CNTInitializedData | imageSCNMemRead,
	})

	binary.LittleEndian.PutUint16(out[coffOff+2:coffOff+4], pf.Coff.NumberOfSections+1)

	switch pf.Bitness {
	case 32, 64:
		binary.LittleEndian.PutUint32(out[optOff+56:optOff+60], newSizeOfImage)
	default:
		return fmt.Errorf("unsupported bitness: %d", pf.Bitness)
	}

	ptrSize := 4
	if pf.Bitness == 64 {
		ptrSize = 8
	}

	for i, off := range patchOffsets {
		newVA := pf.ImageBase + uint64(nextVA) + uint64(payloadOffsets[i])
		if ptrSize == 4 {
			if newVA > math.MaxUint32 {
				return fmt.Errorf("entry %d: target VA does not fit uint32", i)
			}
			if off+4 > len(out) {
				return fmt.Errorf("entry %d: patch offset out of range for 4-byte pointer", i)
			}
			binary.LittleEndian.PutUint32(out[off:off+4], uint32(newVA))
		} else {
			if off+8 > len(out) {
				return fmt.Errorf("entry %d: patch offset out of range for 8-byte pointer", i)
			}
			binary.LittleEndian.PutUint64(out[off:off+8], newVA)
		}
	}

	return os.WriteFile(outPath, out, 0o644)
}

func readEntries(jsonPath string) ([]Entry, error) {
	var payload []byte
	var err error
	if jsonPath != "" {
		payload, err = os.ReadFile(jsonPath)
		if err != nil {
			return nil, err
		}
	} else {
		payload, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
	}

	var entries []Entry
	if err := json.Unmarshal(payload, &entries); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	for i, e := range entries {
		if strings.TrimSpace(e.Text) == "" {
			return nil, fmt.Errorf("entry %d: missing text", i)
		}
		if strings.TrimSpace(e.Offset) == "" {
			return nil, fmt.Errorf("entry %d: missing offset", i)
		}
	}
	return entries, nil
}

func parseOffset(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasPrefix(s, "0x") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, err
		}
		return int(v), nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

func alignUp(v, a uint32) uint32 {
	if a == 0 {
		return v
	}
	r := v % a
	if r == 0 {
		return v
	}
	return v + (a - r)
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

type sectionHeader struct {
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
}

func writeSectionHeader(data []byte, off int, h sectionHeader) {
	name := make([]byte, 8)
	copy(name, []byte(h.Name))
	copy(data[off:off+8], name)
	binary.LittleEndian.PutUint32(data[off+8:off+12], h.VirtualSize)
	binary.LittleEndian.PutUint32(data[off+12:off+16], h.VirtualAddress)
	binary.LittleEndian.PutUint32(data[off+16:off+20], h.SizeOfRawData)
	binary.LittleEndian.PutUint32(data[off+20:off+24], h.PointerToRawData)
	binary.LittleEndian.PutUint32(data[off+24:off+28], 0)
	binary.LittleEndian.PutUint32(data[off+28:off+32], 0)
	binary.LittleEndian.PutUint16(data[off+32:off+34], 0)
	binary.LittleEndian.PutUint16(data[off+34:off+36], 0)
	binary.LittleEndian.PutUint32(data[off+36:off+40], h.Characteristics)
}
