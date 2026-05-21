package extract

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	"pestr/internal/pe"
)

var (
	// The user-provided pattern, translated into Go regex syntax.
	// It is intentionally permissive for ordinary text content.
	stringPattern = regexp.MustCompile(`(?im)^[\n 0-9a-zа-яё§!@#$%^&*()_:;+=><,.\\\[\]?` + "`" + `'~|/-]+$`)
)

type Item struct {
	Text        string `json:"text"`
	Offset      string `json:"offset"` // file offset of the pointer bytes
	Xref        string `json:"xref"`   // virtual address of the string
	Section     string `json:"section"`
	BytesBefore string `json:"bytes_before"`
	BytesAfter  string `json:"bytes_after"`
}

type Output struct {
	Strings []Item `json:"strings"`
}

type candidate struct {
	Text    string
	Off     int
	VA      uint64
	Section string
}

func Extract(data []byte) ([]byte, error) {
	pf, err := pe.Parse(data)
	if err != nil {
		return nil, err
	}

	candidates := findStringCandidates(pf)
	if len(candidates) == 0 {
		out, _ := json.MarshalIndent(Output{Strings: []Item{}}, "", "  ")
		return out, nil
	}

	items := findXrefs(pf, candidates)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Offset == items[j].Offset {
			return items[i].Xref < items[j].Xref
		}
		return items[i].Offset < items[j].Offset
	})

	out, err := json.MarshalIndent(Output{Strings: items}, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
}

func findStringCandidates(pf *pe.File) []candidate {
	seen := map[string]struct{}{}
	var res []candidate

	for _, sec := range pf.Sections {
		if sec.SizeOfRawData == 0 || sec.PointerToRawData == 0 {
			continue
		}
		start := int(sec.PointerToRawData)
		end := start + int(sec.SizeOfRawData)
		if start < 0 || end > len(pf.Data) || start >= end {
			continue
		}
		raw := pf.Data[start:end]

		// ASCII / UTF-8-ish zero-terminated strings.
		scanASCIIStrings := func() {
			i := 0
			for i < len(raw) {
				if raw[i] == 0 {
					i++
					continue
				}
				j := i
				for j < len(raw) && raw[j] != 0 {
					j++
				}
				if j-i >= 3 {
					bs := raw[i:j]
					if isLikelyText(bs) {
						text := string(bs)
						if isValidText(text) {
							if va, ok := pf.RawToVA(start + i); ok {
								key := fmt.Sprintf("%d|%s", start+i, text)
								if _, exists := seen[key]; !exists {
									seen[key] = struct{}{}
									res = append(res, candidate{Text: text, Off: start + i, VA: va, Section: sec.Name})
								}
							}
						}
					}
				}
				i = j + 1
			}
		}

		// UTF-16LE zero-terminated strings.
		scanUTF16Strings := func() {
			i := 0
			for i+1 < len(raw) {
				if raw[i] == 0 && raw[i+1] == 0 {
					i += 2
					continue
				}
				j := i
				var units []uint16
				valid := true
				for j+1 < len(raw) {
					lo := raw[j]
					hi := raw[j+1]
					if lo == 0 && hi == 0 {
						break
					}
					// accept common printable ASCII/Latin letters + spaces, but also any non-zero low byte
					// because the final regex will filter the decoded text.
					units = append(units, binary.LittleEndian.Uint16(raw[j:j+2]))
					j += 2
					if len(units) > 2048 {
						valid = false
						break
					}
				}
				if valid && len(units) >= 3 && j+1 < len(raw) && raw[j] == 0 && raw[j+1] == 0 {
					text := string(utf16.Decode(units))
					if isValidText(text) {
						if va, ok := pf.RawToVA(start + i); ok {
							key := fmt.Sprintf("%d|%s", start+i, text)
							if _, exists := seen[key]; !exists {
								seen[key] = struct{}{}
								res = append(res, candidate{Text: text, Off: start + i, VA: va, Section: sec.Name})
							}
						}
					}
				}
				i = j + 2
			}
		}

		scanASCIIStrings()
		scanUTF16Strings()
	}

	return res
}

func isLikelyText(bs []byte) bool {
	printable := 0
	for _, b := range bs {
		switch {
		case b == '\n', b == '\r', b == '\t', b == ' ':
			printable++
		case b >= 0x20 && b <= 0x7E:
			printable++
		case b >= 0x80:
			// allow high bytes; final regex will reject weird content
			printable++
		default:
			return false
		}
	}
	return printable == len(bs)
}

func isValidText(s string) bool {
	if len(s) < 3 {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	return stringPattern.MatchString(s)
}

func findXrefs(pf *pe.File, candidates []candidate) []Item {
	candByVA := make(map[uint64][]candidate, len(candidates))
	for _, c := range candidates {
		candByVA[c.VA] = append(candByVA[c.VA], c)
	}

	seen := map[string]struct{}{}
	var items []Item

	for _, sec := range pf.Sections {
		if !pf.IsExecutableSection(sec) {
			continue
		}
		if sec.SizeOfRawData == 0 || sec.PointerToRawData == 0 {
			continue
		}
		start := int(sec.PointerToRawData)
		end := start + int(sec.SizeOfRawData)
		if start < 0 || end > len(pf.Data) || start >= end {
			continue
		}
		raw := pf.Data[start:end]

		for i := 0; i < len(raw); i++ {
			// x86: push imm32 / mov reg, imm32
			if pf.Bitness == 32 {
				if raw[i] == 0x68 && i+5 <= len(raw) {
					target := uint64(binary.LittleEndian.Uint32(raw[i+1 : i+5]))
					items = appendIfKnown(items, seen, candByVA, pf, raw, start, i, i+1, 4, target)
				}
				if raw[i] >= 0xB8 && raw[i] <= 0xBF && i+5 <= len(raw) {
					target := uint64(binary.LittleEndian.Uint32(raw[i+1 : i+5]))
					items = appendIfKnown(items, seen, candByVA, pf, raw, start, i, i+1, 4, target)
				}
				continue
			}

			// x64: mov reg, imm64
			if isRexW(raw[i]) && i+10 <= len(raw) && raw[i+1] >= 0xB8 && raw[i+1] <= 0xBF {
				target := binary.LittleEndian.Uint64(raw[i+2 : i+10])
				items = appendIfKnown(items, seen, candByVA, pf, raw, start, i, i+2, 8, target)
			}

			// x64: lea reg, [rip+disp32]
			if isRexW(raw[i]) && i+7 <= len(raw) && raw[i+1] == 0x8D && isRipRelativeModRM(raw[i+2]) {
				disp := int32(binary.LittleEndian.Uint32(raw[i+3 : i+7]))
				insnEnd := uint64(start + i + 7)
				target := uint64(int64(insnEnd) + int64(disp))
				items = appendIfKnown(items, seen, candByVA, pf, raw, start, i, i+3, 4, target)
			}
		}
	}

	return items
}

func appendIfKnown(items []Item, seen map[string]struct{}, candByVA map[uint64][]candidate, pf *pe.File, raw []byte, sectionStart, insnStart, ptrStart, ptrSize int, target uint64) []Item {
	cands := candByVA[target]
	if len(cands) == 0 {
		return items
	}
	absPtr := sectionStart + ptrStart
	if absPtr < 3 || absPtr+ptrSize+3 > len(pf.Data) {
		return items
	}
	for _, c := range cands {
		key := fmt.Sprintf("%d|%d|%s", absPtr, target, c.Text)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, Item{
			Text:        c.Text,
			Offset:      hex64(uint64(absPtr)),
			Xref:        hex64(target),
			Section:     c.Section,
			BytesBefore: hexBytes(pf.Data[absPtr-3 : absPtr]),
			BytesAfter:  hexBytes(pf.Data[absPtr+ptrSize : absPtr+ptrSize+3]),
		})
	}
	return items
}

func isRexW(b byte) bool {
	return b == 0x48 || b == 0x49 || b == 0x4C || b == 0x4D
}

func isRipRelativeModRM(b byte) bool {
	// mod = 00, r/m = 101. reg field may vary.
	return b&0xC7 == 0x05
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hex64(v uint64) string {
	return fmt.Sprintf("0x%x", v)
}

func hexBytes(bs []byte) string {
	out := make([]byte, len(bs)*2)
	for i, b := range bs {
		out[i*2] = hexChar(b >> 4)
		out[i*2+1] = hexChar(b & 0x0F)
	}
	return string(out)
}

func hexChar(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}

func Run(path string) ([]byte, error) {
	return nil, errors.New("use Extract with file contents")
}
