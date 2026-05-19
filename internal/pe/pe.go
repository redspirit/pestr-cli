package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type File struct {
	Data             []byte
	DOS              DOSHeader
	Coff             CoffHeader
	Optional         OptionalHeader
	Sections         []Section
	Bitness          int // 32 or 64
	ImageBase        uint64
	SectionAlignment uint32
	FileAlignment    uint32
	SizeOfImage      uint32
	SizeOfHeaders    uint32
}

type DOSHeader struct {
	EMagic  uint16
	ELfanew uint32
}

type CoffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type OptionalHeader struct {
	Magic               uint16
	AddressOfEntryPoint uint32
}

type Section struct {
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
}

const (
	imageDOSSignature = 0x5A4D     // MZ
	imagePESignature  = 0x00004550 // PE\0\0 little-endian uint32 value

	pe32Magic = 0x10b
	pe64Magic = 0x20b

	imageSCNMemExecute = 0x20000000
)

func Parse(data []byte) (*File, error) {
	if len(data) < 0x40 {
		return nil, errors.New("file too small to be a PE image")
	}

	if binary.LittleEndian.Uint16(data[0:2]) != imageDOSSignature {
		return nil, errors.New("missing MZ signature")
	}

	eLfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(eLfanew)+4+20 > len(data) {
		return nil, errors.New("invalid e_lfanew")
	}

	if binary.LittleEndian.Uint32(data[eLfanew:eLfanew+4]) != imagePESignature {
		return nil, errors.New("missing PE signature")
	}

	coffOff := int(eLfanew) + 4
	coff := CoffHeader{
		Machine:              binary.LittleEndian.Uint16(data[coffOff : coffOff+2]),
		NumberOfSections:     binary.LittleEndian.Uint16(data[coffOff+2 : coffOff+4]),
		TimeDateStamp:        binary.LittleEndian.Uint32(data[coffOff+4 : coffOff+8]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(data[coffOff+8 : coffOff+12]),
		NumberOfSymbols:      binary.LittleEndian.Uint32(data[coffOff+12 : coffOff+16]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(data[coffOff+16 : coffOff+18]),
		Characteristics:      binary.LittleEndian.Uint16(data[coffOff+18 : coffOff+20]),
	}

	optOff := coffOff + 20
	optEnd := optOff + int(coff.SizeOfOptionalHeader)
	if optEnd > len(data) {
		return nil, errors.New("optional header exceeds file size")
	}
	if coff.SizeOfOptionalHeader < 2 {
		return nil, errors.New("optional header too small")
	}

	magic := binary.LittleEndian.Uint16(data[optOff : optOff+2])
	f := &File{Data: data, Coff: coff, DOS: DOSHeader{EMagic: imageDOSSignature, ELfanew: eLfanew}}

	switch magic {
	case pe32Magic:
		if optOff+96 > optEnd {
			return nil, errors.New("PE32 optional header truncated")
		}
		f.Bitness = 32
		f.Optional = OptionalHeader{
			Magic:               magic,
			AddressOfEntryPoint: binary.LittleEndian.Uint32(data[optOff+16 : optOff+20]),
		}
		f.ImageBase = uint64(binary.LittleEndian.Uint32(data[optOff+28 : optOff+32]))
		f.SectionAlignment = binary.LittleEndian.Uint32(data[optOff+32 : optOff+36])
		f.FileAlignment = binary.LittleEndian.Uint32(data[optOff+36 : optOff+40])
		f.SizeOfImage = binary.LittleEndian.Uint32(data[optOff+56 : optOff+60])
		f.SizeOfHeaders = binary.LittleEndian.Uint32(data[optOff+60 : optOff+64])
	case pe64Magic:
		if optOff+112 > optEnd {
			return nil, errors.New("PE32+ optional header truncated")
		}
		f.Bitness = 64
		f.Optional = OptionalHeader{
			Magic:               magic,
			AddressOfEntryPoint: binary.LittleEndian.Uint32(data[optOff+16 : optOff+20]),
		}
		f.ImageBase = binary.LittleEndian.Uint64(data[optOff+24 : optOff+32])
		f.SectionAlignment = binary.LittleEndian.Uint32(data[optOff+32 : optOff+36])
		f.FileAlignment = binary.LittleEndian.Uint32(data[optOff+36 : optOff+40])
		f.SizeOfImage = binary.LittleEndian.Uint32(data[optOff+56 : optOff+60])
		f.SizeOfHeaders = binary.LittleEndian.Uint32(data[optOff+60 : optOff+64])
	default:
		return nil, fmt.Errorf("unsupported optional header magic 0x%x", magic)
	}

	secOff := optOff + int(coff.SizeOfOptionalHeader)
	need := secOff + int(coff.NumberOfSections)*40
	if need > len(data) {
		return nil, errors.New("section table exceeds file size")
	}

	sections := make([]Section, 0, coff.NumberOfSections)
	for i := 0; i < int(coff.NumberOfSections); i++ {
		off := secOff + i*40
		nameBytes := data[off : off+8]
		name := string(bytes.TrimRight(nameBytes, "\x00"))
		sec := Section{
			Name:             name,
			VirtualSize:      binary.LittleEndian.Uint32(data[off+8 : off+12]),
			VirtualAddress:   binary.LittleEndian.Uint32(data[off+12 : off+16]),
			SizeOfRawData:    binary.LittleEndian.Uint32(data[off+16 : off+20]),
			PointerToRawData: binary.LittleEndian.Uint32(data[off+20 : off+24]),
			Characteristics:  binary.LittleEndian.Uint32(data[off+36 : off+40]),
		}
		sections = append(sections, sec)
	}
	f.Sections = sections
	return f, nil
}

func (f *File) SectionForRawOffset(offset int) *Section {
	for i := range f.Sections {
		s := &f.Sections[i]
		start := int(s.PointerToRawData)
		end := start + int(s.SizeOfRawData)
		if offset >= start && offset < end {
			return s
		}
	}
	return nil
}

func (f *File) RawToVA(offset int) (uint64, bool) {
	sec := f.SectionForRawOffset(offset)
	if sec == nil {
		return 0, false
	}
	delta := uint64(offset - int(sec.PointerToRawData))
	return f.ImageBase + uint64(sec.VirtualAddress) + delta, true
}

func (f *File) RawToRVA(offset int) (uint64, bool) {
	sec := f.SectionForRawOffset(offset)
	if sec == nil {
		return 0, false
	}
	delta := uint64(offset - int(sec.PointerToRawData))
	return uint64(sec.VirtualAddress) + delta, true
}

func (f *File) IsExecutableSection(sec Section) bool {
	return sec.Characteristics&imageSCNMemExecute != 0
}
