package tracer

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// Go TLS symbols hooked by uprobes.
const (
	goTLSReadFunc  = "crypto/tls.(*Conn).Read"
	goTLSWriteFunc = "crypto/tls.(*Conn).writeRecordLocked"
)

var (
	errNotGoBinary     = errors.New("not a Go executable")
	errUnsupportedArch = errors.New("unsupported architecture for GoTLS offsets")
	errNoGoTLSFuncs    = errors.New("crypto/tls hooks not found in Go binary")
)

// GoTLSOffsets holds uprobe attachment offsets in the ELF file.
type GoTLSOffsets struct {
	WriteOffset uint64
	ReadEntry   uint64
	ReadReturns []uint64
	GoVersion   string
	IsPIE       bool
	RegisterABI bool
}

// ResolveGoTLSOffsets locates writeRecordLocked and Read RET offsets in a Go ELF binary.
func ResolveGoTLSOffsets(path string) (*GoTLSOffsets, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNotGoBinary, err)
	}

	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := validateGoELFArch(f); err != nil {
		return nil, err
	}

	isPIE := f.Type == elf.ET_DYN
	for _, s := range bi.Settings {
		if s.Key == "-buildmode" && s.Value == "pie" {
			isPIE = true
			break
		}
	}

	result := &GoTLSOffsets{
		GoVersion:   bi.GoVersion,
		IsPIE:       isPIE,
		RegisterABI: goVersionAtLeast(bi.GoVersion, "go1.17"),
	}

	symTab, err := readGoSymbolTable(f, bi.GoVersion)
	if err != nil {
		return nil, err
	}

	result.WriteOffset, err = goFuncFileOffset(f, symTab, goTLSWriteFunc)
	if err != nil {
		return nil, err
	}
	result.ReadEntry, err = goFuncFileOffset(f, symTab, goTLSReadFunc)
	if err != nil {
		return nil, err
	}
	result.ReadReturns, err = goFuncReadRetOffsets(f, symTab, goTLSReadFunc)
	if err != nil {
		return nil, err
	}

	if result.WriteOffset == 0 || result.ReadEntry == 0 {
		return nil, errNoGoTLSFuncs
	}
	return result, nil
}

func validateGoELFArch(f *elf.File) error {
	switch f.Machine {
	case elf.EM_X86_64:
		if runtime.GOARCH != "amd64" {
			return fmt.Errorf("%w: agent is %s, binary is amd64", errUnsupportedArch, runtime.GOARCH)
		}
	case elf.EM_AARCH64:
		if runtime.GOARCH != "arm64" {
			return fmt.Errorf("%w: agent is %s, binary is arm64", errUnsupportedArch, runtime.GOARCH)
		}
	default:
		return fmt.Errorf("%w: %v", errUnsupportedArch, f.Machine)
	}
	return nil
}

func goVersionAtLeast(version, min string) bool {
	return strings.Compare(version, min) >= 0
}

func readGoSymbolTable(f *elf.File, goVersion string) (*gosym.Table, error) {
	section := f.Section(".gopclntab")
	sectionLabel := ".gopclntab"
	if section == nil {
		sectionLabel = ".data.rel.ro.gopclntab"
		section = f.Section(sectionLabel)
	}
	if section == nil {
		sectionLabel = ".data.rel.ro"
		section = f.Section(sectionLabel)
	}
	if section == nil {
		return nil, fmt.Errorf("could not read gopclntab from ELF")
	}

	tableData, err := section.Data()
	if err != nil {
		return nil, err
	}

	magic := goPclntabMagic(goVersion)
	pclntabIndex := bytes.Index(tableData, magic)
	if pclntabIndex < 0 {
		return nil, fmt.Errorf("gopclntab magic not found")
	}
	tableData = tableData[pclntabIndex:]

	ptrSize := uint32(tableData[7])
	var textStart uint64
	if ptrSize == 4 {
		textStart = uint64(binary.LittleEndian.Uint32(tableData[8+2*ptrSize:]))
	} else {
		textStart = binary.LittleEndian.Uint64(tableData[8+2*ptrSize:])
	}

	lineTable := gosym.NewLineTable(tableData, textStart)
	return gosym.NewTable([]byte{}, lineTable)
}

func goPclntabMagic(goVersion string) []byte {
	bs := make([]byte, 4)
	var magic uint32
	switch {
	case goVersionAtLeast(goVersion, "go1.20"):
		magic = 0xfffffff1
	case goVersionAtLeast(goVersion, "go1.18"):
		magic = 0xfffffff0
	case goVersionAtLeast(goVersion, "go1.16"):
		magic = 0xfffffffa
	default:
		magic = 0xfffffffb
	}
	binary.LittleEndian.PutUint32(bs, magic)
	return bs
}

func symbolFileOffset(f *elf.File, symTab *gosym.Table, name string) (uint64, error) {
	fn := symTab.LookupFunc(name)
	if fn == nil {
		return 0, fmt.Errorf("function %q not found", name)
	}
	text := f.Section(".text")
	if text == nil {
		return 0, errors.New("`.text` section not found")
	}
	return fn.Entry - text.Addr + text.Offset, nil
}

func goFuncFileOffset(f *elf.File, symTab *gosym.Table, name string) (uint64, error) {
	fn := symTab.LookupFunc(name)
	if fn == nil {
		return 0, fmt.Errorf("function %q not found", name)
	}
	if off, err := vmaToFileOffset(f, fn.Entry); err == nil {
		return off, nil
	}
	return symbolFileOffset(f, symTab, name)
}

func goFuncReadRetOffsets(f *elf.File, symTab *gosym.Table, name string) ([]uint64, error) {
	fn := symTab.LookupFunc(name)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found", name)
	}

	base, err := vmaToFileOffset(f, fn.Entry)
	if err != nil {
		return symbolReadRetOffsets(f, symTab, name)
	}

	funcLen := fn.End - fn.Entry
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= fn.Entry && fn.Entry < prog.Vaddr+prog.Memsz {
			data := make([]byte, funcLen)
			if _, err := prog.ReadAt(data, int64(fn.Entry-prog.Vaddr)); err != nil {
				return nil, err
			}
			rel, err := retOffsetsInCode(data)
			if err != nil {
				return nil, err
			}
			out := make([]uint64, len(rel))
			for i, off := range rel {
				out[i] = base + uint64(off)
			}
			return out, nil
		}
	}
	return nil, errors.New("could not read function bytes for Read RET offsets")
}

func vmaToFileOffset(f *elf.File, addr uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= addr && addr < prog.Vaddr+prog.Memsz {
			return addr - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("address 0x%x not in executable PT_LOAD segment", addr)
}

func pieSymbolFileOffset(f *elf.File, symTab *gosym.Table, name string) (uint64, error) {
	return goFuncFileOffset(f, symTab, name)
}

func pieReadRetOffsets(f *elf.File, symTab *gosym.Table, name string) ([]uint64, error) {
	return goFuncReadRetOffsets(f, symTab, name)
}

func symbolReadRetOffsets(f *elf.File, symTab *gosym.Table, name string) ([]uint64, error) {
	fn := symTab.LookupFunc(name)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found", name)
	}
	text := f.Section(".text")
	if text == nil {
		return nil, errors.New("`.text` section not found")
	}
	textData, err := text.Data()
	if err != nil {
		return nil, err
	}

	start := fn.Entry - text.Addr
	end := fn.End - text.Addr
	if end <= start || end > text.Size {
		return nil, fmt.Errorf("invalid function range for %q", name)
	}

	rel, err := retOffsetsInCode(textData[start:end])
	if err != nil {
		return nil, err
	}

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= fn.Entry && fn.Entry < prog.Vaddr+prog.Memsz {
			base := fn.Entry - prog.Vaddr + prog.Off
			out := make([]uint64, len(rel))
			for i, off := range rel {
				out[i] = base + uint64(off)
			}
			return out, nil
		}
	}
	return nil, errors.New("could not map Read RET offsets to file offsets")
}

// retOffsetsInCode returns offsets of RET instructions within a function body.
func retOffsetsInCode(code []byte) ([]int, error) {
	var offsets []int
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case 0xc3: // ret
			offsets = append(offsets, i)
		case 0xc2: // ret imm16
			offsets = append(offsets, i)
			i += 2
		case 0x0f:
			if i+1 < len(code) && code[i+1] == 0x0b { // ud2
				break
			}
		}
	}
	if len(offsets) == 0 {
		return nil, errors.New("no RET instructions found in function")
	}
	return offsets, nil
}

// isGoExecutable returns true if path is a Go ELF binary readable by the agent.
func isGoExecutable(path string) bool {
	_, err := buildinfo.ReadFile(path)
	return err == nil
}

func statInode(path string) (dev, ino uint64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("stat inode unavailable")
	}
	return uint64(st.Dev), st.Ino, nil
}
