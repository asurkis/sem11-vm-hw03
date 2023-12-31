#include <algorithm>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <vector>

// #####################################################################
// ##                        Utility functions                        ##
// #####################################################################

// We don't have guarantees that our platform is little-endian,
// which is the assumption in byterun.c

int32_t get_i32_le(const char *bytes) {
  int32_t res = 0;
  for (int i = 0; i < 4; ++i) {
    int byte = int(bytes[i]) & 0xFF;
    res |= int32_t(byte) << 8 * i;
  }
  return res;
}

uint32_t read_i32_le(std::istream &is) {
  char bytes[4] = {};
  is.read(bytes, 4);
  return get_i32_le(bytes);
}

// #####################################################################
// ##                        Raw bytecode file                        ##
// #####################################################################

struct Instruction;

struct BytecodeFile {
  uint32_t stringtab_size        = 0;
  uint32_t global_area_size      = 0;
  uint32_t public_symbols_number = 0;

  void load(std::istream &is) {
    stringtab_size        = read_i32_le(is);
    global_area_size      = read_i32_le(is);
    public_symbols_number = read_i32_le(is);
    std::istreambuf_iterator<char> beg{is}, end;
    bytes = std::vector(beg, end);

    public_symbols_start = 0;
    stringtab_start      = public_symbols_start + 8 * public_symbols_number;
    code_start           = stringtab_start + stringtab_size;

    if (stringtab_start >= bytes.size()) throw std::runtime_error("Incorrect metadata: public_symbols_number");

    if (code_start >= bytes.size()) throw std::runtime_error("Incorrect metadata: stringtab_size");

    if (stringtab_size != 0 && bytes[stringtab_start + stringtab_size - 1] != 0)
      throw std::runtime_error("Last string in table is not null-terminated");

    if (!is.good()) throw std::runtime_error("IO error");
  }

  size_t size() const noexcept { return bytes.size(); }
  size_t code_size() const noexcept { return size() - code_start; }

  Instruction get_instr(size_t offset) const;

  char get_byte(size_t off) const {
    if (off >= code_size()) throw std::runtime_error("EOF");
    return bytes[code_start + off];
  }

  int32_t get_int(size_t off) const {
    if (off + 4 > code_size()) throw std::runtime_error("EOF");
    uint32_t res = get_i32_le(&bytes[code_start + off]);
    off += 4;
    return res;
  }

  const char *get_str(size_t off) const {
    if (0 > off || off >= stringtab_size) throw std::runtime_error("String virtual address out of bounds");
    return &bytes[stringtab_start + off];
  }

private:
  std::vector<char> bytes;
  size_t            public_symbols_start = 0;
  size_t            stringtab_start      = 0;
  size_t            code_start           = 0;
};

// #####################################################################
// ##                      Bytecode instruction                       ##
// #####################################################################
// Opcodes:
// 0xF_ => STOP
// 0x01 => BINOP +
// 0x02 => BINOP -
// 0x03 => BINOP *
// 0x04 => BINOP /
// 0x05 => BINOP %
// 0x06 => BINOP <
// 0x07 => BINOP <=
// 0x08 => BINOP >
// 0x09 => BINOP >=
// 0x0A => BINOP ==
// 0x0B => BINOP !=
// 0x0C => BINOP &&
// 0x0D => BINOP !!
// 0x10 => CONST INT
// 0x11 => STRING STR
// 0x12 => SEXP STR INT
// 0x13 => STI
// 0x14 => STA
// 0x15 => JMP INT
// 0x16 => END
// 0x17 => RET
// 0x18 => DROP
// 0x19 => DUP
// 0x1A => SWAP
// 0x1B => ELEM
// 0x20 => LD G(INT)
// 0x21 => LD L(INT)
// 0x22 => LD A(INT)
// 0x23 => LD C(INT)
// 0x30 => LDA G(INT)
// 0x31 => LDA L(INT)
// 0x32 => LDA A(INT)
// 0x33 => LDA C(INT)
// 0x40 => ST G(INT)
// 0x41 => ST L(INT)
// 0x42 => ST A(INT)
// 0x43 => ST C(INT)
// 0x50 => CJMPz INT
// 0x51 => CJMPnz INT
// 0x52 => BEGIN INT INT
// 0x53 => CBEGIN INT INT
// 0x54 => CLOSURE INT (INT x [BYTE, INT])
// 0x55 => CALLC INT
// 0x56 => CALL INT INT
// 0x57 => TAG STR INT
// 0x58 => ARRAY INT
// 0x59 => FAIL INT INT
// 0x5A => LINE INT
// 0x60 => PATT =str
// 0x61 => PATT #string
// 0x62 => PATT #array
// 0x63 => PATT #sexp
// 0x64 => PATT #ref
// 0x65 => PATT #val
// 0x66 => PATT #fun
// 0x70 => CALL Lread
// 0x71 => CALL Lwrite
// 0x72 => CALL Llength
// 0x73 => CALL Lstring
// 0x74 => CALL Barray INT

// References bytecode file, therefore it must be alive
// for the entire lifetime of the instruction
struct Instruction {
  Instruction(const char *start) : start(start) {}

  size_t size() const {
    char code = *start;
    char hi   = (code >> 4) & 15;
    char lo   = code & 15;
    switch (hi) {
    case 15: // STOP
    case 0:  // BINOP
      return 1;

    case 1:
      switch (lo) {
      case 0: // CONST INT
      case 1: // STRING STR
        return 5;
      case 2: // SEXP STR INT
        return 9;
      case 3: // STI
      case 4: // STA
        return 1;
      case 5: // JMP INT
        return 5;
      case 6:  // END
      case 7:  // RET
      case 8:  // DROP
      case 9:  // DUP
      case 10: // SWAP
      case 11: // ELEM
        return 1;
      }
      break;

    case 2: // LD INT
    case 3: // LDA INT
    case 4: // ST INT
      return 5;

    case 5:
      switch (lo) {
      case 0: // CJMPz INT
      case 1: // CJMPnz INT
        return 5;
      case 2: // BEGIN INT INT
      case 3: // CBEGIN INT INT
        return 9;
      case 4: { // CLOSURE INT (INT x [BYTE, INT])
        int32_t len = get_i32_le(start + 5);
        return 9 + 5 * len;
      }
      case 5: // CALLC INT
        return 5;
      case 6: // CALL INT INT
      case 7: // TAG STR INT
        return 9;
      case 8: // ARRAY INT
        return 5;
      case 9: // FAIL INT INT
        return 9;
      case 10: // LINE INT
        return 5;
      }
      break;

    case 6: // PATT ...
      return 1;
    case 7:
      switch (lo) {
      case 0: // CALL Lread
      case 1: // CALL Lwrite
      case 2: // CALL Llength
      case 3: // CALL Lstring
        return 1;
      case 4: // CALL Barray INT
        return 5;
      }
      break;
    }
    throw std::runtime_error("Invalid opcode");
  }

  // Helper function to prevent UB in BytecodeFile
  bool fits_in_size(size_t limit) const {
    // Special case for CLOSURE,
    // as its size is not known from the first byte
    if (*start == 0x54 && limit < 9) return false;
    return size() <= limit;
  }

  void print(const BytecodeFile &src, std::ostream &os) {
    static const char *const BINOPS[] = {"+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "!!"};
    static constexpr size_t  N_BINOPS = sizeof(BINOPS) / sizeof(BINOPS[0]);

    static const char *const MEMORY_OPS[] = {"LD", "LDA", "ST"};
    static constexpr size_t  N_MEMORY_OPS = sizeof(MEMORY_OPS) / sizeof(MEMORY_OPS[0]);

    static const char *const PATTERNS[] = {"=str", "#string", "#array", "#sexp", "#ref", "#val", "#fun"};
    static constexpr size_t  N_PATTERNS = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

    char code = *start;
    char hi   = (code >> 4) & 15;
    char lo   = code & 15;

    switch (hi) {
    case 15: os << "<end>"; break;

    case 0:
      if (lo == 0 || lo > N_BINOPS) throw std::runtime_error("Invalid BINOP");
      os << "BINOP " << BINOPS[lo - 1];
      break;

    case 1:
      switch (lo) {
      case 0: os << "CONST " << get_int(1); break;
      case 1: os << "STRING " << get_int(1); break;
      case 2: os << "SEXP\t" << get_str(src, 1) << ' ' << get_int(5); break;
      case 3: os << "STI"; break;
      case 4: os << "STA"; break;
      case 5: os << "JMP\t0x" << std::setw(8) << std::setfill('0') << std::hex << get_int(1) << std::dec; break;
      case 6: os << "END"; break;
      case 7: os << "RET"; break;
      case 8: os << "DROP"; break;
      case 9: os << "DUP"; break;
      case 10: os << "SWAP"; break;
      case 11: os << "ELEM"; break;
      default: throw std::runtime_error("Invalid opcode");
      }
      break;

    case 2:
    case 3:
    case 4:
      os << MEMORY_OPS[hi - 2] << '\t';
      switch (lo) {
      case 0: os << 'G'; break;
      case 1: os << 'L'; break;
      case 2: os << 'A'; break;
      case 3: os << 'C'; break;
      default: throw std::runtime_error("Invalid memory operation");
      }
      os << '(' << get_int(1) << ')';
      break;

    case 5:
      switch (lo) {
      case 0: os << "CJMPz\t0x" << std::setw(8) << std::setfill('0') << std::hex << get_int(1) << std::dec; break;
      case 1: os << "CJMPnz\t0x" << std::setw(8) << std::setfill('0') << std::hex << get_int(1) << std::dec; break;
      case 2: os << "BEGIN\t" << get_int(1) << ' ' << get_int(5); break;
      case 3: os << "CBEGIN\t" << get_int(1) << ' ' << get_int(5); break;
      case 4: {
        os << "CLOSURE\t" << std::setw(8) << std::setfill('0') << std::hex << get_int(1) << std::dec;
        int32_t n = get_int(5);
        for (int32_t i = 0; i < n; ++i) {
          switch (start[9 + 5 * i]) {
          case 0: os << " G"; break;
          case 1: os << " L"; break;
          case 2: os << " A"; break;
          case 3: os << " C"; break;
          default: throw std::runtime_error("Invalid CLOSURE");
          }
          os << '(' << get_int(10 + 5 * i) << ')';
        }
      } break;

      case 5: os << "CALLC\t" << get_int(1); break;

      case 6:
        os << "CALL\t0x" << std::setw(8) << std::setfill('0') << std::hex << get_int(1) << std::dec << ' ' << get_int(5);
        break;

      case 7: os << "TAG\t" << get_str(src, 1) << ' ' << get_int(5); break;
      case 8: os << "ARRAY\t" << get_int(1); break;
      case 9: os << "FAIL\t" << get_int(1) << ' ' << get_int(5); break;
      case 10: os << "LINE\t" << get_int(1); break;
      default: throw std::runtime_error("Invalid opcode");
      }
      break;

    case 6:
      if (lo >= N_PATTERNS) throw std::runtime_error("Invalid PATT");
      os << "PATT\t" << PATTERNS[lo];
      break;

    case 7:
      switch (lo) {
      case 0: os << "CALL\tLread"; break;
      case 1: os << "CALL\tLwrite"; break;
      case 2: os << "CALL\tLlength"; break;
      case 3: os << "CALL\tLstring"; break;
      case 4: os << "CALL\tBarray\t" << get_int(1); break;
      default: throw std::runtime_error("Invalid opcode");
      }
      break;

    deafult:
      throw std::runtime_error("Invalid opcode");
    }
  }

  bool operator<(const Instruction &rhs) const { return as_sv() < rhs.as_sv(); }
  bool operator==(const Instruction &rhs) const { return as_sv() == rhs.as_sv(); }

private:
  const char *start;

  std::string_view as_sv() const { return std::string_view(start, size()); }

  int32_t     get_int(size_t off) { return get_i32_le(start + off); }
  const char *get_str(const BytecodeFile &src, size_t off) { return src.get_str(get_int(off)); }

  friend struct std::hash<Instruction>;
};

Instruction BytecodeFile::get_instr(size_t offset) const {
  if (offset >= code_size()) throw std::runtime_error("EOF");
  Instruction instr(&bytes[code_start + offset]);
  if (!instr.fits_in_size(code_size() - offset)) throw std::runtime_error("EOF");
  return instr;
}

template <> struct std::hash<Instruction> {
  size_t operator()(const Instruction &self) const noexcept { return std::hash<std::string_view>{}(self.as_sv()); }
};

// #####################################################################
// ##                      Counting instructions                      ##
// #####################################################################

// We could make a structure holding parsed bytecodes,
// but in this task it is unnecessary

struct Frequencies {
  void parse(const BytecodeFile &src) {
    freq.clear();
    pSrc = &src;

    for (size_t offset = 0; offset < src.code_size();) {
      Instruction instr = src.get_instr(offset);
      freq.try_emplace(instr, 0).first->second++;
      offset += instr.size();
    }
  }

  void print(std::ostream &os) {
    std::vector<std::pair<Instruction, size_t>> sorted(freq.begin(), freq.end());
    std::sort(sorted.begin(), sorted.end(), [](auto &&a, auto &&b) {
      if (a.second != b.second) return a.second > b.second;
      return a.first < b.first;
    });

    for (auto [code, n_entries] : sorted) {
      os << n_entries << " x ";
      code.print(*pSrc, os);
      os << '\n';
    }
  }

private:
  const BytecodeFile                     *pSrc;
  std::unordered_map<Instruction, size_t> freq;
};

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <bytecode file>\n";
    return EXIT_FAILURE;
  }

  BytecodeFile src;
  {
    std::ifstream fin(argv[1], std::ios::binary);
    src.load(fin);
  }
  Frequencies freq;
  freq.parse(src);
  freq.print(std::cout);

  return EXIT_SUCCESS;
}
