#include <algorithm>
#include <cstdint>
#include <fstream>
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

uint32_t get_u32_le(char *bytes) {
  uint32_t res = 0;
  for (int i = 0; i < 4; ++i) {
    int byte = int(bytes[i]) & 0xFF;
    res |= uint32_t(byte) << 8 * i;
  }
  return res;
}

int32_t get_i32_le(char *bytes) {
  int32_t res = 0;
  for (int i = 0; i < 4; ++i) {
    int byte = int(bytes[i]) & 0xFF;
    res |= int32_t(byte) << 8 * i;
  }
  return res;
}

uint32_t read_u32_le(std::istream &is) {
  char bytes[4] = {};
  is.read(bytes, 4);
  return get_u32_le(bytes);
}

// #####################################################################
// ##                        Raw bytecode file                        ##
// #####################################################################

struct BytecodeFile {
  uint32_t stringtab_size        = 0;
  uint32_t global_area_size      = 0;
  uint32_t public_symbols_number = 0;

  bool load(std::istream &is) {
    stringtab_size        = read_u32_le(is);
    global_area_size      = read_u32_le(is);
    public_symbols_number = read_u32_le(is);
    std::istreambuf_iterator<char> beg{is}, end;
    bytes = std::vector(beg, end);

    public_symbols_start = 0;
    stringtab_start      = public_symbols_start + 8 * public_symbols_number;
    code_start           = stringtab_start + stringtab_size;

    if (stringtab_start >= bytes.size())
      throw std::runtime_error("Incorrect metadata: public_symbols_number");

    if (code_start >= bytes.size())
      throw std::runtime_error("Incorrect metadata: stringtab_size");

    if (stringtab_size != 0 && bytes[stringtab_start + stringtab_size - 1] != 0)
      throw std::runtime_error("Last string in table is not null-terminated");

    reset();

    return is.good();
  }

  void reset() { offset = 0; }

  uint8_t read_u8() {
    if (code_start + offset >= bytes.size()) throw std::runtime_error("EOF");
    return bytes[code_start + offset++];
  }

  uint32_t read_u32() {
    if (code_start + offset + 4 > bytes.size()) throw std::runtime_error("EOF");
    uint32_t res = get_u32_le(&bytes[code_start + offset]);
    offset += 4;
    return res;
  }

  uint32_t read_i32() {
    if (code_start + offset + 4 > bytes.size()) throw std::runtime_error("EOF");
    uint32_t res = get_i32_le(&bytes[code_start + offset]);
    offset += 4;
    return res;
  }

  const char *read_cstr() {
    uint32_t str_off = read_u32();
    if (str_off >= stringtab_size)
      throw std::runtime_error("String virtual address out of bounds");
    return &bytes[stringtab_start + str_off];
  }

private:
  std::vector<char> bytes;
  size_t            public_symbols_start = 0;
  size_t            stringtab_start      = 0;
  size_t            code_start           = 0;

  size_t offset = 0;
};

// #####################################################################
// ##                      Counting instructions                      ##
// #####################################################################

// We could make a structure holding parsed bytecodes,
// but in this task it is unnecessary

struct Frequencies {
  void parse(BytecodeFile &src) {
    freq.clear();
    src.reset();

    constexpr const char *BINOPS[] = {"+",
                                      "-",
                                      "*",
                                      "/",
                                      "%",
                                      "<",
                                      "<=",
                                      ">",
                                      ">=",
                                      "==",
                                      "!=",
                                      "&&",
                                      "!!"};
    constexpr size_t      N_BINOPS = sizeof(BINOPS) / sizeof(BINOPS[0]);

    constexpr const char *MEMORY_OPS[] = {"LD", "LDA", "ST"};
    constexpr size_t N_MEMORY_OPS = sizeof(MEMORY_OPS) / sizeof(MEMORY_OPS[0]);

    constexpr const char *PATTERNS[]
        = {"=str", "#string", "#array", "#sexp", "#ref", "#val", "#fun"};
    constexpr size_t N_PATTERNS = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

    for (;;) {
      uint8_t code = src.read_u8();
      uint8_t hi   = (code >> 4) & 15;
      uint8_t lo   = code & 15;

      std::ostringstream oss;

      switch (hi) {
      case 15: return;

      case 0:
        if (lo == 0 || lo > N_BINOPS) throw std::runtime_error("Invalid BINOP");
        oss << "BINOP " << BINOPS[lo - 1];
        break;

      case 1:
        switch (lo) {
        case 0: oss << "CONST " << src.read_i32(); break;
        case 1: oss << "STRING " << src.read_cstr(); break;

        case 2:
          oss << "SEXP\t" << src.read_cstr();
          oss << ' ' << src.read_u32();
          break;

        case 3: oss << "STI"; break;
        case 4: oss << "STA"; break;

        case 5:
          oss << "JMP\t0x" << std::setw(8) << std::setfill('0') << std::hex
              << src.read_u32();
          break;

        case 6: oss << "END"; break;
        case 7: oss << "RET"; break;
        case 8: oss << "DROP"; break;
        case 9: oss << "DUP"; break;
        case 10: oss << "SWAP"; break;
        case 11: oss << "ELEM"; break;

        default: throw std::runtime_error("Invalid opcode");
        }
        break;

      case 2:
      case 3:
      case 4:
        oss << MEMORY_OPS[hi - 2] << "\t";
        switch (lo) {
        case 0: oss << 'G'; break;
        case 1: oss << 'L'; break;
        case 2: oss << 'A'; break;
        case 3: oss << 'C'; break;
        default: throw std::runtime_error("Invalid memory operation");
        }
        oss << '(' << src.read_u32() << ')';
        break;

      case 5:
        switch (lo) {
        case 0:
          oss << "CJMPz\t0x" << std::setw(8) << std::setfill('0') << std::hex
              << src.read_u32();
          break;

        case 1:
          oss << "CJMPnz\t0x" << std::setw(8) << std::setfill('0') << std::hex
              << src.read_u32();
          break;

        case 2:
          oss << "BEGIN\t" << src.read_u32();
          oss << ' ' << src.read_u32();
          break;

        case 3:
          oss << "CBEGIN\t" << src.read_u32();
          oss << ' ' << src.read_u32();
          break;

        case 4: {
          oss << "CLOSURE\t" << std::setw(8) << std::setfill('0') << std::hex
              << src.read_u32();
          oss << std::setw(0) << std::dec;
          uint32_t n = src.read_u32();
          for (uint32_t i = 0; i < n; ++i) {
            switch (src.read_u8()) {
            case 0: oss << " G"; break;
            case 1: oss << " L"; break;
            case 2: oss << " A"; break;
            case 3: oss << " C"; break;
            default: throw std::runtime_error("Invalid CLOSURE");
            }
            oss << '(' << src.read_u32() << ')';
          }
        } break;

        case 5: oss << "CALLC\t" << src.read_u32(); break;

        case 6:
          oss << "CALL\t0x" << std::setw(8) << std::setfill('0') << std::hex
              << src.read_u32();
          oss << std::setw(0) << std::dec << src.read_u32();
          break;

        case 7:
          oss << "TAG\t" << src.read_cstr();
          oss << ' ' << src.read_u32();
          break;

        case 8: oss << "ARRAY\t" << src.read_u32(); break;

        case 9:
          oss << "FAIL\t" << src.read_u32();
          oss << ' ' << src.read_u32();
          break;

        case 10: oss << "LINE\t" << src.read_u32(); break;

        default: throw std::runtime_error("Invalid opcode");
        }
        break;

      case 6:
        if (lo >= N_PATTERNS) throw std::runtime_error("Invalid PATT");
        oss << "PATT\t" << PATTERNS[lo];
        break;

      case 7:
        switch (lo) {
        case 0: oss << "CALL\tLread"; break;
        case 1: oss << "CALL\tLwrite"; break;
        case 2: oss << "CALL\tLlength"; break;
        case 3: oss << "CALL\tLstring"; break;
        case 4: oss << "CALL\tBarray\t" << src.read_u32(); break;

        default: throw std::runtime_error("Invalid opcode");
        }
        break;

      deafult:
        throw std::runtime_error("Invalid opcode");
      }

      freq.try_emplace(oss.str(), 0).first->second++;
    }
  }

  void print(std::ostream &os) {
    std::vector<std::pair<std::string_view, size_t>> sorted(freq.begin(),
                                                            freq.end());
    std::sort(sorted.begin(), sorted.end(), [](auto &&a, auto &&b) {
      if (a.second != b.second) return a.second > b.second;
      return a.first < b.first;
    });

    for (auto [code, n_entries] : sorted) {
      os << n_entries << " x " << code << '\n';
    }
  }

private:
  std::unordered_map<std::string, size_t> freq;
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
