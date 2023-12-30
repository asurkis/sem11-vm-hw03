#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>

// #####################################################################
// ##                        Utility functions                        ##
// #####################################################################

// We don't have guarantees that our platform is little-endian,
// which is the assumption in byterun.c
uint32_t read_u32_le(std::basic_istream<unsigned char> &is) {
  unsigned char bytes[4] = {};
  is.read(bytes, 4);
  std::cerr << is.tellg() << ' ' << int(bytes[0]) << ' ' << int(bytes[1]) << ' '
            << int(bytes[2]) << ' ' << int(bytes[3]) << std::endl;
  return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
         (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}

// #####################################################################
// ##                        Raw bytecode file                        ##
// #####################################################################

struct BytecodeFile {
  uint32_t stringtab_size = 0;
  uint32_t global_area_size = 0;
  uint32_t public_symbols_number = 0;
  std::vector<unsigned char> data;

  void load(std::basic_istream<unsigned char> &is) {
    stringtab_size = read_u32_le(is);
    global_area_size = read_u32_le(is);
    public_symbols_number = read_u32_le(is);
    std::istreambuf_iterator<unsigned char> beg{is}, end;
    data = std::vector(beg, end);
  }
};

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <bytecode file>\n";
    return EXIT_FAILURE;
  }

  BytecodeFile raw_file;
  {
    std::cerr << argv[1] << std::endl;
    std::ios_base::openmode mode = std::ios_base::in | std::ios_base::binary;
    std::basic_ifstream<unsigned char> fin(argv[1], mode);
    fin.seekg(0, std::ios_base::end);
    std::cerr << fin.tellg() << std::endl;
    fin.seekg(0, std::ios_base::beg);
    std::cerr << fin.tellg() << std::endl;
    raw_file.load(fin);
  }
}
