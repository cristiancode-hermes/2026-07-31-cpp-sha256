// SPDX-License-Identifier: MIT
// cpp-sha256 — SHA-256 file hasher and verifier in pure C++23
// Implements the full SHA-256 algorithm (FIPS 180-4) from scratch,
// with streaming hashing, manifest verification and throughput benchmark.
//
// Build:  g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o sha256
// Usage:  ./sha256 [options] <file>...
//         ./sha256 README.md
//         ./sha256 -c <expected-hash> file
//         ./sha256 -C checksums.sha256
//         ./sha256 -b 64            (benchmark over 64 MiB)
//         ./sha256 -                (hash stdin)
//         ./sha256 --selftest       (run FIPS 180-4 known-answer tests)

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <print>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────── SHA-256 core ───────────────────────────────
namespace sha256 {

using Hash = std::array<std::uint8_t, 32>;

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t x, int n) noexcept {
  return (x >> n) | (x << (32 - n));
}

// Round constants K[0..63] — first 32 bits of the fractional parts of
// the cube roots of the first 64 primes.
static constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

class Hasher {
public:
  void update(std::span<const std::uint8_t> data) noexcept {
    total_len_ += data.size();
    std::size_t off = 0;
    if (buf_len_ > 0) {
      const std::size_t need = 64 - buf_len_;
      const std::size_t take = std::min(need, data.size());
      std::memcpy(buf_.data() + buf_len_, data.data(), take);
      buf_len_ += take;
      off += take;
      if (buf_len_ == 64) {
        process_block(buf_.data());
        buf_len_ = 0;
      }
    }
    while (data.size() - off >= 64) {
      process_block(data.data() + off);
      off += 64;
    }
    if (off < data.size()) {
      std::memcpy(buf_.data(), data.data() + off, data.size() - off);
      buf_len_ = data.size() - off;
    }
  }

  [[nodiscard]] Hash finalize() noexcept {
    // Append 0x80, pad with zeros to 56 mod 64, then 64-bit big-endian bit length.
    const std::uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 56) {
      std::memset(buf_.data() + buf_len_, 0, 64 - buf_len_);
      process_block(buf_.data());
      buf_len_ = 0;
    }
    while (buf_len_ < 56) buf_[buf_len_++] = 0;
    for (int i = 0; i < 8; ++i) {
      buf_[56 + i] = static_cast<std::uint8_t>(bit_len >> (56 - 8 * i));
    }
    process_block(buf_.data());

    Hash out{};
    for (int i = 0; i < 8; ++i) {
      out[static_cast<std::size_t>(i) * 4]     = static_cast<std::uint8_t>(h_[i] >> 24);
      out[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
      out[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
      out[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>(h_[i]);
    }
    return out;
  }

private:
  void process_block(const std::uint8_t* p) noexcept {
    std::array<std::uint32_t, 64> w{};
    for (int i = 0; i < 16; ++i) {
      w[static_cast<std::size_t>(i)] =
          (std::uint32_t{p[i * 4]} << 24) | (std::uint32_t{p[i * 4 + 1]} << 16) |
          (std::uint32_t{p[i * 4 + 2]} << 8) | std::uint32_t{p[i * 4 + 3]};
    }
    for (int i = 16; i < 64; ++i) {
      const auto s0 = rotr(w[static_cast<std::size_t>(i - 15)], 7) ^
                      rotr(w[static_cast<std::size_t>(i - 15)], 18) ^
                      (w[static_cast<std::size_t>(i - 15)] >> 3);
      const auto s1 = rotr(w[static_cast<std::size_t>(i - 2)], 17) ^
                      rotr(w[static_cast<std::size_t>(i - 2)], 19) ^
                      (w[static_cast<std::size_t>(i - 2)] >> 10);
      w[static_cast<std::size_t>(i)] = w[static_cast<std::size_t>(i - 16)] + s0 +
                                       w[static_cast<std::size_t>(i - 7)] + s1;
    }

    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

    for (int i = 0; i < 64; ++i) {
      const auto s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const auto ch = (e & f) ^ (~e & g);
      const auto t1 = h + s1 + ch + K[static_cast<std::size_t>(i)] + w[static_cast<std::size_t>(i)];
      const auto s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const auto maj = (a & b) ^ (a & c) ^ (b & c);
      const auto t2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
  }

  std::array<std::uint32_t, 8> h_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  std::array<std::uint8_t, 64> buf_{};
  std::size_t buf_len_ = 0;
  std::uint64_t total_len_ = 0;
};

[[nodiscard]] inline std::string to_hex(const Hash& h, bool upper) noexcept {
  static constexpr char lo[] = "0123456789abcdef";
  static constexpr char up[] = "0123456789ABCDEF";
  const char* tbl = upper ? up : lo;
  std::string out;
  out.reserve(64);
  for (std::uint8_t byte : h) {
    out.push_back(tbl[byte >> 4]);
    out.push_back(tbl[byte & 0x0Fu]);
  }
  return out;
}

// FIPS 180-4 known-answer tests for --selftest.
[[nodiscard]] inline bool selftest() noexcept {
  struct Vector {
    std::string_view input;
    std::string_view digest;
  };
  static constexpr std::array<Vector, 3> vectors = {{
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"The quick brown fox jumps over the lazy dog",
       "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
  }};
  for (const auto& v : vectors) {
    Hasher h;
    h.update(std::span{reinterpret_cast<const std::uint8_t*>(v.input.data()), v.input.size()});
    if (to_hex(h.finalize(), false) != v.digest) return false;
  }
  return true;
}

}  // namespace sha256

// ─────────────────────────────── Utilities ───────────────────────────────
namespace {

std::string fmt_size(std::uint64_t bytes) {
  char buf[32];
  if (bytes < 1024) {
    std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
  } else if (bytes < 1024ull * 1024) {
    std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
  } else if (bytes < 1024ull * 1024 * 1024) {
    std::snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
  } else {
    std::snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
  }
  return buf;
}

std::string fmt_thousands(std::uint64_t n) {
  std::string s = std::to_string(n);
  for (std::size_t i = s.size(); i > 3; i -= 3) s.insert(i - 3, 1, ',');
  return s;
}

std::string fmt_rate(std::uint64_t bytes, double seconds) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%.1f", static_cast<double>(bytes) / seconds / 1e6);
  return buf;
}

std::string fmt_ms(double seconds) {
  char buf[32];
  if (seconds < 1.0) {
    std::snprintf(buf, sizeof(buf), "%.1f ms", seconds * 1000.0);
  } else {
    std::snprintf(buf, sizeof(buf), "%.2f s", seconds);
  }
  return buf;
}

std::string lowercase(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char ch : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  return out;
}

bool is_hex_hash(std::string_view s) {
  if (s.size() != 64) return false;
  return std::all_of(s.begin(), s.end(), [](char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
  });
}

struct Options {
  std::vector<std::string> files;
  std::string check_hash;      // -c
  std::string checkfile;       // -C
  bool upper = false;          // -u
  bool quiet = false;          // -q
  bool bench = false;          // -b
  std::uint64_t bench_mib = 64;
  bool help = false;
  bool selftest = false;
};

void print_help(const char* argv0) {
  std::println(std::cout, "sha256 — SHA-256 File Hasher (C++23, no dependencies)");
  std::println(std::cout, "");
  std::println(std::cout, "Usage:  {} [options] <file>...", argv0);
  std::println(std::cout, "");
  std::println(std::cout, "Options:");
  std::println(std::cout, "  -h, --help           Show this help");
  std::println(std::cout, "  -c, --check <hash>   Verify file(s) against expected SHA-256");
  std::println(std::cout, "  -C, --checkfile <f>  Verify files against a sha256sum manifest");
  std::println(std::cout, "  -u, --upper          Print hashes in uppercase");
  std::println(std::cout, "  -q, --quiet          Only print mismatches and errors");
  std::println(std::cout, "  -b, --bench <MiB>    Hash N MiB in memory, print throughput");
  std::println(std::cout, "  -                    Read data from stdin instead of a file");
  std::println(std::cout, "  --selftest           Run FIPS 180-4 known-answer tests");
  std::println(std::cout, "");
  std::println(std::cout, "Exit codes: 0 = OK, 1 = hash mismatch, 2 = error");
}

bool parse_args(int argc, char** argv, Options& opts) {
  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg == "-h" || arg == "--help") {
      opts.help = true;
    } else if (arg == "-c" || arg == "--check") {
      if (i + 1 >= argc) {
        std::println(std::cerr, "error: {} requires a hash argument", arg);
        return false;
      }
      opts.check_hash = lowercase(argv[++i]);
      if (!is_hex_hash(opts.check_hash)) {
        std::println(std::cerr, "error: invalid SHA-256 hash '{}' (expected 64 hex chars)", opts.check_hash);
        return false;
      }
    } else if (arg == "-C" || arg == "--checkfile") {
      if (i + 1 >= argc) {
        std::println(std::cerr, "error: {} requires a manifest path", arg);
        return false;
      }
      opts.checkfile = argv[++i];
    } else if (arg == "-u" || arg == "--upper") {
      opts.upper = true;
    } else if (arg == "-q" || arg == "--quiet") {
      opts.quiet = true;
    } else if (arg == "-b" || arg == "--bench") {
      opts.bench = true;
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        ++i;
        auto [ptr, ec] = std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), opts.bench_mib);
        if (ec != std::errc{} || opts.bench_mib == 0) {
          std::println(std::cerr, "error: invalid MiB value '{}'", argv[i]);
          return false;
        }
      }
    } else if (arg == "--selftest") {
      opts.selftest = true;
    } else if (arg == "-") {
      opts.files.push_back("-");
    } else if (arg.starts_with("-") && arg.size() > 1) {
      std::println(std::cerr, "error: unknown option '{}'", arg);
      return false;
    } else {
      opts.files.push_back(std::string(arg));
    }
  }
  return true;
}

// ── Hashing helpers ──

struct HashResult {
  bool ok = false;
  sha256::Hash hash{};
  std::uint64_t bytes = 0;
  std::string error;
};

HashResult hash_file(const fs::path& path) {
  HashResult r;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    r.error = "cannot open file";
    return r;
  }
  std::error_code ec;
  const auto size = fs::file_size(path, ec);
  if (!ec) r.bytes = size;

  sha256::Hasher h;
  std::array<std::uint8_t, 1024 * 1024> buf{};
  while (in) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const auto got = static_cast<std::size_t>(in.gcount());
    if (got > 0) h.update(std::span{buf.data(), got});
    if (got < buf.size()) break;
  }
  if (in.bad()) {
    r.error = "read error";
    return r;
  }
  r.hash = h.finalize();
  r.ok = true;
  return r;
}

HashResult hash_stdin() {
  HashResult r;
  sha256::Hasher h;
  std::array<std::uint8_t, 1024 * 1024> buf{};
  std::size_t total = 0;
  while (std::cin) {
    std::cin.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const auto got = static_cast<std::size_t>(std::cin.gcount());
    if (got > 0) {
      h.update(std::span{buf.data(), got});
      total += got;
    }
    if (got < buf.size()) break;
  }
  r.bytes = total;
  r.hash = h.finalize();
  r.ok = true;
  return r;
}

// ── Modes ──

int run_selftest() {
  std::println(std::cout, "sha256 --selftest");
  std::println(std::cout, "");
  if (sha256::selftest()) {
    std::println(std::cout, "  \033[32mPASS\033[0m  e3b0c442...b855  (empty input)");
    std::println(std::cout, "  \033[32mPASS\033[0m  ba7816bf...15ad  (\"abc\")");
    std::println(std::cout, "  \033[32mPASS\033[0m  d7a8fbb3...e592  (\"The quick brown fox jumps over the lazy dog\")");
    std::println(std::cout, "");
    std::println(std::cout, "All 3 FIPS 180-4 known-answer vectors passed.");
    return 0;
  }
  std::println(std::cout, "  \033[31mFAIL\033[0m  known-answer test mismatch — implementation bug!");
  return 2;
}

int run_bench(const Options& opts) {
  const std::uint64_t bytes = opts.bench_mib * 1024ull * 1024ull;
  std::println(std::cout, "sha256 --bench {} MiB", opts.bench_mib);
  std::println(std::cout, "");
  std::println(std::cout, "  Hashing {} bytes...", fmt_thousands(bytes));

  std::vector<std::uint8_t> data(static_cast<std::size_t>(bytes));
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>((i * 31 + 7) & 0xFF);

  const auto t0 = std::chrono::steady_clock::now();
  sha256::Hasher h;
  constexpr std::size_t CHUNK = 1024 * 1024;
  for (std::size_t off = 0; off < data.size(); off += CHUNK) {
    h.update(std::span{data.data() + off, std::min(CHUNK, data.size() - off)});
  }
  const auto digest = h.finalize();
  const auto t1 = std::chrono::steady_clock::now();
  const double seconds = std::chrono::duration<double>(t1 - t0).count();

  std::println(std::cout, "  {} MiB in {} — {} MB/s (single-threaded)", opts.bench_mib, fmt_ms(seconds), fmt_rate(bytes, seconds));
  std::println(std::cout, "  digest: {}", sha256::to_hex(digest, opts.upper));
  return 0;
}

int run_hash_mode(const Options& opts) {
  if (opts.files.empty()) {
    std::println(std::cerr, "error: no input files (use '-' for stdin, or --help)");
    return 2;
  }
  if (!opts.quiet) {
    std::println(std::cout, "sha256 — SHA-256 File Hasher (C++23)");
    std::println(std::cout, "");
  }

  const auto t0 = std::chrono::steady_clock::now();
  std::uint64_t total_bytes = 0;
  std::size_t ok_count = 0;
  int exit_code = 0;

  for (const auto& file : opts.files) {
    HashResult r;
    if (file == "-") {
      r = hash_stdin();
    } else {
      r = hash_file(file);
    }
    if (!r.ok) {
      std::println(std::cerr, "  \033[31mERR\033[0m  {} — {}", file, r.error);
      exit_code = 2;
      continue;
    }
    total_bytes += r.bytes;
    ++ok_count;
    if (!opts.quiet) {
      std::println(std::cout, "  {:<28} {:>10}  {}", file, fmt_size(r.bytes), sha256::to_hex(r.hash, opts.upper));
    }
  }

  const auto t1 = std::chrono::steady_clock::now();
  const double seconds = std::chrono::duration<double>(t1 - t0).count();

  if (!opts.quiet && ok_count > 0) {
    std::println(std::cout, "");
    std::println(std::cout, "  {} file(s) hashed in {} — {} MB/s", ok_count, fmt_ms(seconds), fmt_rate(total_bytes, seconds));
  }
  return exit_code;
}

int run_check_mode(const Options& opts) {
  if (opts.files.empty()) {
    std::println(std::cerr, "error: --check requires exactly one input file (use '-' for stdin)");
    return 2;
  }
  if (opts.files.size() > 1) {
    std::println(std::cerr, "error: --check accepts a single file; use --checkfile for manifests");
    return 2;
  }
  const auto& file = opts.files.front();

  HashResult r = (file == "-") ? hash_stdin() : hash_file(file);
  if (!r.ok) {
    std::println(std::cerr, "  \033[31mERR\033[0m  {} — {}", file, r.error);
    return 2;
  }
  const auto got = sha256::to_hex(r.hash, false);
  if (got == opts.check_hash) {
    if (!opts.quiet) {
      std::println(std::cout, "  \033[32mOK\033[0m   {} — matches {}", file, opts.check_hash);
    }
    return 0;
  }
  std::println(std::cout, "  \033[31mFAIL\033[0m  {} — MISMATCH", file);
  std::println(std::cout, "         expected: {}", opts.check_hash);
  std::println(std::cout, "         got:      {}", got);
  return 1;
}

struct ManifestEntry {
  std::string hash;
  std::string file;
};

bool parse_manifest(const fs::path& path, std::vector<ManifestEntry>& entries, std::string& error) {
  std::ifstream in(path);
  if (!in) {
    error = "cannot open manifest";
    return false;
  }
  std::string line;
  std::size_t lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
    if (line.empty() || line[0] == '#') continue;
    // Format: "<64-hex>  <filename>" (sha256sum style, two spaces)
    const std::size_t sp = line.find(' ');
    if (sp == std::string::npos || sp == 0) {
      std::println(std::cerr, "warning: manifest line {} malformed, skipped", lineno);
      continue;
    }
    std::string hash = line.substr(0, sp);
    std::string file = line.substr(sp + 1);
    // Collapse multiple spaces after hash.
    const std::size_t first = file.find_first_not_of(' ');
    if (first != std::string::npos) file = file.substr(first);
    else file.clear();
    if (!is_hex_hash(hash) || file.empty()) {
      std::println(std::cerr, "warning: manifest line {} malformed, skipped", lineno);
      continue;
    }
    entries.push_back({lowercase(hash), file});
  }
  if (entries.empty()) {
    error = "manifest has no valid entries";
    return false;
  }
  return true;
}

int run_checkfile_mode(const Options& opts) {
  std::vector<ManifestEntry> entries;
  std::string error;
  if (!parse_manifest(opts.checkfile, entries, error)) {
    std::println(std::cerr, "error: {} — {}", opts.checkfile, error);
    return 2;
  }
  std::println(std::cout, "sha256 --checkfile {}", opts.checkfile);
  std::println(std::cout, "");

  const fs::path manifest_dir = fs::path(opts.checkfile).parent_path();
  int mismatches = 0;
  int errors = 0;
  for (const auto& e : entries) {
    fs::path target = e.file;
    if (target.is_relative() && !manifest_dir.empty()) target = manifest_dir / target;
    auto r = hash_file(target);
    if (!r.ok) {
      ++errors;
      std::println(std::cout, "  \033[31mERR\033[0m   {} — {}", e.file, r.error);
      continue;
    }
    const auto got = sha256::to_hex(r.hash, false);
    if (got == e.hash) {
      if (!opts.quiet) std::println(std::cout, "  \033[32mOK\033[0m   {} — {}", e.file, fmt_size(r.bytes));
    } else {
      ++mismatches;
      std::println(std::cout, "  \033[31mFAIL\033[0m  {} — MISMATCH", e.file);
    }
  }
  std::println(std::cout, "");
  std::println(std::cout, "  {} verified, {} mismatched, {} errors", entries.size(), mismatches, errors);
  return (mismatches > 0 || errors > 0) ? 1 : 0;
}

}  // namespace

// ─────────────────────────────── Entry point ───────────────────────────────
int main(int argc, char** argv) {
  Options opts;
  if (!parse_args(argc, argv, opts)) {
    print_help(argv[0]);
    return 2;
  }
  if (opts.help) {
    print_help(argv[0]);
    return 0;
  }
  if (opts.selftest) return run_selftest();
  if (opts.bench) return run_bench(opts);
  if (!opts.checkfile.empty()) return run_checkfile_mode(opts);
  if (!opts.check_hash.empty()) return run_check_mode(opts);
  return run_hash_mode(opts);
}
