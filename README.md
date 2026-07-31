# cpp-sha256 — SHA-256 File Hasher

Hasher y verificador de integridad de archivos que implementa **SHA-256 (FIPS 180-4) desde cero** en C++23 puro, sin dependencias externas. Compila directamente con g++ y solo usa la biblioteca estándar.

## Características

- Implementación completa del algoritmo SHA-256 (padding, ronda de compresión, constantes K)
- Hashing por streaming con buffer de 1 MiB — maneja archivos de cualquier tamaño
- Verificación contra hash esperado (`-c`) y contra manifiestos estilo `sha256sum` (`-C`)
- Entrada desde stdin (`-`)
- Benchmark de rendimiento en memoria (`-b`)
- Self-test con los vectores de prueba conocidos de FIPS 180-4 (`--selftest`)
- Códigos de salida estándar: `0` = OK, `1` = mismatch, `2` = error (integración con scripts)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o sha256
```

Requiere GCC 14+ (usa `std::println`, `std::span`, `std::from_chars`).

## Uso

```bash
# Hash de archivos
./sha256 README.md src/main.cpp

# Verificar contra un hash esperado
./sha256 -c <64-hex-hash> archivo.bin

# Verificar un manifiesto sha256sum (hash<espacio><espacio>archivo)
./sha256 -C checksums.sha256

# Hash desde stdin
printf 'abc' | ./sha256 -

# Benchmark (64 MiB por defecto)
./sha256 -b 128

# Self-test de los vectores FIPS 180-4
./sha256 --selftest
```

## Ejemplo

```
$ ./sha256 src/main.cpp
sha256 — SHA-256 File Hasher (C++23)

  src/main.cpp                    20.4 KB  129e3c273487f84dba1b2e591b239dd74634b5a5ef98a5a8111c921b6dac43a7

  1 file(s) hashed in 2.4 ms — 8.7 MB/s
```

## Estructura

```
src/main.cpp     # Todo el proyecto: algoritmo SHA-256 + CLI (monolítico, stdlib-only)
checksums.sha256 # Manifiesto de ejemplo para --checkfile
```

## Licencia

MIT
