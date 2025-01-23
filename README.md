# Jaadubyte

Jaadubyte is a command-line tool for detecting and verifying file types based on their magic bytes. It processes individual files or directories and supports verbose output for detailed logging.

---

## Features

- **Automatic Detection**: Automatically detect a file's type by matching its magic bytes.
- **Verification**: Verify a file against a specified type.
- **Directory Processing**: Process all files in a directory to detect their types.
- **Verbose Logging**: Get detailed output for each operation.
- **Default JSON**: Uses `magic_bytes.json` from the current directory if `-m` is not provided.

---

## Installation

### Prerequisites

- GCC (or any C compiler)
- Jansson library for JSON parsing

### Compile

```bash
gcc -Wall -Wextra -o jaadubyte jaadubyte.c -ljansson
```

---

## Usage

### Command-line Options

```bash
./jaadubyte [OPTIONS]
```

| Option              | Description                                                      |
| ------------------- | ---------------------------------------------------------------- |
| `-m <file>`         | Path to the magic bytes JSON file (default: `magic_bytes.json`). |
| `-f <file>`         | Path to a file to verify or detect.                              |
| `-d <directory>`    | Path to a directory to process.                                  |
| `-t <type>`         | File type to verify (used with `-f`).                            |
| `--verbose` or `-v` | Enable verbose output for detailed logging.                      |

### Examples

#### Auto-detect a file type:

```bash
./jaadubyte -f test.png
```

#### Verify a file against a specific type:

```bash
./jaadubyte -f test.png -t png
```

#### Process all files in a directory:

```bash
./jaadubyte -d /path/to/dir --verbose
```

---

## JSON Format

The magic bytes JSON file must follow this structure:

```json
{
  "category": {
    "file_type": "magic_bytes",
    ...
  }
}
```

### Example

```json
{
  "image": {
    "png": "89504e470d0a1a0a",
    "jpg": "ffd8ffe000104a464946"
  },
  "document": {
    "pdf": "255044462d312e",
    "txt": "7478740d0a"
  }
}
```

---

## License

Jaadubyte is licensed under the MIT License. See `LICENSE` for details.

# 
‘सत्य, सेवा, सुरक्षणम’ 
