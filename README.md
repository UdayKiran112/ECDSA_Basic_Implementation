# ECDSA Implementation using MIRACL Core Library (SECP256K1 Curve)

This project demonstrates the implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA) using the MIRACL Core Library. The project is specifically configured to work with the SECP256K1 curve.

## Prerequisites

To run this project, you need the following:
- A C++ compiler (`g++` preferred)
- Python 3.x (for configuring the MIRACL library)
- Make (for building the project)

## Project Structure

```
.
├── Lib/                 # MIRACL Core Library files and scripts
│   ├── arch.h           # Architecture-specific configurations
│   ├── core.h           # Core library header
│   ├── randapi.h        # Random number generation utilities
│   ├── big_B256_56.h    # Big number implementation for SECP256K1
│   ├── ecp_SECP256K1.h  # Elliptic Curve operations for SECP256K1
│   ├── ecdh_SECP256K1.h # ECDSA helper functions for SECP256K1
│   ├── config64.py      # Python script to configure MIRACL Core
│   └── core.a           # MIRACL Core compiled static library
├── obj/                 # Directory for object files generated during compilation
├── main.cpp             # Main implementation file
├── Makefile             # Makefile to build and clean the project
└── README.md            # Project documentation (this file)
```

## Setup Instructions

### Step 1: Install the MIRACL Core Library for SECP256K1 Curve

1. Open a terminal and navigate to the `Lib/` directory:
   ```bash
   cd Lib
   ```

2. Run the Python script `config64.py` to generate the required library files:
   ```bash
   python3 config64.py
   ```

3. Install support for the SECP256K1 curve:
   ```bash
   python3 config64.py -s SECP256K1
   ```

### Step 2: Build the Project

1. Navigate back to the root directory of the project:
   ```bash
   cd ..
   ```

2. Compile the project using the following command:
   ```bash
   make
   ```

### Step 3: Run the Program

After successful compilation, run the executable:
```bash
./main
```

### Clean Up

To clean up the object files and the compiled executable:
```bash
make clean
```
