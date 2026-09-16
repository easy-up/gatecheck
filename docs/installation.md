# Installation

## Prerequisites

Before installing Gatecheck, make sure your system meets the following requirements:

- **Operating System**: Windows, macOS, or Linux.
- **Go**: Version 1.23.0 or newer (only required if you plan to build the application from source).
- **Task**: The [Task](https://taskfile.dev/) command runner (only required for source builds).

## Installation Options

Gatecheck can be installed either by downloading the pre-compiled binary for your operating system or by compiling 
the source code. 

### Option 1: Installing from Binary

1. **Download the Binary**: Visit the Gatecheck GitHub releases page at 
     `https://github.com/gatecheckdev/gatecheck/releases` and download the latest version for your operating system.
2. **Unpack the Binary** (if necessary): For Windows and Linux, you may need to unpack the `.zip` or `.tar.gz` file.
3. **Move the Binary to a Bin Directory**:
   - **Windows**: Move `gatecheck.exe` to a directory within your PATH, such as `C:\Windows`.
   - **macOS/Linux**: Move `gatecheck` to a location in your PATH, such as `/usr/local/bin`. 
      You can use the command `mv gatecheck /usr/local/bin` in the terminal.

4. **Verify Installation**: Open a terminal or command prompt and type `gatecheck --version` to ensure the application
    is installed correctly.

### Option 2: Building from Source

1. **Clone the Repository**: Clone the Gatecheck repository to your local machine using Git:
   ```
   git clone https://github.com/gatecheckdev/gatecheck
   ```
2. **Navigate to the Repository Directory**:
   ```
   cd gatecheck
   ```
3. **Build**: Compile the local binary:
   ```
   task build
   ```
   The binary is written to `bin/gatecheck`.
4. **Test**: Run the test suite:
   ```
   task test
   ```
5. **Install**: To copy the binary to `/usr/local/bin` (configurable via `INSTALL_DIR`), run:
   ```
   task install
   ```

6. **Verify Installation**: Check the application version to confirm successful installation:
   ```
   gatecheck --version
   ```

## Post-Installation Steps

After installing Gatecheck, you can begin using it by typing `gatecheck` followed by the necessary commands and 
options in your terminal or command prompt. For a list of available commands and their descriptions, use:

```
gatecheck --help
```

## Troubleshooting

If you encounter any issues during the installation process, ensure that you have the correct permissions to 
install software on your system and that your Go environment is properly configured. 
For further assistance, please visit the Gatecheck GitHub issues page or contact support.

For more information on using Gatecheck, refer to the user documentation or the GitHub repository for examples and 
advanced usage.
