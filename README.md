# BookLive Dumper

## Introduction
**BookLive Dumper** is a script designed to extract and save books from the BookLive Reader application. It leverages Frida to intercept and dump the book data as you interact with the reader.

## Usage

To use the script, run the following command in your terminal:

```bash
python booklive-dumper.py <executable-file-path> [-o <output-directory>]
```

### Parameters:

- **`executable-file-path`**: Path to the main executable file of the BookLive Reader application.
- **`output-directory`** *(optional)*: The directory where the dumped files will be saved. If not specified, the current directory will be used.

### Example:

```bash
python booklive-dumper.py /path/to/booklive-reader.exe -o /path/to/output/directory
```

## Dependencies

Ensure you have the following dependency installed:

- **Frida**: A dynamic instrumentation toolkit. You can install it via pip:

  ```bash
  pip install frida
  ```

## Notice

- Before running the dumper, ensure that the book you want to dump has been added to your bookshelf in the BookLive Reader and fully downloaded.

## Disclaimer

This script is intended for personal use only. Please purchase the books you want to dump before using the script.