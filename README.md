# HashGlance

HashGlance is a Python tool that compares the contents of two directories by computing and comparing their files' hash values. Files with matching hash values are considered identical, even if their paths differ.

## Features

- **Recursive Scanning**: Recursively scans two directories (A and B) to list all files.  
- **Configurable Hashing**: Computes a specified hash (by default, `sha256`) for each file.  
- **Hash-based Comparison**: Uses a dictionary keyed by the hash value to identify matching (identical) files across the two directories.  
- **Summary and Detailed Reporting**:  
  - Number of groups of identical files  
  - Files unique to directory A  
  - Files unique to directory B  
- **Parallel Processing**: Utilizes [joblib](https://joblib.readthedocs.io/en/latest/) for faster hash computation (configurable number of jobs).  
- **Results Logging**: Stores results in a JSON file, timestamped for convenience.

## Requirements

- Python 3.8 or higher  
- [joblib](https://pypi.org/project/joblib/)  
- [tqdm](https://pypi.org/project/tqdm/) (used for progress bars in single-threaded mode)

## Installation

1. Clone or download this repository.
2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. You are ready to use HashGlance.

## Usage

```bash
python compare_directories.py <dir_a> <dir_b> [--hash-alg <alg>] [--n-jobs <jobs>] [--verbose]
```

### Positional Arguments

- **dir_a**  
  Path to the source directory (A).

- **dir_b**  
  Path to the target directory (B).

### Optional Arguments

- `--hash-alg <alg>`  
  Specifies the hashing algorithm to use (e.g., `md5`, `sha1`, `sha256`, etc.).  
  **Default**: `sha256`

- `--n-jobs <jobs>`  
  Number of parallel jobs for hash computation.  
  - **Default**: `-1` (uses all available CPU cores).
  - Use `1` for single-threaded mode (which shows a tqdm progress bar).

- `--verbose`  
  If included, prints detailed information about the matching and non-matching files.

## Example

```bash
python compare_directories.py dirA dirB --hash-alg sha256 --n-jobs 4 --verbose
```

This will:

1. Recursively scan all files under `dirA` and `dirB`.
2. Compute the SHA-256 hash of each file using 4 parallel jobs.
3. Identify which files are identical by comparing their hash values.
4. Print:
   - The number of identical file groups.
   - The number of files only in `dirA`.
   - The number of files only in `dirB`.
   - (If `--verbose` is provided) a detailed list of the files in each group.
5. Save a timestamped JSON log file named in the form `compare_result_YYYYMMDD_HHMMSS.json` containing the detailed comparison results.

## Output Details

The generated JSON file includes:

- **timestamp**: The date and time (ISO 8601) when the script was executed.
- **dir_a** / **dir_b**: Absolute paths to the compared directories.
- **hash_alg**: The hash function used.
- **n_jobs**: Number of parallel jobs used.
- **num_matched_groups**: Number of groups of identical files.
- **num_only_in_a_files**: Number of files unique to directory A.
- **num_only_in_b_files**: Number of files unique to directory B.
- **matched**: A list of objects representing identical file groups. Each object contains:
  - **hash_value**: The hash string of the identical files.
  - **paths_in_a**: List of file paths from directory A that have this hash.
  - **paths_in_b**: List of file paths from directory B that have this hash.
- **only_in_a**: A dictionary keyed by hash value, each containing a list of paths unique to A.
- **only_in_b**: Similarly, a dictionary keyed by hash value for paths unique to B.

## How It Works

1. **File Discovery**  
   HashGlance uses `get_all_files(directory: Path)` to recursively find and list all files in a given directory.

2. **Hash Computation**  
   For each file, `compute_file_hash(file_path: Path, hash_alg: str)` calculates the specified hash (default `sha256`) in chunks to handle large files efficiently.

3. **Parallelization**  
   `joblib.Parallel` is used to compute hashes for multiple files simultaneously. The number of jobs can be set via `--n-jobs`.

4. **Comparison**  
   Two dictionaries (one for directory A, one for directory B) map each `hash_value -> [paths]`. If a hash value is present in both dictionaries, those files are considered identical.

5. **Output Generation**  
   Results are printed to the console and written to a timestamped JSON log file for further analysis or auditing.

## Contributing

Feel free to open an issue or a pull request if you find any bugs or have suggestions for improvements.
