import argparse
import json
import datetime
from pathlib import Path
from functools import partial
from dataclasses import dataclass, field
from typing import List, Dict
from joblib import Parallel, delayed


@dataclass
class MatchedFiles:
    """
    Holds a group of files that share the same hash (indicating identical content).
    - hash_value: The common hash value for these files
    - paths_in_a: List of matching file paths in directory A (absolute paths)
    - paths_in_b: List of matching file paths in directory B (absolute paths)
    """

    hash_value: str
    paths_in_a: List[str] = field(default_factory=list)
    paths_in_b: List[str] = field(default_factory=list)


@dataclass
class CompareResult:
    """
    A data class that aggregates the results of a hash-based directory comparison.
    """

    matched: List[MatchedFiles] = field(default_factory=list)
    only_in_a: Dict[str, List[str]] = field(default_factory=dict)
    only_in_b: Dict[str, List[str]] = field(default_factory=dict)


def get_all_files(directory: Path) -> List[Path]:
    """
    Recursively traverse the specified directory and return a list of Path objects
    for all files within.
    """
    files = []
    for item in directory.iterdir():
        if item.is_dir():
            files.extend(get_all_files(item))
        else:
            files.append(item)
    return files


def compute_file_hash(file_path: Path, hash_alg: str) -> str:
    """
    Compute the hash value (specified by 'hash_alg') for the given file
    and return it as a string.
    """
    import hashlib

    hash_func = getattr(hashlib, hash_alg)()
    with file_path.open("rb") as f:
        for chunk in iter(partial(f.read, 4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def build_hash_to_paths_map(
    directory: Path, hash_alg="sha256", n_jobs=-1
) -> Dict[str, List[str]]:
    """
    Build and return a map of:
      hash_value -> [absolute_file_path, ...]
    for all files within the given directory.

    n_jobs: Number of parallel jobs for joblib's Parallel (default: -1 = use all CPU cores)
            If n_jobs=1, a tqdm progress bar is shown for single-threaded processing.
    """
    from collections import defaultdict

    files = get_all_files(directory)

    def process_file(f: Path):
        h = compute_file_hash(f, hash_alg)
        abs_path = str(f.resolve())
        return h, abs_path

    # --- If n_jobs=1, run in single-threaded mode with tqdm ---
    if n_jobs == 1:
        from tqdm import tqdm

        results = []
        for f in tqdm(files, desc=f"Computing hashes in {directory.name}"):
            res = process_file(f)
            results.append(res)
    else:
        # --- If n_jobs != 1, run in parallel with joblib ---
        results = Parallel(n_jobs=n_jobs, verbose=0)(
            delayed(process_file)(f) for f in files
        )

    hash_map = defaultdict(list)
    for f, res in zip(files, results):
        if res is None:
            raise ValueError(
                f"The computed hash result is None. File: {f}\n"
                "This may be due to read errors or insufficient permissions."
            )
        h, abs_path = res
        hash_map[h].append(abs_path)

    return dict(hash_map)


def compare_by_hash(
    hash_map_a: Dict[str, List[str]], hash_map_b: Dict[str, List[str]]
) -> CompareResult:
    """
    Receive two dictionaries for directories A and B (hash_value -> [absolute paths]),
    compare them by hash, and return the resulting CompareResult.
    """
    result = CompareResult()

    hashes_a = set(hash_map_a.keys())
    hashes_b = set(hash_map_b.keys())

    # Common hash values
    common_hashes = hashes_a & hashes_b
    for h in common_hashes:
        result.matched.append(
            MatchedFiles(
                hash_value=h,
                paths_in_a=hash_map_a[h],
                paths_in_b=hash_map_b[h],
            )
        )

    # Hash values only in A
    only_in_a_hashes = hashes_a - hashes_b
    for h in only_in_a_hashes:
        result.only_in_a[h] = hash_map_a[h]

    # Hash values only in B
    only_in_b_hashes = hashes_b - hashes_a
    for h in only_in_b_hashes:
        result.only_in_b[h] = hash_map_b[h]

    return result


def create_log_data(
    dir_a: Path, dir_b: Path, hash_alg: str, n_jobs: int, compare_result: CompareResult
) -> Dict:
    """
    Create and return a dictionary for JSON output, based on CompareResult and
    other provided information.
    """
    # Summary
    num_matched = len(compare_result.matched)
    num_only_in_a = sum(len(paths) for paths in compare_result.only_in_a.values())
    num_only_in_b = sum(len(paths) for paths in compare_result.only_in_b.values())

    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "dir_a": str(dir_a.resolve()),
        "dir_b": str(dir_b.resolve()),
        "hash_alg": hash_alg,
        "n_jobs": n_jobs,
        "num_matched_groups": num_matched,
        "num_only_in_a_files": num_only_in_a,
        "num_only_in_b_files": num_only_in_b,
        "matched": [
            {
                "hash_value": m.hash_value,
                "paths_in_a": m.paths_in_a,
                "paths_in_b": m.paths_in_b,
            }
            for m in compare_result.matched
        ],
        "only_in_a": compare_result.only_in_a,
        "only_in_b": compare_result.only_in_b,
    }
    return data


def save_log_data_as_json(log_data: Dict) -> str:
    """
    Save the given dictionary as a JSON file (timestamped filename)
    and return the filename.
    """
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"compare_result_{timestamp_str}.json"
    with open(log_filename, "w", encoding="utf-8") as f:
        json.dump(log_data, f, ensure_ascii=False, indent=2)
    return log_filename


def print_compare_result(compare_result: CompareResult):
    """
    Print a summary (and detailed info in verbose mode) of the CompareResult to stdout.
    """
    num_matched = len(compare_result.matched)
    num_only_in_a = sum(len(paths) for paths in compare_result.only_in_a.values())
    num_only_in_b = sum(len(paths) for paths in compare_result.only_in_b.values())

    print("=== Comparison Result (Hash-based) ===")
    print(f"Number of groups of identical files: {num_matched}")
    print(f"Files only in A (total): {num_only_in_a}")
    print(f"Files only in B (total): {num_only_in_b}")


def print_verbose_detail(compare_result: CompareResult):
    """
    Print detailed information about the CompareResult to stdout (verbose).
    """
    if compare_result.matched:
        print("\n-- Files determined to be identical --")
        for matched_group in compare_result.matched:
            print(f"Hash: {matched_group.hash_value}")
            print(f"  In A: {matched_group.paths_in_a}")
            print(f"  In B: {matched_group.paths_in_b}")

    if compare_result.only_in_a:
        print("\n-- Files only in A --")
        for h, paths in compare_result.only_in_a.items():
            print(f"Hash: {h}")
            print(f"  Paths: {paths}")

    if compare_result.only_in_b:
        print("\n-- Files only in B --")
        for h, paths in compare_result.only_in_b.items():
            print(f"Hash: {h}")
            print(f"  Paths: {paths}")


def parse_args() -> argparse.Namespace:
    """
    Parse and return command-line arguments (functional style).
    """
    parser = argparse.ArgumentParser(
        description="Compare file contents by hash value. Files are treated as identical if they share the same hash, even if their paths differ. (Supports parallel processing with joblib.)"
    )
    parser.add_argument("dir_a", type=str, help="Path to the source directory (A)")
    parser.add_argument("dir_b", type=str, help="Path to the target directory (B)")
    parser.add_argument(
        "--hash-alg",
        type=str,
        default="sha256",
        help="The hash algorithm to use (default: sha256)",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="Number of parallel jobs (default: -1 = use all CPU cores)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Print detailed file lists, etc."
    )
    args = parser.parse_args()
    return args


def main():
    # --- Retrieve arguments ---
    args = parse_args()

    p_a = Path(args.dir_a)
    p_b = Path(args.dir_b)

    # --- Perform the comparison ---
    hash_map_a = build_hash_to_paths_map(p_a, args.hash_alg, n_jobs=args.n_jobs)
    hash_map_b = build_hash_to_paths_map(p_b, args.hash_alg, n_jobs=args.n_jobs)

    compare_result = compare_by_hash(hash_map_a, hash_map_b)

    # --- Print the results ---
    print_compare_result(compare_result)
    if args.verbose:
        print_verbose_detail(compare_result)

    # --- Generate & save log data ---
    log_data = create_log_data(
        dir_a=p_a,
        dir_b=p_b,
        hash_alg=args.hash_alg,
        n_jobs=args.n_jobs,
        compare_result=compare_result,
    )
    log_filename = save_log_data_as_json(log_data)
    print(f"\n=== Comparison result saved to JSON: {log_filename} ===")


if __name__ == "__main__":
    main()
