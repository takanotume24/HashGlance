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
    同一ハッシュ（同一内容）を持つファイル群を保持する。
    - hash_value: そのファイル群のハッシュ値
    - paths_in_a: ディレクトリA側の該当ファイルパス一覧 (絶対パス)
    - paths_in_b: ディレクトリB側の該当ファイルパス一覧 (絶対パス)
    """

    hash_value: str
    paths_in_a: List[str] = field(default_factory=list)
    paths_in_b: List[str] = field(default_factory=list)


@dataclass
class CompareResult:
    """
    ディレクトリ比較結果をまとめて保持するデータクラス（ハッシュベース版）。
    """

    matched: List[MatchedFiles] = field(default_factory=list)
    only_in_a: Dict[str, List[str]] = field(default_factory=dict)
    only_in_b: Dict[str, List[str]] = field(default_factory=dict)


def get_all_files(directory: Path) -> List[Path]:
    """
    ディレクトリ配下のファイルを再帰的にたどり、Pathオブジェクトのリストを返す。
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
    指定したファイルのハッシュ値を計算して文字列として返す。
    ※ 'hash_alg' で指定のハッシュアルゴリズムを使用。
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
    ディレクトリ配下のファイルについて:
      ハッシュ値 -> [絶対パス, ...] のマップを構築して返す。

    n_jobs: joblibのParallelに渡す並列ジョブ数 (デフォルト -1: CPU全コア使用)
            n_jobs=1の場合はシングルスレッドでtqdmの進捗を表示。
    """
    from collections import defaultdict

    files = get_all_files(directory)

    def process_file(f: Path):
        h = compute_file_hash(f, hash_alg)
        abs_path = str(f.resolve())  # 絶対パス
        return h, abs_path

    # --- n_jobs=1の場合はtqdmでシングルスレッド処理 ---
    if n_jobs == 1:
        from tqdm import tqdm

        results = []
        for f in tqdm(files, desc=f"Computing hashes in {directory.name}"):
            res = process_file(f)
            results.append(res)
    else:
        # --- n_jobs != 1 の場合はjoblibで並列実行 ---
        results = Parallel(n_jobs=n_jobs, verbose=0)(
            delayed(process_file)(f) for f in files
        )

    hash_map = defaultdict(list)
    for f, res in zip(files, results):
        if res is None:
            raise ValueError(
                f"ハッシュ計算結果が None になりました。ファイル: {f}\n"
                "読み取りエラーや権限不足が原因の可能性があります。"
            )
        h, abs_path = res
        hash_map[h].append(abs_path)

    return dict(hash_map)


def compare_by_hash(
    hash_map_a: Dict[str, List[str]], hash_map_b: Dict[str, List[str]]
) -> CompareResult:
    """
    A・Bの (ハッシュ値 -> [絶対パス群]) 辞書を受け取り、ハッシュ値ベースで比較して CompareResult を返す。
    """
    result = CompareResult()

    hashes_a = set(hash_map_a.keys())
    hashes_b = set(hash_map_b.keys())

    # 共通のハッシュ値
    common_hashes = hashes_a & hashes_b
    for h in common_hashes:
        result.matched.append(
            MatchedFiles(
                hash_value=h,
                paths_in_a=hash_map_a[h],
                paths_in_b=hash_map_b[h],
            )
        )

    # Aだけにあるハッシュ値
    only_in_a_hashes = hashes_a - hashes_b
    for h in only_in_a_hashes:
        result.only_in_a[h] = hash_map_a[h]

    # Bだけにあるハッシュ値
    only_in_b_hashes = hashes_b - hashes_a
    for h in only_in_b_hashes:
        result.only_in_b[h] = hash_map_b[h]

    return result


def create_log_data(
    dir_a: Path, dir_b: Path, hash_alg: str, n_jobs: int, compare_result: CompareResult
) -> Dict:
    """
    CompareResult などの情報を元に、JSON出力用の辞書を作って返す（関数型っぽく）。
    """
    # 集計情報
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
    ログ用の辞書を受け取り、JSONファイル名を返す（ファイル名には日付を使用）。
    """
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"compare_result_{timestamp_str}.json"
    with open(log_filename, "w", encoding="utf-8") as f:
        json.dump(log_data, f, ensure_ascii=False, indent=2)
    return log_filename


def print_compare_result(compare_result: CompareResult):
    """
    CompareResult の概要と (verboseな場合は詳細) を標準出力に表示する。
    """
    num_matched = len(compare_result.matched)
    num_only_in_a = sum(len(paths) for paths in compare_result.only_in_a.values())
    num_only_in_b = sum(len(paths) for paths in compare_result.only_in_b.values())

    print("=== 比較結果 (ハッシュベース) ===")
    print(f"同一内容のファイルグループ数: {num_matched}個")
    print(f"Aにのみ存在するファイル(合計): {num_only_in_a}個")
    print(f"Bにのみ存在するファイル(合計): {num_only_in_b}個")


def print_verbose_detail(compare_result: CompareResult):
    """
    CompareResult の詳細情報を標準出力に表示する (verbose向け)。
    """
    if compare_result.matched:
        print("\n-- 同一内容と判定されたファイルたち --")
        for matched_group in compare_result.matched:
            print(f"ハッシュ: {matched_group.hash_value}")
            print(f"  A側: {matched_group.paths_in_a}")
            print(f"  B側: {matched_group.paths_in_b}")

    if compare_result.only_in_a:
        print("\n-- Aにのみ存在するファイル --")
        for h, paths in compare_result.only_in_a.items():
            print(f"ハッシュ: {h}")
            print(f"  パス: {paths}")

    if compare_result.only_in_b:
        print("\n-- Bにのみ存在するファイル --")
        for h, paths in compare_result.only_in_b.items():
            print(f"ハッシュ: {h}")
            print(f"  パス: {paths}")


def parse_args() -> argparse.Namespace:
    """
    コマンドライン引数をパースして返す（関数型っぽく）。
    """
    parser = argparse.ArgumentParser(
        description="ファイル内容（ハッシュ値）を比較し、パスが違っても同じハッシュなら同一扱いするスクリプト (Joblib並列対応)"
    )
    parser.add_argument("dir_a", type=str, help="比較元ディレクトリ (A) のパス")
    parser.add_argument("dir_b", type=str, help="比較先ディレクトリ (B) のパス")
    parser.add_argument(
        "--hash-alg",
        type=str,
        default="sha256",
        help="使用するハッシュアルゴリズム (デフォルト: sha256)",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="並列実行するジョブ数 (デフォルト: -1 = CPUコアを最大限使用)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="ファイル一覧など詳細情報を出力する"
    )
    args = parser.parse_args()
    return args


def main():
    # --- 引数を受け取る ---
    args = parse_args()

    p_a = Path(args.dir_a)
    p_b = Path(args.dir_b)

    # --- 比較処理の実行 ---
    hash_map_a = build_hash_to_paths_map(p_a, args.hash_alg, n_jobs=args.n_jobs)
    hash_map_b = build_hash_to_paths_map(p_b, args.hash_alg, n_jobs=args.n_jobs)

    compare_result = compare_by_hash(hash_map_a, hash_map_b)

    # --- 結果表示 ---
    print_compare_result(compare_result)
    if args.verbose:
        print_verbose_detail(compare_result)

    # --- ログデータ生成 & 保存 ---
    log_data = create_log_data(
        dir_a=p_a,
        dir_b=p_b,
        hash_alg=args.hash_alg,
        n_jobs=args.n_jobs,
        compare_result=compare_result,
    )
    log_filename = save_log_data_as_json(log_data)
    print(f"\n=== 比較結果をJSONに保存しました: {log_filename} ===")


if __name__ == "__main__":
    main()
