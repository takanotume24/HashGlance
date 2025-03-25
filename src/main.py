import argparse
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
    - paths_in_a: ディレクトリA側の該当ファイルパス一覧
    - paths_in_b: ディレクトリB側の該当ファイルパス一覧
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


def compute_hash(file_path: Path, hash_alg="sha256") -> str:
    """
    指定したファイルのハッシュ値を計算して文字列として返す。
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
      ハッシュ値 -> [相対パス, ...] のマップを構築して返す。

    n_jobs: joblibのParallelに渡す並列ジョブ数 (デフォルト -1: CPU全コア使用)
    """
    files = get_all_files(directory)

    def process_file(f: Path):
        h = compute_hash(f, hash_alg)
        rel_path = str(f.relative_to(directory))
        return h, rel_path

    # 並列実行でファイルごとの (ハッシュ, パス) を取得
    results = Parallel(n_jobs=n_jobs, verbose=0)(
        delayed(process_file)(f) for f in files
    )

    from collections import defaultdict

    hash_map = defaultdict(list)

    # ファイルと結果をペアで取り出し、Noneチェックを行う
    for f, res in zip(files, results):
        if res is None:
            # どのファイルで None が返ってきたのか明示
            raise ValueError(
                f"ハッシュ計算結果が None になりました。ファイル: {f}\n"
                "読み取りエラーや権限不足が原因の可能性があります。"
            )
        h, rel_path = res
        hash_map[h].append(rel_path)

    return dict(hash_map)


def compare_by_hash(
    hash_map_a: Dict[str, List[str]], hash_map_b: Dict[str, List[str]]
) -> CompareResult:
    """
    ハッシュ値をベースに、A・Bに含まれるファイル（の内容）を比較する。
    内容が同じ(= ハッシュ値が一致)であれば、ファイルパスが違っても「matched」に含まれる。

    CompareResult の構造:
      - matched: 同一ハッシュ値を持つファイル群 (MatchedFiles)
      - only_in_a: Aのみに存在するハッシュ値 -> [ファイルパス一覧]
      - only_in_b: Bのみに存在するハッシュ値 -> [ファイルパス一覧]
    """
    result = CompareResult()

    hashes_a = set(hash_map_a.keys())
    hashes_b = set(hash_map_b.keys())

    # どちらにもあるハッシュ値
    common_hashes = hashes_a & hashes_b
    for h in common_hashes:
        result.matched.append(
            MatchedFiles(
                hash_value=h,
                paths_in_a=hash_map_a[h],
                paths_in_b=hash_map_b[h],
            )
        )

    # Aにのみ存在するハッシュ値
    only_in_a_hashes = hashes_a - hashes_b
    for h in only_in_a_hashes:
        result.only_in_a[h] = hash_map_a[h]

    # Bにのみ存在するハッシュ値
    only_in_b_hashes = hashes_b - hashes_a
    for h in only_in_b_hashes:
        result.only_in_b[h] = hash_map_b[h]

    return result


def main():
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

    p_a = Path(args.dir_a)
    p_b = Path(args.dir_b)

    # A, Bのハッシュマップを構築
    hash_map_a = build_hash_to_paths_map(p_a, args.hash_alg, n_jobs=args.n_jobs)
    hash_map_b = build_hash_to_paths_map(p_b, args.hash_alg, n_jobs=args.n_jobs)

    # ハッシュ値ベースで比較
    result = compare_by_hash(hash_map_a, hash_map_b)

    # 集計情報
    num_matched = len(result.matched)
    num_only_in_a = sum(len(paths) for paths in result.only_in_a.values())
    num_only_in_b = sum(len(paths) for paths in result.only_in_b.values())

    print("=== 比較結果 (ハッシュベース) ===")
    print(f"同一内容のファイルグループ数: {num_matched}個")
    print(f"Aにのみ存在するファイル(合計): {num_only_in_a}個")
    print(f"Bにのみ存在するファイル(合計): {num_only_in_b}個")

    if args.verbose:
        if result.matched:
            print("\n-- 同一内容と判定されたファイルたち --")
            for matched_group in result.matched:
                print(f"ハッシュ: {matched_group.hash_value}")
                print(f"  A側: {matched_group.paths_in_a}")
                print(f"  B側: {matched_group.paths_in_b}")

        if result.only_in_a:
            print("\n-- Aにのみ存在するファイル --")
            for h, paths in result.only_in_a.items():
                print(f"ハッシュ: {h}")
                print(f"  パス: {paths}")

        if result.only_in_b:
            print("\n-- Bにのみ存在するファイル --")
            for h, paths in result.only_in_b.items():
                print(f"ハッシュ: {h}")
                print(f"  パス: {paths}")


if __name__ == "__main__":
    main()
