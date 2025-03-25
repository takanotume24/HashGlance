import os
import unittest
import json
import io
import tempfile
import hashlib
from unittest.mock import patch, MagicMock

from pathlib import Path

from main import (
    get_all_files,
    compare_by_hash,
    compute_file_hash,
    build_hash_to_paths_map,
    print_verbose_detail,
    save_log_data_as_json,
    create_log_data,
    print_compare_result,
    parse_args,
    main,
    CompareResult,
    MatchedFiles,
)


class TestGetAllFiles(unittest.TestCase):
    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            files = get_all_files(tmp_path)
            self.assertEqual(
                len(files), 0, "Expected an empty list for an empty directory."
            )

    def test_single_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            file_path = tmp_path / "test.txt"
            file_path.write_text("test content")
            files = get_all_files(tmp_path)
            self.assertEqual(len(files), 1)
            self.assertIn(file_path, files)

    def test_nested_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "dir1").mkdir()
            (tmp_path / "dir1" / "file1.txt").write_text("content1")
            (tmp_path / "dir2").mkdir()
            (tmp_path / "dir2" / "file2.txt").write_text("content2")
            (tmp_path / "file3.txt").write_text("content3")

            files = get_all_files(tmp_path)
            self.assertEqual(len(files), 3)
            expected_paths = {
                tmp_path / "dir1" / "file1.txt",
                tmp_path / "dir2" / "file2.txt",
                tmp_path / "file3.txt",
            }
            self.assertEqual(set(files), expected_paths)


class TestComputeFileHash(unittest.TestCase):
    def test_hash_empty_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            file_path = tmp_path / "empty.txt"
            file_path.touch()  # create empty file
            hash_value = compute_file_hash(file_path, "sha256")
            # SHA256 of an empty file is "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            self.assertEqual(
                hash_value,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )

    def test_hash_nonempty_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            file_path = tmp_path / "test.txt"
            file_path.write_text("Hello World")
            hash_value = compute_file_hash(file_path, "sha256")

            # Calculate directly in Python for verification
            expected = hashlib.sha256("Hello World".encode("utf-8")).hexdigest()
            self.assertEqual(hash_value, expected)

    def test_hash_alg_switch(self):
        # Check whether switching the algorithm (e.g., MD5, SHA1) works properly
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            file_path = tmp_path / "test.txt"
            file_content = "Test for MD5"
            file_path.write_text(file_content)

            md5_value = compute_file_hash(file_path, "md5")
            expected_md5 = hashlib.md5(file_content.encode("utf-8")).hexdigest()
            self.assertEqual(md5_value, expected_md5)

            sha1_value = compute_file_hash(file_path, "sha1")
            expected_sha1 = hashlib.sha1(file_content.encode("utf-8")).hexdigest()
            self.assertEqual(sha1_value, expected_sha1)


class TestBuildHashToPathsMap(unittest.TestCase):
    def test_map_with_single_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            file_path = tmp_path / "test.txt"
            file_path.write_text("Hello")
            hash_map = build_hash_to_paths_map(tmp_path, "sha256", n_jobs=1)
            self.assertEqual(len(hash_map), 1)
            # Check the key (hash string) matches expectation
            computed_hash = list(hash_map.keys())[0]
            expected = hashlib.sha256("Hello".encode("utf-8")).hexdigest()
            self.assertEqual(computed_hash, expected)
            self.assertEqual(hash_map[computed_hash], [str(file_path.resolve())])

    def test_map_with_multiple_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # Write identical content to multiple files
            file1 = tmp_path / "file1.txt"
            file2 = tmp_path / "file2.txt"
            file1.write_text("abc")
            file2.write_text("abc")

            # Another file with different content
            file3 = tmp_path / "file3.txt"
            file3.write_text("xyz")

            hash_map = build_hash_to_paths_map(tmp_path, "sha256", n_jobs=-1)
            self.assertEqual(
                len(hash_map),
                2,
                "Expected 2 distinct hashes: one for 'abc', one for 'xyz'",
            )

            # Check the specific hashes
            abc_hash = hashlib.sha256("abc".encode("utf-8")).hexdigest()
            xyz_hash = hashlib.sha256("xyz".encode("utf-8")).hexdigest()

            self.assertIn(abc_hash, hash_map)
            self.assertIn(xyz_hash, hash_map)
            self.assertCountEqual(
                hash_map[abc_hash],
                [str(file1.resolve()), str(file2.resolve())],
            )
            self.assertEqual(hash_map[xyz_hash], [str(file3.resolve())])


class TestCompareByHash(unittest.TestCase):
    def test_no_common_hashes(self):
        # Entirely different sets of hashes
        hash_map_a = {
            "hashA1": ["/path/to/a1"],
            "hashA2": ["/path/to/a2"],
        }
        hash_map_b = {
            "hashB1": ["/path/to/b1"],
            "hashB2": ["/path/to/b2"],
        }
        result = compare_by_hash(hash_map_a, hash_map_b)
        self.assertEqual(len(result.matched), 0)
        self.assertEqual(len(result.only_in_a), 2)
        self.assertEqual(len(result.only_in_b), 2)

    def test_common_hashes(self):
        # Some overlapping hashes
        hash_map_a = {
            "common1": ["/A/common_file1"],
            "uniqueA": ["/A/unique_file"],
        }
        hash_map_b = {
            "common1": ["/B/common_file1"],
            "uniqueB": ["/B/unique_file"],
        }
        result = compare_by_hash(hash_map_a, hash_map_b)
        self.assertEqual(len(result.matched), 1)
        self.assertEqual(result.matched[0].hash_value, "common1")
        self.assertEqual(result.matched[0].paths_in_a, ["/A/common_file1"])
        self.assertEqual(result.matched[0].paths_in_b, ["/B/common_file1"])
        # Check the entries exclusive to each side
        self.assertEqual(list(result.only_in_a.keys()), ["uniqueA"])
        self.assertEqual(list(result.only_in_b.keys()), ["uniqueB"])


class TestCreateLogData(unittest.TestCase):
    def test_create_log_data_basic(self):
        dir_a = Path("/dir/a")
        dir_b = Path("/dir/b")
        compare_result = CompareResult(
            matched=[
                MatchedFiles(
                    hash_value="hash1",
                    paths_in_a=["/dir/a/file_a1"],
                    paths_in_b=["/dir/b/file_b1"],
                )
            ],
            only_in_a={"hash2": ["/dir/a/file_a2"]},
            only_in_b={"hash3": ["/dir/b/file_b3"]},
        )
        log_data = create_log_data(
            dir_a=dir_a,
            dir_b=dir_b,
            hash_alg="sha256",
            n_jobs=-1,
            compare_result=compare_result,
        )
        self.assertIn("timestamp", log_data)
        self.assertEqual(log_data["dir_a"], str(dir_a.resolve()))
        self.assertEqual(log_data["dir_b"], str(dir_b.resolve()))
        self.assertEqual(log_data["hash_alg"], "sha256")
        self.assertEqual(log_data["n_jobs"], -1)
        self.assertEqual(log_data["num_matched_groups"], 1)
        self.assertEqual(log_data["num_only_in_a_files"], 1)
        self.assertEqual(log_data["num_only_in_b_files"], 1)
        self.assertEqual(len(log_data["matched"]), 1)
        self.assertIn("only_in_a", log_data)
        self.assertIn("only_in_b", log_data)


class TestSaveLogDataAsJson(unittest.TestCase):
    def test_save_log_data_as_json(self):
        test_data = {
            "timestamp": "2025-01-01T00:00:00",
            "dir_a": "/path/to/dirA",
            "dir_b": "/path/to/dirB",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            try:
                # Switch to the temporary directory so the JSON output is placed here
                os.chdir(tmpdir)
                filename = save_log_data_as_json(test_data)
                self.assertTrue(filename.startswith("compare_result_"))
                self.assertTrue(filename.endswith(".json"))
                file_path = Path(tmpdir) / filename
                self.assertTrue(file_path.exists())

                with file_path.open("r", encoding="utf-8") as f:
                    data_loaded = json.load(f)
                self.assertEqual(data_loaded, test_data)
            finally:
                os.chdir(cwd)


class TestPrintFunctions(unittest.TestCase):
    def test_print_compare_result(self):
        compare_result = CompareResult(
            matched=[MatchedFiles(hash_value="hash1")],
            only_in_a={"hash2": ["file_a2"]},
            only_in_b={"hash3": ["file_b3"]},
        )
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            print_compare_result(compare_result)
            output = fake_out.getvalue()
            self.assertIn("=== Comparison Result (Hash-based) ===", output)
            self.assertIn("Number of groups of identical files: 1", output)
            self.assertIn("Files only in A (total): 1", output)
            self.assertIn("Files only in B (total): 1", output)

    def test_print_verbose_detail(self):
        compare_result = CompareResult(
            matched=[
                MatchedFiles(
                    hash_value="hash1", paths_in_a=["/A/file1"], paths_in_b=["/B/file1"]
                )
            ],
            only_in_a={"hash2": ["/A/file2"]},
            only_in_b={"hash3": ["/B/file3"]},
        )
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            print_verbose_detail(compare_result)
            output = fake_out.getvalue()
            self.assertIn("-- Files determined to be identical --", output)
            self.assertIn("Hash: hash1", output)
            self.assertIn("/A/file1", output)
            self.assertIn("/B/file1", output)
            self.assertIn("-- Files only in A --", output)
            self.assertIn("Hash: hash2", output)
            self.assertIn("/A/file2", output)
            self.assertIn("-- Files only in B --", output)
            self.assertIn("Hash: hash3", output)
            self.assertIn("/B/file3", output)


class TestParseArgs(unittest.TestCase):
    @patch(
        "argparse.ArgumentParser.parse_args",
        return_value=MagicMock(
            dir_a="A", dir_b="B", hash_alg="sha256", n_jobs=2, verbose=True
        ),
    )
    def test_parse_args(self, mock_parse):
        args = parse_args()
        self.assertEqual(args.dir_a, "A")
        self.assertEqual(args.dir_b, "B")
        self.assertEqual(args.hash_alg, "sha256")
        self.assertEqual(args.n_jobs, 2)
        self.assertTrue(args.verbose)


class TestMainFunctionIntegration(unittest.TestCase):
    """
    Integration test for main():
    - Actually create temporary directories (A and B), populate them with test files,
      set up sys.argv accordingly, and run main().
    - Verify that the entire flow (scanning, hashing, JSON output) works correctly.
    """

    def test_main_integration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpA = Path(tmpdir) / "dirA"
            tmpB = Path(tmpdir) / "dirB"
            tmpA.mkdir()
            tmpB.mkdir()

            # Create some test files
            (tmpA / "dummyA.txt").write_text("AAAA")
            (tmpB / "dummyB.txt").write_text("BBBB")

            cwd = os.getcwd()
            try:
                # Change the current directory to tmpdir so the JSON output is placed here
                os.chdir(tmpdir)

                test_argv = [
                    "prog",
                    str(tmpA),
                    str(tmpB),
                    "--hash-alg",
                    "md5",
                    "--n-jobs",
                    "1",
                    "--verbose",
                ]

                # Patch sys.argv to simulate command-line arguments
                with patch("sys.argv", test_argv):
                    # Capture the stdout
                    with patch("sys.stdout", new=io.StringIO()) as fake_out:
                        main()

                    output = fake_out.getvalue()
                    self.assertIn("=== Comparison Result (Hash-based) ===", output)
                    self.assertIn("=== Comparison result saved to JSON:", output)

                # Verify that a JSON file was generated
                files_in_tmpdir = os.listdir(tmpdir)
                json_files = [
                    f
                    for f in files_in_tmpdir
                    if f.startswith("compare_result_") and f.endswith(".json")
                ]
                self.assertTrue(json_files, "No JSON file was created by main()")

                # Optionally, load the JSON file and check contents
                with open(json_files[0], "r", encoding="utf-8") as jf:
                    json_data = json.load(jf)
                self.assertEqual(json_data["hash_alg"], "md5")
                self.assertEqual(json_data["n_jobs"], 1)

            finally:
                os.chdir(cwd)


# If you'd like to run these tests directly via Python:
# if __name__ == "__main__":
#     unittest.main()
