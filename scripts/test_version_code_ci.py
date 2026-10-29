"""Regression tests for post-release CI-only maintenance and monotonic Play tags."""
import unittest
from unittest.mock import patch
import subprocess

import check_version_code as subject


class VersionGuardTests(unittest.TestCase):
    def test_only_android_app_release_tags_count(self):
        self.assertIsNone(subject.APP_RELEASE_TAG.fullmatch("signed-hashdb-v123"))
        self.assertIsNotNone(subject.APP_RELEASE_TAG.fullmatch(
            "safemobile-v1.0.16-code20261109-run10"))

    def test_same_published_app_tree_permitted_for_ci_only(self):
        def fake_git(*args):
            if args == ("git", "tag", "--list"):
                return "signed-hashdb-v500\nsafemobile-v1.0.16-code20261109-run10"
            if args == ("git", "show", "safemobile-v1.0.16-code20261109-run10:app/build.gradle.kts"):
                return "versionCode = 20261109"
            if args == ("git", "rev-parse", "HEAD:app"):
                return "unchanged-tree"
            if args == ("git", "rev-parse", "safemobile-v1.0.16-code20261109-run10:app"):
                return "unchanged-tree"
            raise AssertionError(f"Unexpected Git query: {args}")
        with patch.object(subject, "run", side_effect=fake_git), (
                patch.object(subject.Path, "read_text", return_value="versionCode = 20261109")):
            subject.validate(release=False)
            with self.assertRaisesRegex(ValueError, "must exceed"):
                subject.validate(release=True)

    def test_modified_app_cannot_use_published_version(self):
        def fake_git(*args):
            if args == ("git", "tag", "--list"):
                return "safemobile-v1.0.16-code20261109-run10"
            if args[1] == "show":
                return "versionCode = 20261109"
            if args == ("git", "rev-parse", "HEAD:app"):
                return "changed-tree"
            if args[1] == "rev-parse":
                return "tagged-tree"
            raise AssertionError(args)
        with patch.object(subject, "run", side_effect=fake_git), (
                patch.object(subject.Path, "read_text", return_value="versionCode = 20261109")):
            with self.assertRaisesRegex(ValueError, "app changes require"):
                subject.validate()

    def test_version_below_tag_fails(self):
        with patch.object(subject, "run", side_effect=lambda *a:
                "safemobile-v1.0.16-code20261109-run10" if a[1] == "tag" else
                "versionCode = 20261109"), (
                patch.object(subject.Path, "read_text", return_value="versionCode = 20261108")):
            with self.assertRaises(ValueError):
                subject.validate()


if __name__ == "__main__":
    unittest.main()
