"""The Dockerfile must copy every app module into the image.

0.3.28 shipped with one COPY line per module and never copied
``app/annotate.py``, so the container died at import time with
``ModuleNotFoundError: No module named 'annotate'``. This test derives the
image contents from the Dockerfile itself, so a module added later cannot be
silently dropped again.
"""

import glob
import os
import shlex
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCKERFILE = os.path.join(ROOT, "Dockerfile")
APP_DIR = os.path.join(ROOT, "app")


def read_dockerfile(path=DOCKERFILE):
    with open(path, encoding="utf-8") as handle:
        return handle.read().splitlines()


def instructions(lines):
    """Yield ``(KEYWORD, arguments)`` with comments and continuations handled."""
    buffer = ""
    for raw in lines:
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buffer += line[:-1].rstrip() + " "
            continue
        buffer += line
        text = " ".join(buffer.split())
        buffer = ""
        if not text:
            continue
        keyword, _, rest = text.partition(" ")
        yield keyword.upper(), rest.strip()


def copy_tokens(arguments):
    """Split a COPY/ADD argument string into ``(sources, destination)``."""
    tokens = [t for t in shlex.split(arguments) if not t.startswith("--")]
    if len(tokens) < 2:
        return [], ""
    return tokens[:-1], tokens[-1]


def image_paths(lines):
    """Every destination path the Dockerfile puts into the image."""
    paths = set()
    for keyword, arguments in instructions(lines):
        if keyword not in ("COPY", "ADD"):
            continue
        sources, destination = copy_tokens(arguments)
        for source in sources:
            if "://" in source:  # ADD from a URL
                continue
            for found in sorted(glob.glob(os.path.join(ROOT, source), recursive=True)):
                if os.path.isdir(found):
                    for base, _dirs, files in os.walk(found):
                        for name in files:
                            inner = os.path.relpath(os.path.join(base, name), ROOT)
                            paths.add("/" + inner.replace(os.sep, "/"))
                    continue
                relative = os.path.relpath(found, ROOT).replace(os.sep, "/")
                target = destination
                if destination.endswith("/") or len(sources) > 1:
                    target = destination.rstrip("/") + "/" + os.path.basename(relative)
                paths.add(target if target.startswith("/") else "/" + target)
    return paths


def app_modules():
    found = glob.glob(os.path.join(APP_DIR, "*.py"))
    return sorted(os.path.basename(path) for path in found)


def missing_modules(paths, modules):
    return sorted(name for name in modules if "/app/" + name not in paths)


class DockerfileCopiesEveryModule(unittest.TestCase):
    def test_app_directory_has_modules_to_check(self):
        self.assertTrue(app_modules(), "no app/*.py modules found to verify")

    def test_every_app_module_reaches_the_image(self):
        missing = missing_modules(image_paths(read_dockerfile()), app_modules())
        self.assertEqual(
            missing,
            [],
            "Dockerfile never copies app module(s) into /app: " + ", ".join(missing),
        )

    def test_annotate_is_copied(self):
        # The exact module whose absence crashed 0.3.28.
        self.assertIn("/app/annotate.py", image_paths(read_dockerfile()))

    def test_checker_detects_a_dropped_module(self):
        # Guards against the check silently passing on a bad Dockerfile.
        per_file = ["FROM python:3.12-alpine", "COPY app/server.py /app/server.py"]
        paths = image_paths(per_file)
        self.assertIn("/app/server.py", paths)
        missing = missing_modules(paths, app_modules())
        self.assertIn("annotate.py", missing)
        self.assertEqual(len(missing), len(app_modules()) - 1)

    def test_module_copy_keeps_root_ownership(self):
        # COPY without --chown/--chmod keeps the source owner (root) and mode.
        for keyword, arguments in instructions(read_dockerfile()):
            if keyword not in ("COPY", "ADD") or "app/" not in arguments:
                continue
            for token in shlex.split(arguments):
                if token.startswith("--chown") or token.startswith("--chmod"):
                    self.fail(
                        "app copy changes ownership or mode, which the 0.3.28 "
                        "per-file copies did not: " + token
                    )


if __name__ == "__main__":
    unittest.main()
