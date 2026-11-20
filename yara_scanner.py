import os
import tempfile
from pathlib import Path

from app_state import default_data_directory

try:
    import yara
except ImportError:
    yara = None


class YaraScanner:
    def __init__(self, rules_directory=None, user_rules_directory=None):
        if rules_directory is None:
            self.bundled_rules_directory = Path(__file__).parent / "yara_rules"
            self.rules_directory = Path(
                user_rules_directory
                or default_data_directory() / "yara_rules"
            )
        else:
            self.bundled_rules_directory = Path(rules_directory)
            self.rules_directory = Path(
                user_rules_directory or rules_directory
            )
        self._rule_directories = list(dict.fromkeys(
            (self.bundled_rules_directory, self.rules_directory)
        ))

        self.rules = None
        self.error = None

        self._load_rules()

    def _get_rule_directories(self):
        return getattr(self, "_rule_directories", (self.rules_directory,))

    def _load_rules(self):
        self.rules = None
        self.error = None
        if yara is None:
            self.error = "yara-python is not installed."
            return

        rule_directories = [
            directory
            for directory in self._get_rule_directories()
            if directory.exists()
        ]
        if not rule_directories:
            self.error = "YARA rules directory not found."
            return

        rule_files = sorted(
            path
            for directory in rule_directories
            for pattern in ("*.yar", "*.yara")
            for path in directory.glob(pattern)
        )

        if not rule_files:
            self.error = "No YARA rule files found."
            return

        try:
            filepaths = {
                f"rule_{index}": str(rule_file)
                for index, rule_file in enumerate(sorted(rule_files))
            }

            self.rules = yara.compile(
                filepaths=filepaths
            )

        except Exception as error:
            self.error = f"Unable to compile local YARA rules: {error}"
            self.rules = None

    def reload_rules(self):
        self._load_rules()
        return {
            "loaded": self.rules is not None,
            "error": self.error,
            "rule_files": self.get_rule_files(),
        }

    def get_rule_files(self):
        return [
            str(path)
            for path in sorted(
                path
                for directory in self._get_rule_directories()
                if directory.exists()
                for pattern in ("*.yar", "*.yara")
                for path in directory.glob(pattern)
            )
        ]

    def get_status(self):
        return {
            "available": self.rules is not None,
            "error": self.error,
            "directory": str(self.rules_directory),
            "bundled_directory": str(
                getattr(self, "bundled_rules_directory", self.rules_directory)
            ),
            "rule_files": self.get_rule_files(),
        }

    def install_rule(self, source_path):
        if yara is None:
            raise RuntimeError("YARA rule installation requires yara-python.")
        source = Path(source_path)
        if source.is_symlink() or not source.is_file():
            raise ValueError("Select a regular local YARA rule file.")
        if source.suffix.lower() not in {".yar", ".yara"}:
            raise ValueError("YARA rules must use the .yar or .yara extension.")
        if source.stat().st_size > 1024 * 1024:
            raise ValueError("YARA rule file exceeds the 1 MiB limit.")

        candidate = yara.compile(filepath=str(source))
        del candidate
        self.rules_directory.mkdir(parents=True, exist_ok=True)
        destination = self.rules_directory / source.name
        if destination.exists():
            raise FileExistsError(f"A YARA rule already exists: {destination.name}")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".yara-rule-",
            suffix=source.suffix.lower(),
            dir=self.rules_directory
        )
        try:
            with os.fdopen(descriptor, "wb") as target:
                target.write(source.read_bytes())
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary_name, destination)
            self._load_rules()
            if self.rules is None:
                raise ValueError(self.error or "YARA rules failed compilation.")
        except Exception:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            self._load_rules()
            raise
        return str(destination)

    def scan_file(self, filepath):
        if self.rules is None:
            return []

        matches = self.rules.match(
            filepath,
            timeout=10
        )

        results = []

        for match in matches:
            results.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
            })

        return results