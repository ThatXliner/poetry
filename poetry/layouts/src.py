from typing import TYPE_CHECKING

from .layout import Layout


if TYPE_CHECKING:
    from pathlib import Path

DEFAULT = """__version__ = '{version}'
"""


class SrcLayout(Layout):
    def _create_default(self, path: "Path") -> None:
        package_path = path / "src" / self._package_name

        package_init = package_path / "__init__.py"

        package_path.mkdir(parents=True)

        with package_init.open("w", encoding="utf-8") as f:
            f.write(DEFAULT.format(version=self._version))
