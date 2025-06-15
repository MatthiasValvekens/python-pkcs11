import sys
from pathlib import Path

import tomlkit


def apply_version(root: Path, version: str):
    version_components = version.split(".", maxsplit=3)
    if len(version_components) < 3:
        raise ValueError(f"Don't know how to interpret {version!r} as a version number")

    project_dir = root
    # set the version in the main pyproject.toml
    print(f"Reading {project_dir / 'pyproject.toml'}...")
    with open(project_dir / "pyproject.toml", "r") as pyproj:
        pyproj_content = tomlkit.load(pyproj)
    pyproj_content["project"]["version"] = version

    print(f"Setting project.version to {version}")
    with open(project_dir / "pyproject.toml", "w") as pyproj:
        tomlkit.dump(pyproj_content, pyproj)


def run():
    repo_root = Path(__file__).resolve().parents[1]
    version = sys.argv[1]

    apply_version(repo_root, version)


if __name__ == "__main__":
    run()
