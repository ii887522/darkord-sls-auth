import glob
import os
import shutil
import subprocess

# Constants
PYTHON_VERSION = "3.11"
PLATFORM = "manylinux2014_aarch64"

LAYER_REL_PATHS = [
    rel_path
    for rel_path in os.listdir("src/layers")
    if rel_path not in (".serverless", "serverless.yml")
]

for layer_rel_path in LAYER_REL_PATHS:
    try:
        # Cleanup previous installation
        print(f"Removing src/layers/{layer_rel_path}/python/lib")
        shutil.rmtree(f"src/layers/{layer_rel_path}/python/lib")

    except FileNotFoundError:
        # Previous installation already cleaned up which fulfills the requirement, so ignore this exception
        pass

for layer_rel_path in LAYER_REL_PATHS:
    # Download and install Python dependency packages
    print(
        subprocess.run(
            f"pip install -r src/layers/{layer_rel_path}/python/requirements.txt"
            f" -t src/layers/{layer_rel_path}/python/lib/python{PYTHON_VERSION}/site-packages"
            f" --platform {PLATFORM}"
            " --implementation cp"
            f" --python-version {PYTHON_VERSION}"
            " --only-binary=:all:",
            shell=True,
            stdout=subprocess.PIPE,
        ).stdout.decode()
    )

for layer_rel_path in LAYER_REL_PATHS:
    # Remove unused *.dist-info directories
    for path in glob.iglob(
        f"src/layers/{layer_rel_path}/python/lib/python{PYTHON_VERSION}/site-packages/**/*.dist-info",
        recursive=True,
    ):
        print(f"Removing {path}")
        shutil.rmtree(path)
