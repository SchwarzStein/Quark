#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import tempfile
import tarfile
import subprocess

CHUNK_SIZE = 4 * 1024 * 1024  # 2MB alignment

def sha512_2mb_aligned(file_path):
    """Compute SHA512 of the file, splitting into 2MB blocks.
       Each block is padded to 2MB if it's the last block and smaller.
    """
    h = hashlib.sha512()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            print(f"[DEBUG] Read chunk of size: {len(chunk)} bytes from file: {file_path}")
            # only pad the last chunk if it's smaller than 2MB
            if len(chunk) < CHUNK_SIZE:
                chunk += b'\x00' * (CHUNK_SIZE - len(chunk))
            h.update(chunk)
            print(f"[DEBUG] Processed chunk slice: {chunk[:32]}... for file: {file_path}")
    return h.hexdigest()


def extract_docker_fs(image_name, dest_dir):
    """
    Extract filesystem from docker image using docker save and tar extraction.
    Handles layer order and .wh.* deletion files to produce correct merged filesystem.
    """
    import tempfile, subprocess, tarfile, json, os

    os.makedirs(dest_dir, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".tar") as temp_tar:
        print(f"[INFO] Saving docker image '{image_name}' to temporary tar...")
        subprocess.run(["docker", "save", "-o", temp_tar.name, image_name], check=True)

        with tarfile.open(temp_tar.name, "r") as tar:
            manifest_member = tar.getmember("manifest.json")
            manifest_file = tar.extractfile(manifest_member)
            manifest = json.load(manifest_file)
            layers = manifest[0]["Layers"]

            print(f"[INFO] Total layers to extract: {len(layers)}")

            for layer_name in layers:
                print(f"[INFO] Extracting layer: {layer_name}")
                layer_member = tar.getmember(layer_name)
                layer_file = tar.extractfile(layer_member)

                if not layer_file:
                    continue

                with tarfile.open(fileobj=layer_file) as layer_tar:
                    for member in layer_tar.getmembers():
                        fpath = os.path.join(dest_dir, member.name)

                        basename = os.path.basename(fpath)
                        if basename.startswith(".wh."):
                            target = os.path.join(os.path.dirname(fpath), basename[4:])
                            if os.path.exists(target):
                                if os.path.isdir(target):
                                    os.rmdir(target)
                                else:
                                    os.remove(target)
                            continue

                        if member.isdir():
                            os.makedirs(fpath, exist_ok=True)

                        elif member.issym():
                            target = member.linkname
                            os.makedirs(os.path.dirname(fpath), exist_ok=True)
                            try:
                                if os.path.exists(fpath):
                                    os.remove(fpath)
                                os.symlink(target, fpath)
                            except FileExistsError:
                                pass  
                        elif member.isreg():
                            os.makedirs(os.path.dirname(fpath), exist_ok=True)
                            fileobj = layer_tar.extractfile(member)
                            if fileobj:
                                with open(fpath, "wb") as out_f:
                                    out_f.write(fileobj.read())

                        else:
                            continue

            # print(f"[EXTRACTED] {fpath}")

    print(f"[INFO] Filesystem successfully extracted to {dest_dir}")
    print(f"[INFO] Top-level directories: {os.listdir(dest_dir)}")


def process_config_recursive(root_dir, config_paths, manifest=None):
    """
    Recursively process config paths (files and directories) and compute SHA512 hashes.
    manifest: dictionary to store path -> hash
    """
    if manifest is None:
        manifest = {}

    for path in config_paths:
        abs_path = os.path.join(root_dir, path.lstrip("/"))
        print(f"[DEBUG] Processing path: {abs_path}")
        if not os.path.exists(abs_path):
            print(f"[WARN] Path not found: {abs_path}")
            continue

        if os.path.isdir(abs_path):
            print(f"[DEBUG] '{abs_path}' is a directory, processing contents...")
            for entry in os.listdir(abs_path):
                print(f"[DEBUG] Found entry: {entry} in directory: {abs_path}")
                entry_rel_path = os.path.join(path, entry)
                process_config_recursive(root_dir, [entry_rel_path], manifest)
        else:
            print(f"[DEBUG] '{abs_path}' is a file, computing hash...")
            rel_path = os.path.relpath(abs_path, root_dir)
            manifest["/" + rel_path] = sha512_2mb_aligned(abs_path)

    return manifest


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <docker_image> <config_file.json> <output_manifest.json>")
        sys.exit(1)

    docker_image = sys.argv[1]
    config_file = sys.argv[2]
    output_manifest = sys.argv[3]

    with open(config_file, "r") as f:
        config_paths = json.load(f)  # expect a list of paths, path ends with '/' if directory

    with tempfile.TemporaryDirectory() as tmpfs:
        extract_docker_fs(docker_image, tmpfs)
        manifest = process_config_recursive(tmpfs, config_paths)


    with open(output_manifest, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[INFO] Manifest saved to {output_manifest}")

if __name__ == "__main__":
    main()

