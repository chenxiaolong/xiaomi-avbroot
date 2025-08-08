#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import argparse
from graphlib import TopologicalSorter
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomlkit
from typing import Any, assert_never


# Version requirement due to some bug fixes we depend on:
# - https://github.com/chenxiaolong/avbroot/pull/476
# - https://github.com/chenxiaolong/avbroot/pull/479
AVBROOT_REQUIRED_VERSION = (3, 19, 0)


def status(*args, **kwargs):
    if 'file' not in kwargs:
        kwargs['file'] = sys.stderr

    print(f'\x1b[1m[*] {' '.join(args)}\x1b[0m', **kwargs)


def check_avbroot_version():
    output = subprocess.check_output(['avbroot', '--version'])
    version = output.removeprefix(b'avbroot ').decode('ASCII').strip()
    split = tuple(int(v) for v in version.split('.'))

    if split < AVBROOT_REQUIRED_VERSION:
        required = '.'.join(str(v) for v in AVBROOT_REQUIRED_VERSION)
        raise ValueError(f'avbroot version {version} < {required}')


def avb_is_valid(image: Path):
    return 0 == subprocess.call(
        [
            'avbroot', 'avb', 'info',
            '--quiet',
            '--input', image,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def avb_generate_metadata(descriptor: dict[str, Any]):
    status(f'Generating AVB metadata for: {descriptor['partition_name']}')

    is_signed = descriptor['type'] == 'ChainPartition'

    return {
        'image_size': 0,
        'header': {
            'required_libavb_version_major': 1,
            'required_libavb_version_minor': 0,
            'algorithm_type': 'Sha256Rsa4096' if is_signed else 'None',
            'hash': '0' * 64 if is_signed else '',
            'signature': '0' * 512 if is_signed else '',
            'public_key': '0' * 1032 if is_signed else '',
            'public_key_metadata': '',
            'rollback_index': 0,
            'flags': 0,
            'rollback_index_location': 0,
            'release_string': 'avbtool 1.3.0',
            'reserved': '0' * 160,
            'descriptors': [descriptor],
        },
        'footer': {
            'version_major': 1,
            'version_minor': 0,
            'original_image_size': 0,
            'vbmeta_offset': 0,
            'vbmeta_size': 0,
            'reserved': '0' * 56,
        },
    }


def avb_unpack(input_image: Path, output_dir: Path):
    status(f'Unpacking AVB image: {input_image} -> {output_dir}')

    subprocess.check_call(
        [
            'avbroot', 'avb', 'unpack',
            '--quiet',
            '--input', input_image.absolute(),
            '--ignore-invalid',
        ],
        cwd=output_dir,
    )


def avb_pack(input_dir: Path, output_image: Path, avb_key: Path):
    status(f'Packing AVB image: {input_dir} -> {output_image}')

    avb_toml = input_dir / 'avb.toml'

    # Automatically recompute the image size if this is using a hash tree,
    # because then it's a dynamic partition.
    with open(avb_toml, 'r') as f:
        avb_info = tomlkit.load(f)

    extra_args = []
    if any(
        d['type'] == 'HashTree'
        for d in avb_info['header']['descriptors']
    ):
        extra_args.append('--recompute-size')

    subprocess.check_call(
        [
            'avbroot', 'avb', 'pack',
            '--quiet',
            '--output', output_image.absolute(),
            '--key', avb_key.absolute(),
            # Overwrite the metadata file with the newly computed hashes and
            # signatures so that we can later insert them into vbmeta.
            '--output-info', avb_toml.absolute(),
            *extra_args,
        ],
        cwd=input_dir,
    )


def avb_verify(root_image: Path, avb_key: Path):
    status(f'Verifying AVB signatures: {root_image}')

    with tempfile.NamedTemporaryFile() as f:
        subprocess.check_call([
            'avbroot', 'key', 'encode-avb',
            '--key', avb_key,
            '--output', f.name,
        ])

        subprocess.check_call([
            'avbroot', 'avb', 'verify',
            '--input', root_image,
            '--public-key', f.name,
        ])


def sparse_unpack(input_image: Path, output_image: Path, preserve=True):
    status(f'Unpacking sparse image: {input_image} -> {output_image}')

    extra_args = ['--preserve'] if preserve else []

    subprocess.check_call([
        'avbroot', 'sparse', 'unpack',
        '--quiet',
        '--input', input_image,
        '--output', output_image,
        *extra_args,
    ])


def lp_unpack(input_image: Path, output_dir: Path):
    status(f'Unpacking LP image: {input_image} -> {output_dir}')

    subprocess.check_call(
        [
            'avbroot', 'lp', 'unpack',
            '--quiet',
            '--input', input_image.absolute(),
        ],
        cwd=output_dir,
    )


def lp_pack(input_dir: Path, output_image: Path):
    status(f'Packing LP image: {input_dir} -> {output_image}')

    subprocess.check_call(
        [
            'avbroot', 'lp', 'pack',
            '--quiet',
            '--output', output_image.absolute(),
        ],
        cwd=input_dir,
    )


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action')

    parser_unpack = subparsers.add_parser('unpack')
    parser_unpack.add_argument(
        '-i', '--input',
        required=True,
        type=Path,
        help='fastboot images input directory',
    )
    parser_unpack.add_argument(
        '-o', '--output',
        required=True,
        type=Path,
        help='unpacked images output directory',
    )

    parser_pack = subparsers.add_parser('pack')
    parser_pack.add_argument(
        '-i', '--input',
        required=True,
        type=Path,
        help='unpacked images input directory',
    )
    parser_pack.add_argument(
        '-o', '--output',
        required=True,
        type=Path,
        help='signed images output directory',
    )
    parser_pack.add_argument(
        '-k', '--key',
        required=True,
        type=Path,
        help='AVB signing private key',
    )

    return parser.parse_args()


def unpack_subcommand(input_dir: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    vbmeta_images = set(
        f.name.removesuffix('.img')
        for f in input_dir.glob('vbmeta*.img')
    )

    avb_descriptors = {}

    # Unpack vbmeta images first. We need them to know which other images are
    # AVB protected.
    for name in vbmeta_images:
        image_dir = output_dir / name
        image_dir.mkdir(parents=True, exist_ok=True)

        avb_unpack(input_dir / f'{name}.img', image_dir)

        with open(image_dir / 'avb.toml', 'r') as f:
            avb_info = tomlkit.load(f)

        for descriptor in avb_info['header']['descriptors']:
            if 'partition_name' in descriptor:
                avb_descriptors[descriptor['partition_name']] = descriptor

    # Join the super image from the split sparse files.
    super_image = output_dir / 'super.img'
    # Must delete first in case file already exists. Otherwise, the holes in the
    # file may contain unexpected data.
    super_image.unlink(missing_ok=True)

    for image in input_dir.glob('super.img.*'):
        sparse_unpack(image, super_image)

    # Unpack the super image.
    super_dir = output_dir / 'super'
    super_dir.mkdir(parents=True, exist_ok=True)
    lp_unpack(super_image, super_dir)
    super_image.unlink()

    # Load LP metadata.
    with open(super_dir / 'lp.toml', 'r') as f:
        lp_info = tomlkit.load(f)

    # Unpack all the LP images.
    lp_images = set()
    lp_images_dir = super_dir / 'lp_images'

    for group in lp_info['slots'][0]['groups']:
        for partition in group['partitions']:
            lp_name = partition['name']
            lp_image = lp_images_dir / f'{lp_name}.img'

            if lp_name.endswith('_b'):
                # _b images are meant to be empty.
                if lp_image.stat().st_size != 0:
                    raise ValueError(f'{lp_name} should be empty')
                continue
            elif not lp_name.endswith('_a'):
                raise ValueError(f'Unknown LP partition name: {lp_name}')

            name = lp_name.removesuffix('_a')
            image_dir = output_dir / name
            image_dir.mkdir(parents=True, exist_ok=True)

            # The _a images contain the actual data. If they are missing AVB
            # metadata, then generate new metadata from a template.
            if avb_is_valid(lp_image):
                avb_unpack(lp_image, image_dir)
            else:
                avb_info = avb_generate_metadata(avb_descriptors[name])
                with open(image_dir / 'avb.toml', 'w') as f:
                    tomlkit.dump(avb_info, f)

                lp_image.rename(image_dir / 'raw.img')

            lp_images.add(name)

    # All needed LP images have already been renamed or unpacked.
    shutil.rmtree(lp_images_dir)

    # Unpack all remaining non-LP images.
    for name in avb_descriptors.keys() - vbmeta_images - lp_images:
        image_dir = output_dir / name
        image_dir.mkdir(parents=True, exist_ok=True)

        avb_unpack(input_dir / f'{name}.img', image_dir)


def pack_subcommand(input_dir: Path, output_dir: Path, avb_key: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine the order to pack the images.
    avb_dep_graph = {}

    for avb_toml in input_dir.glob('*/avb.toml'):
        name = avb_toml.parent.name
        avb_dep_graph[name] = set()

        with open(avb_toml, 'r') as f:
            avb_info = tomlkit.load(f)

        for descriptor in avb_info['header']['descriptors']:
            if 'partition_name' in descriptor and descriptor['partition_name'] != name:
                avb_dep_graph[name].add(descriptor['partition_name'])

    avb_pack_order = list(TopologicalSorter(avb_dep_graph).static_order())
    avb_descriptors = {}
    avb_public_keys = {}

    # Pack all AVB images.
    for name in avb_pack_order:
        image_dir = input_dir / name
        avb_toml = image_dir / 'avb.toml'
        is_vbmeta = name.startswith('vbmeta')

        # For vbmeta images, copy the newly recomputed descriptors from the
        # referenced partitions before packing.
        if is_vbmeta:
            with open(avb_toml, 'r') as f:
                avb_info = tomlkit.load(f)

            descriptors = list(avb_info['header']['descriptors'])

            for i, descriptor in enumerate(descriptors):
                if 'partition_name' in descriptor:
                    partition_name = descriptor['partition_name']

                    if partition_name in avb_public_keys:
                        # The child partition is signed. Update the public key
                        # in the chain descriptor.
                        descriptor['public_key'] = avb_public_keys[partition_name]
                    else:
                        # The child partition is unsigned. Copy the entire hash
                        # or hash tree descriptor
                        descriptors[i] = avb_descriptors[partition_name]

            avb_info['header']['descriptors'] = descriptors

            # Ensure that AVB verification is actually enabled.
            avb_info['header']['flags'] = avb_info['header']['flags'] & ~3

            with open(avb_toml, 'w') as f:
                tomlkit.dump(avb_info, f)

        # Pack the image. avb.toml will be updated with the recomputed hashes
        # and signature (if signed).
        avb_pack(image_dir, output_dir / f'{name}.img', avb_key)

        # Read the newly recomputed descriptor so that it can be copied into the
        # corresponding vbmeta descriptors later.
        with open(avb_toml, 'r') as f:
            avb_info = tomlkit.load(f)

        descriptor = next(
            (
                d
                for d in avb_info['header']['descriptors']
                if d.get('partition_name') == name
            ),
            None,
        )
        if descriptor:
            avb_descriptors[name] = descriptor

        if avb_info['header']['algorithm_type'] != 'None':
            avb_public_keys[name] = avb_info['header']['public_key']

    # Verify the entire AVB trust chain.
    avb_verify(output_dir / 'vbmeta.img', avb_key)

    # Create a new LP super image for the dynamic partitions.
    super_image = output_dir / 'super.img'
    super_dir = output_dir / 'super'
    lp_toml = super_dir / 'lp.toml'
    lp_images_dir = super_dir / 'lp_images'
    lp_images_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy(input_dir / 'super' / 'lp.toml', lp_toml)

    with open(lp_toml, 'r') as f:
        lp_info = tomlkit.load(f)

    for group in lp_info['slots'][0]['groups']:
        for partition in group['partitions']:
            lp_name = partition['name']
            lp_image = lp_images_dir / f'{lp_name}.img'

            if lp_name.endswith('_a'):
                # _a images contain the actual data. Move the image file.
                name = lp_name.removesuffix('_a')
                image = output_dir / f'{name}.img'

                image.rename(lp_image)
            elif lp_name.endswith('_b'):
                # _b images are meant to be empty.
                with open(lp_image, 'wb') as _:
                    pass
            else:
                raise ValueError(f'Unknown LP partition name: {lp_name}')

    lp_pack(super_dir, super_image)

    shutil.rmtree(super_dir)


def main():
    args = parse_args()

    check_avbroot_version()

    if args.action == 'unpack':
        unpack_subcommand(args.input, args.output)
    elif args.action == 'pack':
        pack_subcommand(args.input, args.output, args.key)
    else:
        assert_never(args.action)

    status('Done!')


if __name__ == '__main__':
    main()
