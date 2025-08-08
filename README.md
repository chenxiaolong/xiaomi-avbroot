# xiaomi-avbroot

This is a proof of concept for https://github.com/chenxiaolong/avbroot/issues/472 to use [avbroot](https://github.com/chenxiaolong/avbroot) for signing xiaomi.eu images.

There are two features:

* Unpacking images from xiaomi.eu fastboot zips
* Repacking and signing images

NOTE: xiaomi.eu does not provide OTAs and this script does not generate an OTA. Everything is based on raw partitions images.

## Requirements

* python3
* [tomlkit](https://github.com/python-poetry/tomlkit)
* [avbroot](https://github.com/chenxiaolong/avbroot) (>= version 3.19.0)

The `avbroot` executable must exist in `PATH`.

## Usage

### Unpacking

First, extract the `images/` directory from a xiaomi.eu fastboot images zip.

Then, to unpack the images, run:

```bash
python3 xiaomi-avbroot.py unpack -i images -o unpacked
```

The output directory will contain a directory for each image with `avb.toml` and `raw.img` inside. Modifying `raw.img` will change the partitions. `avb.toml` does not need to be manually updated. The values will be automatically recomputed during packing.

### Packing

Ensure that you have an AVB signing key. A new one can be generated with:

```bash
avbroot key generate-key -o avb.key
```

Then, to pack the images, run:

```bash
python3 xiaomi-avbroot.py pack -i unpacked -o signed -k avb.key
```

The output directory will contain properly signed `.img` files.

## License

This repo is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
