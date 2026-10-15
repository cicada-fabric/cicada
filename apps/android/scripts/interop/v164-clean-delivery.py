#!/usr/bin/env python3
"""Independently inspect the frozen v1.6.5 export; never run a Hub or Core helper.

The export is provenance, not Android acceptance. Image inspection reads only
IDs and labels. Source verification reads the fixed Git tree and regular input
files, never Hub databases, process arguments, credentials or container env.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile


PINS = {
    'source_revision': 'c6887f46c8412e648b8e8e68da371acd80e0b87e',
    'contract_revision': 'client-hub-v1.6.5',
    'wire_version': 1,
    'catalog_sha256': 'a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9',
    'source_dirty': False,
    'source_fingerprint': 'cc4ae9207a790c30e9b702c378d9a699bfe95f56e80b5ccfe3b748a6aefaf1ef',
    'bundle_sha256': '37759169d0f776ab318a2cced01ac0ce557fba446980a5b3d112598dc72f50a4',
    'build_metadata_sha256': '3a18caeebb5cba467e44b2bb319a92f49054ccd5771cc95603784ec5d2500b43',
    'hub_image_id': 'sha256:b7bc42678adf9ab44df2a3c51732b2956d668dd7745a93ec3c2a0387d3fc07c2',
    'test_image_id': 'sha256:fa314f2b3f54d269bca963edae675fa0142d0d2bbf833c24170aafaba25c4477',
    'hub_archive_sha256': '2b9d35939b4ff059bfb75ade96e7d73cec4e586057fd9ee77ac5a7c45a0c9a15',
}
DELIVERY_SHA256 = 'f159869f38d8a7a82525a6da4fdcd96de1e43213d4c3d5023b77a15b8758e911'
INVENTORY_SHA256 = '8b8390984f1b09e14774fc135d376302cf09e96b33862110cadab442b821a387'
INPUT_SCOPE = ['LICENSE', 'cicada-go', 'docker/Dockerfile.hub', '.dockerignore',
    'scripts/build-web-panel.sh', 'scripts/write-web-panel-manifest.py',
    'scripts/build-hub-image.sh', '.github/workflows/release.yml']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON number')))


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(), 'export must be a regular file')
    return path


def file_digest(path):
    with regular(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inside(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == relative,
        'export path is not canonical and relative')
    target = root / relative
    require(target.resolve().is_relative_to(root.resolve()), 'export escapes its directory')
    return regular(target)


def verify_bundle(path):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == 25 and len({row.name for row in members}) == 25,
            'unexpected or duplicate contract members')
        raw_files = {}
        for row in members:
            name = PurePosixPath(row.name)
            require(row.isfile() and not name.is_absolute() and '..' not in name.parts and
                str(name) == row.name and row.size <= 1024 * 1024, 'unsafe contract member')
            raw_files[row.name] = archive.extractfile(row).read()
        manifest_raw = raw_files.pop('manifest.json')
        manifest = parse(manifest_raw)
        for key in ('source_revision', 'source_dirty', 'contract_revision', 'catalog_sha256', 'wire_version'):
            require(manifest[key] == PINS[key] and type(manifest[key]) is type(PINS[key]),
                'contract provenance differs from the frozen delivery')
        require(set(raw_files) == set(manifest['files']), 'contract manifest inventory differs')
        for name, raw in raw_files.items():
            expected = manifest['files'][name]
            require(len(raw) == expected['bytes'] and digest(raw) == expected['sha256'],
                'contract member digest mismatch')
        catalog = parse(raw_files['cicada-go/internal/clientcontract/catalog.json'])
        require(digest(raw_files['cicada-go/internal/clientcontract/catalog.json']) == PINS['catalog_sha256'],
            'catalog bytes differ')
        return manifest, digest(manifest_raw), len(catalog.get('operations', [])), raw_files


def verify_inventory(core, inventory):
    """Reproduce both digests and compare every input to the clean fixed Git tree."""
    rows = inventory['entries']
    require(len(rows) == 957 and inventory['scope'] == INPUT_SCOPE, 'source scope changed')
    paths = [bytes.fromhex(row['path_bytes_hex']) for row in rows]
    require(paths == sorted(set(paths)), 'source paths are unordered or duplicated')
    tree_raw = subprocess.check_output(['git', '-C', str(core), 'ls-tree', '-rz',
        PINS['source_revision'], '--', *INPUT_SCOPE], timeout=30)
    tree = {}
    for row in tree_raw.split(b'\0'):
        if row:
            meta, path = row.split(b'\t', 1)
            mode, kind, oid = meta.split(b' ')
            require(kind == b'blob', 'non-blob source input')
            tree[path] = (mode.decode(), oid.decode())
    require(set(paths) == set(tree), 'build inventory differs from fixed Git tree')
    process = subprocess.Popen(['git', '-C', str(core), 'cat-file', '--batch'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    fingerprint = hashlib.sha256(bytes.fromhex(inventory['source_fingerprint_v4']['domain_hex']))
    try:
        for row, raw_path in zip(rows, paths):
            mode, oid = tree[raw_path]
            require(row['file_type'] == 'regular' and row['path'].encode() == raw_path and
                row['git_index'] == {'mode': mode, 'blob_oid': oid, 'object_format': 'sha1'},
                'source inventory metadata differs from fixed Git tree')
            process.stdin.write(oid.encode() + b'\n')
            process.stdin.flush()
            header = process.stdout.readline().split()
            require(len(header) == 3 and header[0].decode() == oid and header[1] == b'blob',
                'Git object read failed')
            raw = process.stdout.read(int(header[2]))
            require(process.stdout.read(1) == b'\n' and len(raw) == row['size_bytes'] and
                digest(raw) == row['content_sha256'], 'source bytes differ from fixed Git commit')
            path = inside(core, row['path'])
            require(file_digest(path) == row['content_sha256'] and
                stat.S_IMODE(path.lstat().st_mode) == stat.S_IMODE(int(row['raw_mode'], 8)),
                'current frozen source input differs from exported bytes/mode')
            fingerprint.update(len(raw_path).to_bytes(8, 'big'))
            fingerprint.update(raw_path)
            fingerprint.update(stat.S_IMODE(int(row['raw_mode'], 8)).to_bytes(4, 'big'))
            fingerprint.update(bytes.fromhex(row['content_sha256']))
    finally:
        process.stdin.close()
        process.wait(timeout=30)
        process.stdout.close()
        process.stderr.close()
    require(process.returncode == 0 and fingerprint.hexdigest() == PINS['source_fingerprint'],
        'source fingerprint mismatch')
    implementation = inventory['implementation']
    require(file_digest(inside(core, implementation['path'])) == implementation['sha256'],
        'inventory implementation bytes differ')
    payload = {key: inventory[key] for key in ('entries', 'implementation', 'source_fingerprint_v4', 'scope')}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    actual = digest(bytes.fromhex(inventory['fingerprint']['domain_hex']) + encoded)
    require(actual == INVENTORY_SHA256 == inventory['fingerprint']['sha256'], 'inventory fingerprint mismatch')
    return len(rows)


def verify_image(image_id):
    raw = subprocess.check_output(['docker', 'image', 'inspect', '--format',
        '{{json .Id}}\t{{json .Config.Labels}}', image_id], timeout=30)
    encoded_id, encoded_labels = raw.rstrip(b'\n').split(b'\t')
    actual_id, labels = parse(encoded_id), parse(encoded_labels)
    require(actual_id == image_id, 'image ID mismatch')
    expected = {
        'org.opencontainers.image.revision': PINS['source_revision'],
        'org.cicada.build.dirty': 'false',
        'org.cicada.build.source-fingerprint': PINS['source_fingerprint'],
        'org.cicada.client-catalog.sha256': PINS['catalog_sha256'],
    }
    require(all(labels.get(key) == value for key, value in expected.items()), 'image provenance label mismatch')
    return {key: labels[key] for key in expected}


def verify(delivery, core):
    manifest_raw = inside(delivery, 'DELIVERY-MANIFEST.NONAUTH.json').read_bytes()
    require(digest(manifest_raw) == DELIVERY_SHA256, 'delivery manifest digest mismatch')
    manifest = parse(manifest_raw)
    for key, expected in PINS.items():
        require(manifest[key] == expected and type(manifest[key]) is type(expected), 'frozen delivery pin mismatch')
    require(manifest['acceptance'] == 'BUILD_EXPORT_ONLY_ANDROID_NOT_RUN', 'unexpected acceptance claim')
    bundle_path = inside(delivery, manifest['bundle'])
    require(file_digest(bundle_path) == PINS['bundle_sha256'], 'bundle digest mismatch')
    contract, contract_sha, operation_count, raw_files = verify_bundle(bundle_path)
    # The exporter pretty-prints its external copy. Its byte hash intentionally
    # differs from the canonical manifest bytes inside the tar archive.
    external_contract_raw = inside(delivery, 'contract-manifest.json').read_bytes()
    require(digest(external_contract_raw) == manifest['manifest_sha256'] and
        parse(external_contract_raw) == contract and operation_count == 55,
        'external contract manifest/catalog mismatch')
    metadata_raw = inside(delivery, 'build.json').read_bytes()
    require(digest(metadata_raw) == PINS['build_metadata_sha256'], 'build metadata digest mismatch')
    metadata = parse(metadata_raw)
    require(metadata['source']['revision'] == PINS['source_revision'] and
        metadata['source']['dirty'] is False and
        metadata['source']['source_fingerprint'] == PINS['source_fingerprint'] and
        metadata['source']['catalog_sha256'] == PINS['catalog_sha256'] and
        metadata['image']['id'] == PINS['hub_image_id'] and
        metadata['test_image']['id'] == PINS['test_image_id'], 'build provenance mismatch')
    count = verify_inventory(core, metadata['source']['input_inventory'])
    require(file_digest(inside(delivery, manifest['hub_archive'])) == PINS['hub_archive_sha256'],
        'Hub archive digest mismatch')
    for name, expected in manifest['licenses'].items():
        require(file_digest(inside(delivery, name)) == expected, 'export license digest mismatch')
    images = {key: verify_image(PINS[key]) for key in ('hub_image_id', 'test_image_id')}
    local_contract = Path(__file__).resolve().parents[2] / 'contracts/client-hub-v1.6.5-c6887f4'
    unchanged_vectors = {name: digest(raw) for name, raw in raw_files.items()
        if '/testdata/' in name and name.endswith('.json') and (local_contract / name).is_file() and
        file_digest(local_contract / name) == digest(raw)}
    return {'schema': 'cicada.client-v164-e2a1908-delivery-check.v1', 'result': 'PASS',
        **PINS, 'delivery_manifest_sha256': DELIVERY_SHA256, 'contract_manifest_sha256': contract_sha,
        'catalog_operations': operation_count, 'contract_files_verified': len(raw_files),
        'source_input_count': count, 'source_inventory_sha256': INVENTORY_SHA256,
        'image_labels': images, 'unchanged_public_vectors': unchanged_vectors,
        'android_recovery_acceptance': 'NOT_RUN', 'encrypted_runtime_capabilities': 'NOT_RUN',
        'hub_lifecycle_actions': 0, 'core_writes': 0, 'database_reads': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--delivery', type=Path, required=True)
    parser.add_argument('--core', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.delivery, args.core)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
