#!/usr/bin/env python3
"""Inspect local APK packaging with the Android/NDK tools, without signing it."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_apk(path, readelf, apksigner, single_abi, require_unsigned):
    if path.is_symlink() or not path.is_file():
        raise ValueError('APK must be a regular file')
    verify_command = [apksigner, 'verify', '--verbose', '--print-certs', str(path)]
    verified = subprocess.run(verify_command, capture_output=True, text=True, check=False)
    libraries, dex = [], []
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory() as temporary:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('APK contains duplicate entries')
        signature_entries = [name for name in names if
                             re.fullmatch(r'META-INF/[^/]+\.(SF|RSA|DSA|EC)', name, re.I)]
        with path.open('rb') as stream:
            stream.seek(max(0, archive.start_dir - 16))
            signing_block_marker = stream.read(16) == b'APK Sig Block 42'
        no_signature_error = any(message in verified.stderr for message in (
            'Missing META-INF/MANIFEST.MF', 'No signatures', 'No JAR signatures',
        ))
        unsigned = (verified.returncode == 1 and no_signature_error and
                    not signature_entries and not signing_block_marker)
        if require_unsigned and not unsigned:
            raise ValueError('APK did not pass the expected unsigned-artifact check')
        for index, info in enumerate(archive.infolist()):
            if info.filename.endswith('.dex'):
                dex.append({'entry': info.filename, 'bytes': info.file_size})
            if not re.fullmatch(r'lib/[^/]+/[^/]+\.so', info.filename):
                continue
            _, abi, name = info.filename.split('/')
            extracted = Path(temporary) / f'{index}.so'
            with archive.open(info) as source, extracted.open('wb') as target:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    target.write(chunk)
            command = [readelf, '--file-header', '--section-headers', '--wide', str(extracted)]
            sections = subprocess.check_output(command, text=True)
            machine = re.search(r'^\s*Machine:\s*(.+)$', sections, re.M)
            elf_class = re.search(r'^\s*Class:\s*(.+)$', sections, re.M)
            libraries.append({
                'abi': abi, 'name': name, 'bytes': info.file_size,
                'zip_bytes': info.compress_size,
                'zip_compression': 'stored' if info.compress_type == zipfile.ZIP_STORED else 'deflated',
                'sha256': sha256(extracted),
                'elf_class': elf_class.group(1).strip() if elf_class else None,
                'machine': machine.group(1).strip() if machine else None,
                'has_debug_sections': bool(re.search(r'\s\.debug_\S+', sections)),
                'has_full_symbol_table': bool(re.search(r'\s\.symtab\s', sections)),
                'has_dynamic_symbol_table': bool(re.search(r'\s\.dynsym\s', sections)),
            })
        abis = sorted({item['abi'] for item in libraries})
        if single_abi and len(abis) != 1:
            raise ValueError('Expected exactly one native ABI per APK')
        prohibited = [name for name in names if
                      name.endswith(('.onnx', '/am/final.mdl', '/cross-owner-group-key-v2.json')) or
                      name.rsplit('/', 1)[-1] in {'.env', 'cicada.env'}]
        if prohibited:
            raise ValueError('Unexpected model, test vector or environment entry in product APK')
        return {
            'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha256(path),
            'abis': abis, 'libraries': libraries, 'dex': dex,
            'native_uncompressed_bytes': sum(item['bytes'] for item in libraries),
            'bundled_javascript': 'assets/index.android.bundle' in names,
            'unsigned_check': {
                'command': verify_command, 'exit_code': verified.returncode,
                'expected_unsigned': unsigned, 'signature_entries': signature_entries,
                'signing_block_marker': signing_block_marker,
                'stdout': verified.stdout, 'stderr': verified.stderr,
            },
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apks', nargs='+', type=Path)
    parser.add_argument('--readelf', required=True)
    parser.add_argument('--apksigner', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--single-abi', action='store_true')
    parser.add_argument('--require-unsigned', action='store_true')
    args = parser.parse_args()
    reports = [inspect_apk(path, args.readelf, args.apksigner,
                           args.single_abi, args.require_unsigned) for path in args.apks]
    report = {'schema': 'cicada.client.apk-packaging-audit.v1', 'artifacts': reports,
              'scope': 'APK bytes, ZIP entries, ELF sections and Android signature-tool output; '
                       'not runtime, physical-device or universal secret validation'}
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    os.chmod(args.output, 0o600)
    print(json.dumps({'report': str(args.output), 'artifacts': len(reports),
                      'bytes': [item['bytes'] for item in reports]}))


if __name__ == '__main__':
    main()
