"""Default-off bounded sibling codec. No Runtime or provider launcher."""
import argparse
import json
import os
from pathlib import Path
from native_request_observer import validate_io_diagnostic, validate_record

MAX_ROWS = 16
MAX_BYTES = 32768
WATERMARK_KEYS = {'schema', 'admitted', 'successful', 'failed', 'sealed', 'drained'}


def canonical(record):
    validate_io_diagnostic(record)
    raw = (json.dumps(record, sort_keys=True, separators=(',', ':'))+'\n').encode()
    if len(raw) > 2048:
        raise ValueError('BOUNDS')
    return raw


class IOSink:
    """Optional evidence failure is isolated from the original observer sink."""
    def __init__(self, path):
        self.path = Path(path)
        self.successful = 0
        self.failed = False
        self.output = None
        try:
            self.output = os.fdopen(os.open(self.path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'wb')
        except BaseException:
            self.failed = True

    def __call__(self, record):
        try:
            raw = canonical(record)
            if self.failed or self.output is None or self.successful >= MAX_ROWS or record['sequence'] != self.successful:
                raise ValueError('SEQUENCE')
            if self.output.write(raw) != len(raw):
                raise ValueError('SHORT_WRITE')
            self.output.flush()
            self.successful += 1
        except BaseException:
            self.failed = True

    def seal(self, observer, drain):
        # Caller has completed the existing quiesce. Never add another wait.
        sealed = False
        try:
            if self.output is not None:
                self.output.flush()
                os.fsync(self.output.fileno())
                self.output.close()
            sealed = drain.get('drained') is True and not self.failed and self.successful == observer.io_sequence
        except BaseException:
            self.failed = True
        return dict(schema='cicada.native-observer-io-watermark.v1', admitted=observer.io_sequence,
                    successful=self.successful, failed=self.failed, sealed=sealed, drained=drain.get('drained') is True)


def validate_export(raw, watermark):
    if (type(raw) is not bytes or len(raw)>MAX_BYTES or type(watermark) is not dict or
            set(watermark)!=WATERMARK_KEYS or watermark['schema']!='cicada.native-observer-io-watermark.v1'):
        raise ValueError('SCHEMA')
    for key in ('admitted','successful'):
        if type(watermark[key]) is not int or not 0<=watermark[key]<=MAX_ROWS:
            raise ValueError('COUNT')
    if any(type(watermark[k]) is not bool for k in ('failed','sealed','drained')) or watermark['failed'] or not watermark['sealed'] or not watermark['drained']:
        raise ValueError('UNSEALED')
    rows=[]
    for line in raw.splitlines(keepends=True):
        if len(rows)>=MAX_ROWS or len(line)>2048:
            raise ValueError('BOUNDS')
        record=json.loads(line)
        if canonical(record)!=line or record['sequence']!=len(rows):
            raise ValueError('CANONICAL_SEQUENCE')
        rows.append(record)
    if len(rows)!=watermark['admitted'] or len(rows)!=watermark['successful']:
        raise ValueError('COUNT')
    return rows


def join_records(rows, originals, expected_thread, actual_turns, watermark=None):
    """Ordinal association, not guessed POST ordinal (pre-send failure retains count)."""
    try:
        if type(rows) is not list or type(originals) is not list or len(rows)>MAX_ROWS or len(originals)>MAX_ROWS:
            raise ValueError('BOUNDS')
        validate_export(b''.join(canonical(row) for row in rows),watermark)
        if len(rows)!=len(originals):
            raise ValueError('JOIN')
        previous=0
        for index,(row,original) in enumerate(zip(rows,originals)):
            validate_io_diagnostic(row); validate_record(original)
            if (row['sequence']!=index or row['POST_before']!=previous or
                    row['POST_after']!=original['outbound_POST_count'] or
                    original['thread']!=expected_thread or not original['runtime_thread_bound'] or
                    original['association_provenance']!='CORE_METADATA' or
                    (original['thread'],original['turn']) not in set(actual_turns)):
                raise ValueError('JOIN')
            previous=row['POST_after']
        return {'status':'COMPLETE' if rows else 'UNKNOWN','records':rows, 'native_acceptance':'UNCHANGED',
                'provider_acceptance':'NOT_MEASURED'}
    except Exception:
        return {'status':'UNKNOWN','records':[], 'native_acceptance':'UNCHANGED','provider_acceptance':'NOT_MEASURED'}


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--export',action='store_true')
    parser.add_argument('--records'); parser.add_argument('--watermark')
    args=parser.parse_args(argv)
    if not args.export:
        print(json.dumps({'status':'NONAUTH','effects':False}))
        return 0
    result={'status':'UNKNOWN','records':[]}
    try:
        with Path(args.records).open('rb') as stream: raw=stream.read(MAX_BYTES+1)
        with Path(args.watermark).open('rb') as stream: mark=stream.read(1025)
        if len(mark)>1024: raise ValueError('BOUNDS')
        watermark=json.loads(mark)
        result={'status':'COMPLETE','records':validate_export(raw,watermark),'watermark':watermark}
    except Exception:
        pass
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
