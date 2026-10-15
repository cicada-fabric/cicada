#!/usr/bin/env python3
"""Measure an offline Vosk model on a WAV sample; never print or retain raw audio."""
import argparse
import json
import resource
import time
import wave
from pathlib import Path

from vosk import KaldiRecognizer, Model, SetLogLevel


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--wav", type=Path, required=True)
    parser.add_argument("--expected", default="")
    args = parser.parse_args()
    SetLogLevel(-1)
    with wave.open(str(args.wav), "rb") as audio:
        if audio.getnchannels() != 1 or audio.getsampwidth() != 2 or audio.getframerate() != 16000:
            parser.error("sample must be 16 kHz mono 16-bit PCM WAV")
        duration = audio.getnframes() / audio.getframerate()
        started = time.monotonic()
        model = Model(str(args.model))
        loaded = time.monotonic()
        recognizer = KaldiRecognizer(model, 16000)
        pieces = []
        while chunk := audio.readframes(4000):
            if recognizer.AcceptWaveform(chunk):
                pieces.append(json.loads(recognizer.Result()).get("text", ""))
        pieces.append(json.loads(recognizer.FinalResult()).get("text", ""))
        finished = time.monotonic()
    transcript = " ".join(part for part in pieces if part).strip()
    print(json.dumps({
        "model": args.model.name,
        "sample": args.wav.name,
        "duration_seconds": round(duration, 3),
        "load_seconds": round(loaded - started, 3),
        "decode_seconds": round(finished - loaded, 3),
        "real_time_factor": round((finished - loaded) / duration, 3),
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "expected": args.expected,
        "transcript": transcript,
    }, ensure_ascii=False, indent=2))
    return 0 if transcript else 2


if __name__ == "__main__":
    raise SystemExit(main())
