#!/usr/bin/env python3
"""Run pinned sherpa-onnx models on a public PCM WAV, without saving audio/text."""
import argparse
import json
import resource
import time
import wave

import numpy as np
import sherpa_onnx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["sensevoice", "paraformer"], required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--tokens", required=True)
    parser.add_argument("--wav", required=True)
    args = parser.parse_args()
    with wave.open(args.wav, "rb") as wav:
        assert wav.getnchannels() == 1 and wav.getsampwidth() == 2
        sample_rate = wav.getframerate()
        duration = wav.getnframes() / sample_rate
        samples = np.frombuffer(wav.readframes(wav.getnframes()), dtype="<i2").astype(np.float32) / 32768

    started = time.monotonic()
    if args.engine == "sensevoice":
        recognizer = sherpa_onnx.OfflineRecognizer.from_sense_voice(
            model=args.model, tokens=args.tokens, num_threads=2, use_itn=True)
    else:
        recognizer = sherpa_onnx.OfflineRecognizer.from_paraformer(
            paraformer=args.model, tokens=args.tokens, num_threads=2)
    loaded = time.monotonic()
    stream = recognizer.create_stream()
    stream.accept_waveform(sample_rate, samples)
    recognizer.decode_stream(stream)
    finished = time.monotonic()
    print(json.dumps({
        "engine": args.engine,
        "duration_s": round(duration, 3),
        "load_s": round(loaded - started, 3),
        "decode_s": round(finished - loaded, 3),
        "rtf": round((finished - loaded) / duration, 3),
        "rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "text": stream.result.text,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
