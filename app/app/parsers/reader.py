from pathlib import Path
from scapy.all import PcapReader
from app.parsers.core import parse_packet
from app.utils import maybe_decompress
from app.config import PROGRESS_EVERY


def stream_events(path: Path, work_dir: Path, checkpoint: dict, progress_cb=None):
    """Stream a capture and yield normalized events.

    progress_cb supports either packet-only callbacks or richer byte progress.
    When possible, this reader reports bytes read from the capture file so the
    web UI can display a real 0-100 percent progress bar instead of only packet
    counts. This keeps memory usage low because packets are still parsed one at
    a time by Scapy.
    """
    actual = maybe_decompress(path, work_dir)
    processed = int(checkpoint.get('packets', 0))
    total = 0
    total_bytes = actual.stat().st_size if actual.exists() else 0

    # Use an explicit file handle so we can call tell() for byte-level progress.
    with open(actual, 'rb') as fh:
        with PcapReader(fh) as reader:
            for idx, pkt in enumerate(reader):
                if idx < processed:
                    continue
                total = idx + 1
                ts = float(getattr(pkt, 'time', idx))
                for ev in parse_packet(pkt, ts):
                    yield idx, ev
                if progress_cb and idx % PROGRESS_EVERY == 0:
                    try:
                        progress_cb(idx, fh.tell(), total_bytes)
                    except TypeError:
                        progress_cb(idx)
    if progress_cb:
        try:
            progress_cb(total, total_bytes, total_bytes)
        except TypeError:
            progress_cb(total)
