import pathlib
import stat
import sys
import time
import zipfile

ZIP_EPOCH = 315532800


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: zipdist.py STAGE_DIR OUT_ZIP EPOCH")
    stage = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    t = time.gmtime(max(int(sys.argv[3]), ZIP_EPOCH))
    date_time = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
    files = sorted(p for p in stage.rglob("*") if p.is_file())
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(stage.parent).as_posix(), date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if path.suffix == ".exe" else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(info, path.read_bytes())


if __name__ == "__main__":
    main()
