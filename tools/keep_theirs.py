import sys
from pathlib import Path

def keep_theirs(path: Path):
    text = path.read_text(encoding='utf-8')
    out_lines = []
    i = 0
    lines = text.splitlines()
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.startswith('<<<<<<<'):
            # skip until =======
            i += 1
            while i < n and not lines[i].startswith('======='):
                i += 1
            # now skip the '=======' line
            i += 1
            # collect theirs until >>>>>>>
            while i < n and not lines[i].startswith('>>>>>>>'):
                out_lines.append(lines[i])
                i += 1
            # skip the >>>>>>> line
            i += 1
        else:
            out_lines.append(line)
            i += 1
    path.write_text('\n'.join(out_lines) + ('\n' if out_lines and not out_lines[-1].endswith('\n') else ''), encoding='utf-8')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: keep_theirs.py <file> [<file> ...]')
        sys.exit(2)
    for p in sys.argv[1:]:
        fp = Path(p)
        if not fp.exists():
            print(f'File not found: {p}', file=sys.stderr)
            continue
        keep_theirs(fp)
        print(f'Processed {p}')
