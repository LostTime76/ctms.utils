import config
import time
from pathlib import Path
from ctms.binaries import TiCoffImage

p = Path(Path(__file__).parent, "test.out")

s = time.perf_counter()

c = TiCoffImage.from_file(p)

o = c.to_bin(0x80_000, 1024*1024)

Path(Path(__file__).parent, "test.bin").write_bytes(o)

e = time.perf_counter()
print(e - s)

ss = ""
for s in c.symtab:
	ss += f"{s.name}, {s.sect}, {hex(s.value)} \n"

ss = ""
for s in c.sectab:
	ss += f"{s.name}, {hex(s.laddr)}, {hex(s.eaddr)}, {len(s._data)} \n"

Path(Path(__file__).parent, "blah.txt").write_text(ss)