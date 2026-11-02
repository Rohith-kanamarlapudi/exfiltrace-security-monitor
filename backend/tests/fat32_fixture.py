"""Create a disposable raw FAT32 image, never touch or format a device."""
import struct


def make_image(path):
    sectors, fat_sectors, reserved = 70000, 550, 32
    data_sector = reserved + 2 * fat_sectors
    boot = bytearray(512)
    boot[:11] = b'\xeb\x58\x90MSWIN4.1'
    struct.pack_into('<H', boot, 11, 512)
    boot[13] = 1
    struct.pack_into('<H', boot, 14, reserved)
    boot[16] = 2
    boot[21] = 0xf8
    struct.pack_into('<I', boot, 32, sectors)
    struct.pack_into('<I', boot, 36, fat_sectors)
    struct.pack_into('<I', boot, 44, 2)
    struct.pack_into('<H', boot, 48, 1)
    struct.pack_into('<H', boot, 50, 6)
    boot[64], boot[66] = 0x80, 0x29
    boot[71:82], boot[82:90], boot[510:512] = b'TEST IMAGE ', b'FAT32   ', b'\x55\xaa'
    fat = bytearray(fat_sectors * 512)
    for cluster, value in ((0, 0x0ffffff8), (1, 0x0fffffff), (2, 0x0fffffff), (9, 0x0fffffff)):
        struct.pack_into('<I', fat, cluster * 4, value)
    root = bytearray(512)
    def entry(index, name, cluster, size, deleted=True):
        offset = index * 32
        root[offset:offset + 11] = name
        if deleted:
            root[offset] = 0xe5
        root[offset + 11] = 0x20
        struct.pack_into('<H', root, offset + 26, cluster)
        struct.pack_into('<I', root, offset + 28, size)
    entry(0, b'PLAIN   TXT', 3, 700)
    entry(1, b'FRAG    TXT', 5, 700)
    entry(2, b'OVER    TXT', 9, 100)
    entry(3, b'LIVE    TXT', 9, 100, False)
    with open(path, 'xb') as f:
        f.truncate(sectors * 512)
        f.write(boot)
        f.seek(6 * 512); f.write(boot)
        for pos in (reserved, reserved + fat_sectors):
            f.seek(pos * 512); f.write(fat)
        for cluster, data in {2: root, 3: b'A' * 512, 4: b'B' * 188,
                              5: b'F' * 512, 6: b'X' * 512, 8: b'G' * 188, 9: b'N' * 100}.items():
            f.seek((data_sector + cluster - 2) * 512); f.write(data)
    return {'plain': b'A' * 512 + b'B' * 188, 'fragmented': b'F' * 512 + b'G' * 188,
            'overwrittenOriginal': b'O' * 100}
