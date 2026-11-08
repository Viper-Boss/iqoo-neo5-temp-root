import struct
img = open(r"Q:\Deepseek\_neo5\firmware\boot.img", "rb").read()
print("magic:", img[:8])
kernel_size = struct.unpack("<I", img[8:12])[0]
kernel_addr = struct.unpack("<I", img[12:16])[0]
ramdisk_size = struct.unpack("<I", img[16:20])[0]
page_size = struct.unpack("<I", img[0x24:0x28])[0]
dt_size = struct.unpack("<I", img[0x28:0x2C])[0]
name = img[0x40:0x50].rstrip(b"\x00")
cmdline = img[0x40+16:0x40+16+512].rstrip(b"\x00")
print(f"kernel_size={kernel_size} kernel_addr=0x{kernel_addr:x}")
print(f"ramdisk_size={ramdisk_size} page_size={page_size} dt_size={dt_size}")
print("name:", name)
print("cmdline:", cmdline[:200])
kernel = img[page_size : page_size+kernel_size]
print("kernel first bytes:", kernel[:16].hex())
print("kernel magic ascii:", kernel[:4])
# arm64 Image magic: "MZ\x00\x00" hmm actually ARM64 kernel Image starts with 0x900? no:
# arm64 Image header: branch instruction (0x140000xx) + "ARM\x64" at offset 4
if kernel[4:8] == b"ARM\x64":
    print("=> RAW ARM64 KERNEL IMAGE")
    open(r"Q:\Deepseek\_neo5\firmware\kernel_Image", "wb").write(kernel)
elif kernel[:2] == b"\x1f\x8b":
    print("=> GZIP COMPRESSED KERNEL")
    open(r"Q:\Deepseek\_neo5\firmware\kernel_gz", "wb").write(kernel)
else:
    print("=> unknown format, saving raw")
    open(r"Q:\Deepseek\_neo5\firmware\kernel_raw", "wb").write(kernel)
