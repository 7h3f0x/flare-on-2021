#!/usr/bin/env python3

p8 = lambda x : bytes([x & 0xff])

def decrypt_buf(buf: bytes, password: bytes) -> bytes:
    res = b""
    for i, (v1, v2) in enumerate(zip(buf, password)):
        tmp = v1 ^ v2
        tmp = ((tmp << i) | (tmp >> (8 - i))) - i
        res += p8(tmp)
    return res

def decrypt_file(fname: str, password: bytes) -> bytes:
    out = b""
    with open(fname, "rb") as h:
        while True:
            buf = h.read(8)
            if not buf:
                break
            res = decrypt_buf(buf, password)
            out += res
    return out

png_header = bytes.fromhex("89504e470d0a1a0a")

def get_password() -> bytes:
    with open('./Files/capa.png.encrypted', "rb") as h:
        enc_header = h.read(8)
    out = b""
    for i, (v1, v2) in enumerate(zip(enc_header, png_header)):
        # tmp = (v1 + i) & 0xff
        # tmp = (tmp << (8 - i) | tmp >> i) & 0xff
        # out += p8(tmp ^ v2)
        for b in range(256):
            tmp = b ^ v1
            tmp = (((tmp << i) | (tmp >> (8 - i))) - i) & 0xff
            if tmp == v2:
                out += p8(b)
                break



    return out

password = get_password()
print(password)


# with open('./a.png', "wb") as f:
#     f.write(decrypt_file('./Files/capa.png.encrypted', password))

