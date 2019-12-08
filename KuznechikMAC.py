from codecs import getdecoder
from codecs import getencoder
from sys import version_info


xrange = range if version_info[0] == 3 else xrange  # pylint: disable=redefined-builtin

_hexdecoder = getdecoder("hex")
_hexencoder = getencoder("hex")


def hexdec(data):
    """Decode hexadecimal
    """
    return _hexdecoder(data)[0]


def hexenc(data):
    """Encode hexadecimal
    """
    return _hexencoder(data)[0].decode("ascii")


def bytes2long(raw):
    """ Deserialize big-endian bytes into long number

    :param bytes raw: binary string
    :returns: deserialized long number
    :rtype: int
    """
    return int(hexenc(raw), 16)


def long2bytes(n, size=32):
    """ Serialize long number into big-endian bytestring

    :param long n: long number
    :returns: serialized bytestring
    :rtype: bytes
    """
    res = hex(int(n))[2:].rstrip("L")
    if len(res) % 2 != 0:
        res = "0" + res
    s = hexdec(res)
    if len(s) != size:
        s = (size - len(s)) * b"\x00" + s
    return s

def _mac_shift(bs, data, xor_lsb=0):
    num = (bytes2long(data) << 1) ^ xor_lsb
    return long2bytes(num, bs)[-bs:]

def strxor(a, b):
    """ XOR of two strings

    This function will process only shortest length of both strings,
    ignoring remaining one.
    """
    mlen = min(len(a), len(b))
    a, b, xor = bytearray(a), bytearray(b), bytearray(mlen)
    for i in xrange(mlen):
        xor[i] = a[i] ^ b[i]
    return bytes(xor)

def pad_size(data_size, blocksize):
    """Calculate required pad size to full up blocksize
    """
    if data_size < blocksize:
        return blocksize - data_size
    if data_size % blocksize == 0:
        return 0
    return blocksize - data_size % blocksize

def pad2(data, blocksize):
    """Padding method 2 (also known as ISO/IEC 7816-4)

    Add one bit and then fill up with zeros.
    """
    return data + b"\x80" + b"\x00" * pad_size(len(data) + 1, blocksize)


def pad3(data, blocksize):
    """Padding method 3
    """
    if pad_size(len(data), blocksize) == 0:
        return data
    return pad2(data, blocksize)

def mac(encrypter, bs, data):
    """MAC (known here as CMAC, OMAC1) mode of operation

    :param encrypter: Encrypting function, that takes block as an input
    :param int bs: cipher's blocksize
    :param bytes data: data to authenticate

    Implementation is based on PyCrypto's CMAC one, that is in public domain.
    """
    k1, k2 = _mac_ks(encrypter, bs)
    if len(data) % bs == 0:
        tail_offset = len(data) - bs
    else:
        tail_offset = len(data) - (len(data) % bs)
    prev = bs * b'\x00'
    for i in xrange(0, tail_offset, bs):
        prev = encrypter(strxor(data[i:i + bs], prev))
    tail = data[tail_offset:]
    return encrypter(strxor(
        strxor(pad3(tail, bs), prev),
        k1 if len(tail) == bs else k2,
    ))


def _mac_ks(encrypter, bs):
    Rb = 0b10000111 if bs == 16 else 0b11011
    _l = encrypter(bs * b'\x00')
    k1 = _mac_shift(bs, _l, Rb) if bytearray(_l)[0] & 0x80 > 0 else _mac_shift(bs, _l)
    k2 = _mac_shift(bs, k1, Rb) if bytearray(k1)[0] & 0x80 > 0 else _mac_shift(bs, k1)
    return k1, k2
LC = bytearray((
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
))
PI = bytearray((
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5,
    132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235,
    52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
    112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161,
    150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117,
    25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245,
    36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15,
    236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
    96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70,
    146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64,
    134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73,
    76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164,
    45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230,
    244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
))

C = []
PIinv = bytearray(256)
for x in xrange(256):
    PIinv[PI[x]] = x

def gf(a, b):
    c = 0
    while b:
        if b & 1:
            c ^= a
        if a & 0x80:
            a = (a << 1) ^ 0x1C3
        else:
            a <<= 1
        b >>= 1
    return c

# Precalculate all possible gf(byte, byte)
GF = [bytearray(256) for _ in xrange(256)]

for x in xrange(256):
    for y in xrange(256):
        GF[x][y] = gf(x, y)


def L(blk, rounds=16):
    for _ in range(rounds):
        t = blk[15]
        for i in range(14, -1, -1):
            blk[i + 1] = blk[i]
            t ^= GF[blk[i]][LC[i]]
        blk[0] = t
    return blk


def Linv(blk):
    for _ in range(16):
        t = blk[0]
        for i in range(15):
            blk[i] = blk[i + 1]
            t ^= GF[blk[i]][LC[i]]
        blk[15] = t
    return blk

for x in range(1, 33):
    y = bytearray(16)
    y[15] = x
    C.append(L(y))


def lp(blk):
    return L([PI[v] for v in blk])


class GOST3412Kuznechik(object):
    """GOST 34.12-2015 128-bit block cipher Кузнечик (Kuznechik)
    """
    def __init__(self, key):
        """
        :param key: encryption/decryption key
        :type key: bytes, 32 bytes

        Key scheduling (roundkeys precomputation) is performed here.
        """
        kr0 = bytearray(key[:16])
        kr1 = bytearray(key[16:])
        self.ks = [kr0, kr1]
        for i in range(4):
            for j in range(8):
                k = lp(bytearray(strxor(C[8 * i + j], kr0)))
                kr0, kr1 = [strxor(k, kr1), kr0]
            self.ks.append(kr0)
            self.ks.append(kr1)

    def encrypt(self, blk):
        blk = bytearray(blk)
        for i in range(9):
            blk = lp(bytearray(strxor(self.ks[i], blk)))
        return bytes(strxor(self.ks[9], blk))

    def decrypt(self, blk):
        blk = bytearray(blk)
        for i in range(9, 0, -1):
            blk = [PIinv[v] for v in Linv(bytearray(strxor(self.ks[i], blk)))]
        return bytes(strxor(self.ks[0], blk))


class Main:
    key = hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    ciph = GOST3412Kuznechik(key)
    plaintext = ""
    plaintext += "1122334455667700ffeeddccbbaa9988"
    plaintext += "00112233445566778899aabbcceeff0a"
    plaintext += "112233445566778899aabbcceeff0a00"
    plaintext += "2233445566778899aabbcceeff0a0011"
    iv = hexdec("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")

    def test(self):
        k1, k2 = _mac_ks(self.ciph.encrypt, 16)
        print(hexenc(k1), "297d82bc4d39e3ca0de0573298151dc7")
        print(hexenc(k2), "52fb05789a73c7941bc0ae65302a3b8e")
        print(
            hexenc(mac(self.ciph.encrypt, 16, hexdec(self.plaintext))[:8]),
            "336f4d296059fbe3",
        )

def main():
    lamport = Main()
    lamport.test()


if __name__ == "__main__":
    main()
