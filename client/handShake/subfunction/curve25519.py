# Coding: UTF-8
# https://asecuritysite.com/encryption/python_25519ecdh
# https://datatracker.ietf.org/doc/html/rfc7748#section-5


import sys

# https://datatracker.ietf.org/doc/html/rfc7748#section-5
# ord: 文字のUnicodeに対応する整数値を取得
# 5. The X25519 and X448 Functions
gf = 2 ** 255 - 19
P = 2 ** 255 - 19
a24 = (486662-2) // 4
A24 = 121665

def decode_little_endian(private_key_list):
    if sys.version_info.major > 2:
        xrange = range

    return sum([private_key_list[i] << 8 * i for i in xrange(32)])

def decode_scalar25519(private_key):
    private_key_list = [unicode_integer for unicode_integer in private_key]
    private_key_list[0] &= 248
    private_key_list[31] &= 127
    private_key_list[31] |= 64

    return decode_little_endian(private_key_list)


def cswap(swap_value, x_2, x_3):
    dummy = swap_value * ((x_2 - x_3) % gf)
    x_2 = (x_2 - dummy) % gf
    x_3 = (x_3 + dummy) % gf

    return x_2, x_3

def x25519(k, u):
    if sys.version_info.major > 2:
        xrange = range

    x_1 = u
    x_2 = 1
    x_3 = u
    z_2 = 0
    z_3 = 1
    swap_value = 0

    for i in reversed(xrange(255)):
        k_i = (k >> i) & 1
        swap_value ^= k_i
        x_2, x_3 = cswap(swap_value, x_2, x_3)
        z_2, z_3 = cswap(swap_value, z_2, z_3)
        swap_value = k_i

        a = (x_2 + z_2) % gf
        aa = (pow(a, 2)) % gf

        b = (x_2 - z_2) % gf
        bb = (pow(b, 2)) % gf

        e = (aa - bb) % gf
        c = (x_3 + z_3) % gf
        d = (x_3 - z_3) % gf

        da = (d * a) % gf
        cb = (c * b) % gf

        x_3 = (((da + cb) % gf)**2) % gf

        z_3 = (x_1 * (((da - cb) % gf)**2) % gf) % gf
        x_2 = (aa * bb) % gf

        z_2 = (e * ((aa + (a24 * e)  % gf)  % gf)) % gf

    x_2, x_3 = cswap(swap_value, x_2, x_3)
    z_2, z_3 = cswap(swap_value, z_2, z_3)

    return (x_2 * pow(z_2, gf - 2, gf)) % gf


def clamp(decode_scalar25519_value):
    decode_scalar25519_value &= ~7
    decode_scalar25519_value &= ~(128 << 8 * 31)
    decode_scalar25519_value |= 64 <<  8 * 31

    return decode_scalar25519_value