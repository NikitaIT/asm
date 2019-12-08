import numpy as np
import sympy

# https://ru.bmstu.wiki/%D0%9A%D1%80%D0%B8%D0%BF%D1%82%D0%BE%D1%81%D0%B8%D1%81%D1%82%D0%B5%D0%BC%D0%B0_%D0%A0%D0%B0%D0%B1%D0%B8%D0%BD%D0%B0
class Rabin:
    def encript(self, p, q, m):
        return rabin_encript(p, q, m)
    def decript(self, p, q, c):
        return rabin_decript(p, q, c)

def rabin_encript(p, q, m):
    validateArgs(p, q)
    n = p * q
    return pow(m, 2) % n


def rabin_decript(p, q, c):
    n = p * q

    def pow4(base, mod):
        return pow(base, (mod + 1) // 4, mod)

    m1 = pow4(c, p)
    m2 = -pow4(c, p)
    m3 = pow4(c, q)
    m4 = -pow4(c, q)
    a = q * pow(q, p - 2, p)
    b = p * pow(p, q - 2, q)
    return (a * np.array([m1, m1, m2, m2]) + b * np.array([m3, m4, m3, m4])) % n


def validateArgs(p, q):
    def is_3mod4(x):
        return x % 4 == 3
    throwIf(not sympy.isprime(q), f'{q} shold be prime')
    throwIf(not sympy.isprime(p), f'{p} shold be prime')
    throwIf(not is_3mod4(p), f'{p} !== 3 (mod 4')
    throwIf(not is_3mod4(q), f'{q} !== 3 (mod 4')

def throwIf(x, s):
    if x:
        raise Exception(s)


p = 11
q = 7
m = 20
c = rabin_encript(p, q, m)
print(m, " in ", *rabin_decript(p, q, c)) # 20  in  64 20 57 13
