from .primes import random_prime, random_coprime


def xgcd(b, n):
    """Takes positive integers a, b as input, and return a triple (g, x, y), such that ax + by = g = gcd(a, b)"""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def mulinv(b, n):
    """An application of extended GCD algorithm to finding modular inverses"""
    g, x, _ = xgcd(b, n)
    assert g == 1, 'Numbers must be coprimes'
    return x % n


def generate_keypair(bits):
    p = random_prime(bits//2)
    q = random_prime(bits//2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random_coprime(phi)  # alternative e = 65537

    d = mulinv(e, phi)

    private = (d, n)
    public = (e, n)
    return private, public

