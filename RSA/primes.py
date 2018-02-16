import random
import secrets
from math import gcd


def miller_rabin(n, runs=40):
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    if n == 2:
        return True

    # If number is even, it's a composite number
    if not n & 1:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(runs):
        a = random.randrange(3, n - 1, 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    while True:
        n = secrets.randbits(bits)
        if miller_rabin(n):
            return n


def random_coprime(n):
    assert n > 1
    while True:
        e = random.randrange(1, n)
        if gcd(n, e) == 1:
            return e


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