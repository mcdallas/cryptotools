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
