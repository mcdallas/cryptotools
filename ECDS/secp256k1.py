import secrets
from transformations import int_to_bytes, bytes_to_int

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def private_to_public(key):
    x, y = point_mul(G, bytes_to_int(key))
    return b'\x04' + int_to_bytes(x) + int_to_bytes(y)


def generate_keypair():
    private = secrets.token_bytes(32)
    public = private_to_public(private)
    return private, public


def point_add(p, q):
    """https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition"""
    px, py = p
    qx, qy = q
    if p == q:
        lam = (3 * px * px) * pow(2 * py % P, P - 2, P)
    else:
        lam = pow(qx - px, P - 2, P) * (qy - py) % P

    rx = lam**2 - px - qx
    ry = lam * (px - rx) - py
    return rx % P, ry % P


def point_mul(p, d):
    n = p
    q = None

    for i in reversed(format(d, 'b')):
        if i == '1':
            if q is None:
                q = n
            else:
                q = point_add(q, n)

        n = point_add(n, n)
    return q
