from typing import Union, Type

__all__ = ['Curve']

class AbstractPoint:

    def __init__(self, x, y, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
        if curve:
            assert self in curve, f"Point {x}, {y} not in curve"

    def __add__(self, other):
        assert self.curve == other.curve, 'Cannot add points on different curves'
        return self.curve.point_add(self, other)

    def __sub__(self, other):
        return self + (other * -1)

    def __mul__(self, other: int):
        assert isinstance(other, int), 'Multiplication is only defined between a point and an integer'
        return self.curve.point_mul(self, other)

    def __repr__(self):
        return f"Point({self.x}, {self.y}, {self.curve.name})"

    def __eq__(self, other):
        return self.x % self.curve.P == other.x % self.curve.P and self.y % self.curve.P == other.y % self.curve.P

    def is_inf(self):
        return self.x is None and self.y is None and self.curve is None

INF = AbstractPoint(None, None, None)
assert INF.is_inf()
POINT = Type[AbstractPoint]

class Curve:

    Point = AbstractPoint

    def __init__(self, P, a, b, G, N, name):
        self.P = P
        self.a = a
        self.b = b
        self.__G = G
        self.N = N
        self.name = name

    @property
    def G(self):
        if not hasattr(self, '_G'):
            self._G = self.Point(*self.__G)
        return self._G

    def point_add(self, P1: POINT, P2: POINT):
        """https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition"""
        P = self.P
        if P1 is INF:
            return P2
        if P2 is INF:
            return P1

        if (P1.x == P2.x) and (P1.y != P2.y):
            return INF

        if P1 == P2:
            lam = (3 * P1.x * P1.x * pow(2 * P1.y, P - 2, P)) % P
        else:
            lam = (pow(P2.x - P1.x, P - 2, P) * (P2.y - P1.y)) % P

        rx = lam ** 2 - P1.x - P2.x
        ry = lam * (P1.x - rx) - P1.y
        return self.Point(rx % P, ry % P)

    def point_mul(self, P: POINT, d: int):
        d = d % self.N
        R = INF
        for i in range(256):
            if (d >> i) & 1:
                R = self.point_add(R, P)
            P = self.point_add(P, P)
        return R

    def __contains__(self, point: POINT):
        return point.y ** 2 % self.P == (point.x ** 3 + self.a * point.x + self.b) % self.P

    def f(self, x: int):
        """Compute y**2 = x^3 + ax + b in field FP"""
        return (x ** 3 + self.a * x + self.b) % self.P



