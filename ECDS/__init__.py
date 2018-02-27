
class Point:

    def __init__(self, x, y, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
        assert self in curve, f"Point {x}, {y} not in curve"

    def __add__(self, other):
        assert self.curve == other.curve, 'Cannot add points on different curves'
        return self.curve.point_add(self, other)

    def __mul__(self, other: int):
        assert isinstance(other, int), 'Multiplication is only defined between a point and an integer'
        return self.curve.point_mul(self, other)

    def __repr__(self):
        return f"Point({self.x}, {self.y}, {self.curve.name})"

    def __eq__(self, other):
        return self.x % self.curve.P == other.x % self.curve.P and self.y % self.curve.P == other.y % self.curve.P


class Curve:

    def __init__(self, P, a, b, G, N, name):
        self.P = P
        self.a = a
        self.b = b
        self.G = Point(*G, self)
        self.N = N
        self.name = name

    def point_add(self, p, q):
        """https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition"""
        P = self.P
        if p == q:
            lam = (3 * p.x * p.x) * pow(2 * p.y % P, P - 2, P)
        else:
            lam = pow(q.x - p.x, P - 2, P) * (q.y - p.y) % P

        rx = lam ** 2 - p.x - q.x
        ry = lam * (p.x - rx) - p.y
        return Point(rx % P, ry % P, curve=self)

    def point_mul(self, p, d):
        n = p
        q = None

        for i in reversed(format(d, 'b')):
            if i == '1':
                if q is None:
                    q = n
                else:
                    q = self.point_add(q, n)

            n = self.point_add(n, n)
        return q

    def __contains__(self, point):
        return point.y ** 2 % self.P == (point.x ** 3 + self.a * point.x + self.b) % self.P

    def f(self, x):
        """Compute y**2 = x^3 + ax + b in field FP"""
        return (x ** 3 + self.a * x + self.b) % self.P


