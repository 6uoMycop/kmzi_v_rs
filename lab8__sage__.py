import linecache
from math import trunc
from math import log

def get_prime(index):
    return Integer(linecache.getline('1m.csv', index + 2).split(',')[1])


def factorize(n, m):
    while True:
        xQ = randrange(2, n)
        yQ = randrange(2, n)
        A = randrange(2, n)
        B = (yQ * yQ - xQ * xQ * xQ - A * xQ) % n
        
        E = EllipticCurve(Zmod(n), [A, B])
        Q = E([xQ, yQ])
        
        i = 0
        flag = False
        
        while i <= m:
            p = int(get_prime(i))
            i += 1
            alpha = trunc(float(0.5 * log(n, p)))
            for j in range(alpha):
                try:
                    Q = p * Q
                except ZeroDivisionError as err:
                    print(str(err.args[0].split()) + ' ' + str(p))
                    d = int(gcd(Integer(err.args[0].split()[2]), n))
                    flag = True
                d = d if flag else int(gcd(n, 2 * Q[0]))
                print(d)
                if d > 1 and d < n:
                    return d
            if flag:
                break

#print("Answer " + str(factorize(661643, 5)))
#print("Answer " + str(factorize(239807090315411, 500)))
#print("Answer " + str(factorize(35, 5)))
