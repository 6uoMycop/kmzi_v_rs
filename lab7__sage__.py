from time import time

def pohlig_hellman(P, Q, q, factors):
    d_, moduli = [], []
    for fact in factors:
        p, a = fact[0], fact[1]
        moduli.append( p^a )
        z_ = [ 0 ]
        P_0 = (ZZ( q/p )) * P
        d_.append( 0 )
        for i in range( a ):
            Q_ = Q
            for j in range( 1, i + 1 ):
                Q_ -= z_[j - 1] * (p^(j - 1)) * P
            Qi = (ZZ( q/(p^(i + 1))) ) * Q_
            z_.insert( i, discrete_log(Qi, P_0, operation='+') )
            d_[-1] = d_[-1] + z_[i] * (p^i)
    return crt( d_, moduli )


n = 67132857362092776134801902741
d = 165656009925479929
A, B = 18728829716168259351043591227, 24276978234606192640778174505
E = EllipticCurve( GF(n), [A, B] )
P = E([22848554082758903856724580217, 41323162614334326744868329071])
Q = d * P
q = P.order()
factors = q.factor()

print( 'd =', d )
print('A, B:', A, B)
print( 'P =', P )
print( 'q =', q )
print( 'q =', factors )

for i in range(100):
    start = time()
    res = pohlig_hellman( P, Q, q, factors )
    start -= time()
    print( 'Result:', d == res )
    print( 'Time (ms):', -start * 1000)
