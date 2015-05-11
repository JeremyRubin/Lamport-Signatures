import os
from hashlib import sha256
from bitstring import BitArray
def h(a):
    return sha256(a).digest()
class PubKey:
    def __init__(self, privateKey=None, publicKey=None):
        if privateKey == None and publicKey == None:
            raise ValueError("No Key Provided")

        if privateKey != None:
            self.publicKey = map(lambda (a,b): (h(a), h(b)), privateKey)

        if publicKey != None:
            self.publicKey = self.publicKey
    def raw(self):
        return self.publicKey

    def verify(self, msg, sig):
        if len(sig) != 256:
            return False
        sigHash = map(h, sig)
        for sigHash, (keyHash0, keyHash1), bit in zip(sigHash, self.publicKey, BitArray(bytes=h(msg)).bin):
            if bit == "0":
                if sigHash != keyHash0:
                    return False
            elif bit == "1":
                if sigHash != keyHash1:
                    return False
                
        return True
            
    def hash(self):
        return h("".join([key0+key1 for key0, key1 in self.publicKey]))
                
class NewKeyPair:
    def __init__(self, rng = os.urandom):
        self.privateKey = [(rng(32), rng(32)) for i in xrange(256)]
        self.publicKey = PubKey(privateKey = self.privateKey)
    def sign(self, msg):
        signature = []
        for (key0, key1), bit in zip(self.privateKey, BitArray(bytes=h(msg)).bin):
            if bit == "0":
                signature.append(key0)
            elif bit == "1":
                signature.append(key1)
        self.privateKey = []
        return signature
    def getPubKey(self):
        return self.publicKey
        
                
class CSRNG:
    def __init__(self):
        self.seeded = True
        self._seed = ""
        self.n = 0
    def seed(self, x):
        self._seed =x
    def get32bytes(self):
        self.n +=1
        return h(self._seed + str(self.n).zfill(20))
    def getbytes(self,n):
        if n > 32:
            return self.get32bytes() + self.getbytes(n-32)
        elif n <= 32:
            return self.get32bytes()[:n]
if __name__ == "__main__":
    rng = CSRNG()
    key = 'x\x06\xa5\xcag\x18O\x01\xe9\x10\xe3\x98n\xca\xd9\xb6\xa9\x9bk\xfe\xee\x14\xd7\x9f\xdf\xb7&\\\xbc\xd9\x1c\xc7'
    print key
    rng.seed(key)
    kp = NewKeyPair(rng.getbytes)
    pk = kp.getPubKey()
    sig = kp.sign("hello")
    print all(not pk.verify("hello%i"%i, sig) for i in xrange(0,10))
    print pk.verify("hello", sig)


