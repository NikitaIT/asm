import numpy as np

#https://tproger.ru/translations/diffie-hellman-key-exchange-explained/
class DH_Endpoint():
    def __init__(self, public_key1, public_key2, private_key):
        self.public_key1 = public_key1
        self.public_key2 = public_key2
        self.private_key = private_key
        self.full_key = None

    def generate_partial_key(self):
        return (self.public_key1 ** self.private_key) % self.public_key2

    def generate_full_key(self, partial_key_r):
        self.full_key = (partial_key_r ** self.private_key) % self.public_key2
        return self.full_key

    def encrypt(self, message):
        return self.simple_sub(message, +1)

    def decrypt(self, encrypted_message):
        return self.simple_sub(encrypted_message, -1)

    # простая замена, тут может быть любой алгоритм
    def simple_sub(self, message, sign):
        m2 = ""
        for c in message:
            m2 += chr(ord(c) + np.sign(sign) * self.full_key)
        return m2


def sendKeyFromTo(type, key, me, name):
    print("send ", type ," key: ", key, " from", me, " to ", name)

message = "This is a very very very secret message"
Sadat_public = 197
Sadat_private = 199
Michael_public = 151
Michael_private = 157
# мы согласились использовать мой открытый ключ в качестве основы, а его открытый ключ – в качестве расчета «по модулю».
sendKeyFromTo("public", Sadat_public, "Sadat", "Michael")
Sadat = DH_Endpoint(Sadat_public, Michael_public, Sadat_private)
s_partial=Sadat.generate_partial_key()
sendKeyFromTo("partial", s_partial, "Sadat", "Michael")

sendKeyFromTo("public", Michael_public, "Michael", "Sadat")
Michael = DH_Endpoint(Sadat_public, Michael_public, Michael_private)
m_partial=Michael.generate_partial_key()
sendKeyFromTo("partial", m_partial, "Michael", "Sadat")

m_full1=Sadat.generate_full_key(m_partial)
print(m_full1) #75
m_full=Michael.generate_full_key(s_partial)
print(m_full) #75
