import subprocess
from sympy import mod_inverse


class Cryptor:
    # dir_name with a slash in the end
    def __init__(
            self,
            var_num: int,
            dir_name: str,
            l: int = 10,
            s: int = 1,
            num_of_significant_bits: int = 3,  # number of MSBits which will be guessed in the beginning
            delta_estimate_border: int = 500000):
        self.exe_path     = dir_name + "v" + str(var_num) + "/cryptor_v" + str(var_num) + ".exe"
        self.keyinfo_path = dir_name + "v" + str(var_num) + "/keyinfo_v" + str(var_num) + ".txt"

        self.process = None
        self.stdin   = None
        self.stdout  = None

        self.interactions = 0

        self.all_time = 0

        # Parameters:
        self.l: int = l
        self.s: int = s
        self.delta_border = delta_estimate_border  # where we assume if q_i = 0 or 1
        self.n: int = 0
        self.e: int = 0
        self.d: int = 0
        self.p: int = 0  # n = pq
        self.q: int = 0
        self.phi_n: int = 0  # = (p-1)(q-1)
        self.len_n: int = 0  # number of bits in n
        self.len_factor: int = 0  # |n|//2 -- length of p and q
        self.R: int = 0  # R for Montgomery method
        self.R_inv_n: int = 0  # precomputed R^{-1}(mod n) for attack
        self.msb: int = num_of_significant_bits

        with open(self.keyinfo_path, 'r') as file:
            self.n = int(file.readline().split()[2], 16)
            self.e = int(file.readline().split()[2], 2)

        self.len_n = len("{0:b}".format(self.n))
        self.len_factor = self.len_n // 2

        # w = self.len_n + 1  # R = 2^w, R > N
        self.R = 1 << self.len_factor
        self.R_inv_n = mod_inverse(self.R, self.n)

        print("N =   " + str(self.n))
        print("E =   " + str(self.e))
        print("|N| = " + str(self.len_n) + " bits. Assume |p| = |q| = |N|/2 = " + str(self.len_factor) + " bits")
        print("R =   " + str(self.R))

    def timing_attack_alg(self, g: int, index: int):
        T_g  = 0
        T_g_ = 0
        # message = 0

        # 1 # Set next bit of number g to 1:
        g_ = g + (1 << index)

        # 2 #
        for i in range(self.l):
            # 2.1 #
            u_g  = ((g  + i) * self.R_inv_n) % self.n
            u_g_ = ((g_ + i) * self.R_inv_n) % self.n

            # 2.2 # Measure average decryption time for u_gi and u_g_i
            T_g  += self.interact_wrapper(u_g)
            T_g_ += self.interact_wrapper(u_g_)

        # 3 #
        delta = abs(T_g - T_g_)
        # return self.eval_current_delta(delta)
        if delta < self.delta_border:
            print("1 " + str(index) + "\t" + str(delta))
            retval = 1
        else:
            print("0 " + str(index) + "\t" + str(delta))
            retval = 0

        return retval

    def execute_attack(self):
        # find MSB
        time_min = 10000000000000000
        for k in range(1 << (self.msb - 1)):
            # initialize q
            q = 1 << (self.len_factor - 1)
            # guess given number of bits
            q |= k << (self.len_factor - self.msb)

            # measure minimal time
            _, time = self.interact(q)

            if time < time_min:
                time_min = time
                self.q = q

        print('Initial value of q: {:b}'.format(self.q))

        # find remaining bits
        for i in reversed(range(self.len_factor - self.msb)):
            self.q += self.timing_attack_alg(self.q, i) << i

        self.p = self.n // self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.d = mod_inverse(self.e, self.phi_n)

        print("Attack finished")
        print("Factors of N:")
        print("p = " + hex(self.p))
        print("q = " + hex(self.q))
        print("----")
        if self.p * self.q != self.n:
            print("Error - wrong result!")
            print("----")
            return None, None
        print("SUCCESS")
        print("----")
        print("Attack performance:")
        print("Number of interactions = " + str(self.interactions))
        print("Overall time (returned by external executable) = " + str(self.all_time))

        self.close()  # terminate subprocess

        return self.q, self.d

    def run(self):
        self.process = subprocess.Popen(args=self.exe_path, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        self.stdout  = self.process.stdout
        self.stdin   = self.process.stdin

    # returns average time for s interactions
    def interact_wrapper(self, c):
        time_avg = 0

        for i in range(self.s):
            message, time = self.interact(c)
            time_avg += time

        self.all_time += time_avg

        time_avg /= self.s

        return time_avg

    def interact(self, c):
        self.interactions += 1

        line = "{0:X}\r\n".format(c).encode()
        self.stdin.write(line)
        self.stdin.flush()

        time = int(self.stdout.readline())
        message = int(self.stdout.readline().strip(), 16)

        return message, time

    def close(self):
        if self.process:
            self.process.kill()


if __name__ == '__main__':
    cryptor = Cryptor(var_num=3, dir_name="variants/", num_of_significant_bits=3, l=10, s=1)
    cryptor.run()
    cryptor.execute_attack()

