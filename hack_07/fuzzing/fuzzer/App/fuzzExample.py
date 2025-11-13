import sys
import afl
import os

# -----------------------------------------
# Collocate qui la funzione di test
# -----------------------------------------
def testFunction(a, b, c):
    # esempio di funzione di test
    print(a + b + c)

def main():
    in_str = sys.stdin.read()  # (1)
    a, b, c = in_str.strip().split(" ")  # (2)
    a = int(a)
    b = int(b)
    c = int(c)
    testFunction(a, b, c)

if __name__ == "__main__":
    afl.init()  # (3)
    main()
    os._exit(0)  # (4)
