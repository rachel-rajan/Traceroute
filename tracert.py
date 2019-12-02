# -*- coding: utf-8 -*-
"""
@author: Rachel Rajan
"""
from rawsocket import RawSocket
import time

def main():
    startTime = time.time()
    remotehost = "www.google.com"
    print(remotehost)
    raw = RawSocket(remotehost)
    raw.trace()
    end_time = time.time()
    print("Total execution time(ms) = ",(end_time - startTime))
    print("Trace complete!!!")
# call main() method:
if __name__ == "__main__":
    main()
