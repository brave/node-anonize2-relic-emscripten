# Copyright 2015 abhi shelat
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#        http://www.apache.org/licenses/LICENSE-2.0
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

CC=clang++
CFLAGS=-std=c++11 -stdlib=libc++  -fomit-frame-pointer -DNDEBUG -msse2 -mfpmath=sse -march=native


#CFLAGS = -g -O1 -fomit-frame-pointer -DNDEBUG -msse2 -mfpmath=sse -march=native
CFLAGS_WARN=-Wall -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith #-Wswitch-enum -Wstrict-aliasing=2
CFLAGS_ALWAYS = -D_FILE_OFFSET_BITS=64 -fno-operator-names
LDFLAGS =  -lm -lzm $(LIB_DIR) -lgmp -lgmpxx

RELIC_CFLAGS = -I../relic-darwin/include -I../relic/include
RELIC_LDFLAGS = -L../relic-darwin/lib  -lrelic_s

all: libanon.a anontest

dev: CFLAGS += -g -Wall -Isrc -Wall -Wextra $(OPTFLAGS)
dev: all

sha2.o: sha2.cpp sha2.h
	$(CC) -O1 -c sha2.cpp

anoncli: libanon.a anon.h groups.h
	$(CC) $(CFLAGS) -o anoncli -DRELIC_LIBRARY anoncli.cpp  $(RELIC_CFLAGS)  libanon.a $(RELIC_LDFLAGS)

anontest: anontest.cpp libanon.a anon.h groups.h
	$(CC) $(CFLAGS) -g -o anontest -DRELIC_LIBRARY anontest.cpp  $(RELIC_CFLAGS)  libanon.a $(RELIC_LDFLAGS)


libanon.a: anon.cpp sha2.o anon.h groups.h
	$(CC) -static $(CFLAGS) -o anon.o -c -DRELIC_LIBRARY anon.cpp $(RELIC_CFLAGS)
	ar cr libanon.a anon.o sha2.o		

#For MR_PAIRING_BLS curve
#   cl /O2 /GX hibe.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

clean:
	rm *.o anonize anonize256

cleanfile:
	rm	PrivateRA.keytxt PrivateVA.keytxt PublicParameters.key RAToUsernNetworkTraffic  
	rm	UserToRANetworkTraffic UserToVANetworkTraffic  VerificationRA.keytxt VerificationVA.keytxt
		
	
valgrind: dev
	valgrind --leak-check=yes ./anontest
