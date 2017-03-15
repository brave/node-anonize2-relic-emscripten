# Anonize2 Library


*** This is a work in progress. ***

Directory structure:
```
├── relic/
│   ├── ...
├── relic-darwin/
│   ├── setup.sh
│   ├── <...other files...>		
├── relic-linux/
│   ├── setup.sh		
│   ├── <...other files...>		
├── anon
│   ├── anon.cpp
│   ├── anon.h
│   ├── ...
```

# Relic library
This Anonize library uses the relic crypto library to implement the bilinear pairings.  The directory structure that I use has the `RELIC` library at the same level as the `anon` library.  Relic needs to be configured and compiled for the right platform.   The project has been tested with commit `dbfd28803e0397707177e0f2c9aa6ed3ef24fdee` of the [RELIC library](https://github.com/relic-toolkit/relic).

```sh
$ git clone ...
$ mkdir relic-darwin
$ cd relic-darwin
$ cmake ../relic -G "Unix Makefiles"  \
		   -DCHECK=on -DDEBUG=on \
		   -DARCH=X64 -DALIGN=16 \
		   -DOPSYS=MACOSX -DSTLIB=ON -DSHLIB=OFF \
		   -DALLOC=AUTO \
		   -DCOLOR=OFF -DSEED=UDEV \
		   -DWITH="BN;DV;FP;FPX;EP;EPX;PP;MD" \
		   -DBN_PRECI=256 -DBN_MAGNI=DOUBLE  \
		   -DBENCH=0 -DTESTS=0
$ cd ..
```

The `setup.sh` file in `relic-darwin` just has that cmake command in it.

### For linux
I believe the following will setup `relic` for linux.
```sh
$ cmake ../relic -G "Unix Makefiles"  \
        -DCHECK=on -DDEBUG=on \
        -DARCH=X64 -DALIGN=16 \
        -DOPSYS=LINUX \
        -DCOLOR=OFF -DSEED=UDEV \
        -DWITH="BN;DV;FP;FPX;EP;EPX;PP;MD" \
        -DBN_PRECI=256 -DBN_MAGNI=DOUBLE 
```


# Compiling `libanon.a`

```sh
$ cd anon
$ make libanon.a
$ make anontest
```

# Anontest

Running `anontest` tests the methods exported in `anon.h` with a standard flow of calls. A new master key is generated, a user credential is created, a survey is created, the user responds to the survey, and the response message is verified.

# Note
The description of the protocol can be found in the anon.pdf file. The [anonize site](https://anonize.org/) uses an older version of this protocol.


### Diagrams


```sequence
Note left of User: registerUserMessage
User->RA: userid, proof
Note right of RA: registerServerResponse
RA-->User: sigma, rr
Note left of User: registerUserFinal
```



