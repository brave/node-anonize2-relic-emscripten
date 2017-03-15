#!/bin/sh

BUILD=anonize2/relic-build

rm -rf $BUILD
mkdir  $BUILD
cd     $BUILD

cmake ../relic -G "Unix Makefiles"  \
    -DCMAKE_TOOLCHAIN_FILE="`brew --prefix`/Cellar/emscripten/1.37.1/libexec/cmake/Modules/Platform/Emscripten.cmake" \
    -DCHECK=OFF -DDEBUG=OFF -DVERBS=ON \
    -DARCH=NONE -DWORD=32 -DSHLIB=OFF -DSTLIB=on -DTESTS=0 -DBENCH=0 \
    -DOPSYS=NONE  \
    -DCOLOR=OFF -DSEED=UDEV -DWITH="BN;DV;FP;FPX;EP;EPX;PP;MD" \
    -DBN_PRECI=256 -DBN_MAGNI=DOUBLE 
make
exit

emcc -O2 -DNOMAIN -DRELIC_LIBRARY -I../src -I./include -I../relic/include ../anon.cpp -o anonize2.bc
emcc -O2 ../sha2.cpp -o sha2.bc

emcc -O2 anonize2.bc sha2.bc lib/librelic_s.a -o anonize2-jumbo.js -s EXPORTED_FUNCTIONS="['_initAnonize','_printParams','_makeCred','_makeKey','_createSurvey','_extendSurvey','_freeSurvey','_freeSurveyResponse','_registerUserMessage','_registerServerResponse','_registerUserFinal','_submitMessage','_verifyMessage']" --memory-init-file 0

emcc -O2 anonize2.bc sha2.bc lib/librelic_s.a -o anonize2.js -s EXPORTED_FUNCTIONS="['_initAnonize','_printParams','_makeCred','_makeKey','_createSurvey','_extendSurvey','_freeSurvey','_freeSurveyResponse','_registerUserMessage','_registerServerResponse','_registerUserFinal','_submitMessage','_verifyMessage']" --memory-init-file 1
