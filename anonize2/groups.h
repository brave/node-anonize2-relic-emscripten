// Copyright 2015 abhi shelat
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//        http://www.apache.org/licenses/LICENSE-2.0
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

//
//
// This file serves as the interface between the anonize2 code and the underlying
// eliptic curve implementation that is used.  The anonize2 code only makes use of the
// functions in this file to perform its group and group input/output operations.
//
// To switch to a different number-theory library, one need only re-implement the
// functions in this interface file.  This file currently uses the relic implementation.
//
// This library purposefully avoids C++ idioms to the extent possible in order to
// maintain link-compatibility with programs that easily handle C interface-linking
// such as GO and Java Native Interface.
//
//
// aas
//
//
// define either ATE_PAIRING_LIBRARY or RELIC_LIBRARY in the makefile


extern "C" {
#include <fcntl.h>
#include <unistd.h>
#include "sha2.h"
}

#include <iostream>
#include <fstream>
#include <sstream>

//using namespace std;

void rand(char* buf, int sz) {
	int rr = open("/dev/urandom", O_RDONLY);
	if (rr<0 || read(rr, buf, sz) != sz) {
		fprintf(stderr,"Could not read %d byes from /dev/urandom. Abort.\n",sz);
	}
	close(rr);
}

static inline void H(sha256_ctx ctx[1], std::string s) {
	sha256_hash((unsigned char*)s.c_str(), s.length(), ctx);
}


#ifdef RELIC_LIBRARY
// ##############################################################################################
// ##############################################################################################
// ########################### RELIC VERSION        #############################################
// ##############################################################################################
// ##############################################################################################
// ##############################################################################################

extern "C" {
#include "relic.h"
#include "relic_conf.h"
}

typedef struct _big {
	bn_t k;
} Big;

typedef struct _G1 {
	ep_t  g;
} G1;

typedef struct _G2 {
	ep2_t g;
} G2;

typedef struct _GT {
	fp12_t g;
} GT;

void rand_int(Big& k) { 
	bn_new(k.k);
	bn_rand(k.k, BN_POS, 256);
}

static inline void set_int(Big& k, const char* cmsg, int len) {
	bn_new(k.k);

	uint8_t buf[BN_PRECI/8];
	memset(buf,0, BN_PRECI/8);
	memcpy(buf,cmsg, (len>(BN_PRECI/8) ? (BN_PRECI/8) : len) );

	bn_read_bin(k.k, (const uint8_t*)buf, BN_PRECI/8);
	memset(buf,0,BN_PRECI/8);
}

static inline void zero(Big& k) {
	bn_new(k.k);	
}


static inline void zero(G1& g) {
	ep_null(g.g);
	fp_zero(g.g->x);
	fp_zero(g.g->y);
	fp_zero(g.g->z);
	g.g->norm = 1;
}

static inline void zero(G2& g) {
	ep2_null(g.g);
	fp2_zero(g.g->x);
	fp2_zero(g.g->y);
	fp2_zero(g.g->z);	
	g.g->norm = 1;
}


static inline void copy(G1& dest, G1& src) {
	ep_copy(dest.g, src.g);
}

static inline void copy(G2& dest, G2& src) {
	ep2_copy(dest.g, src.g);
}

static inline void pow(GT& y, GT& x, Big& k) {
	fp12_exp(y.g, x.g, k.k);
}

static inline void mult(G1& y, G1& x, Big& k) {
	ep_mul(y.g, x.g, k.k);
}

static inline void mult(G2& y, G2& x, Big& k) {
	ep2_mul(y.g, x.g, k.k);
}

static inline void mult(GT& c, GT& a, GT& b) {
	fp12_mul(c.g, a.g, b.g);
}

// c = a+b
static inline void add(G1& c, G1& a, G1& b) {
	ep_add(c.g, a.g, b.g);
}

static inline void add(G2& c, G2& a, G2& b) {
	ep2_add(c.g, a.g, b.g);
}

static inline void inc(Big& c) {
	bn_add_dig(c.k, c.k, 1);
}

static inline void atepair(GT& t, G2& a, G1& b) {
	ep_t tb; ep2_t ta;
	ep_norm(tb, b.g);
	ep2_norm(ta, a.g);

	fp12_zero(t.g);
	pp_map_k12(t.g, tb, ta);

}

static inline void normalize(G1& a, G1& b) {
	ep_norm(a.g, b.g);
}

static inline bool equal(G1& a, G1& b) {
	return (ep_cmp(a.g, b.g)==CMP_EQ);
}

static inline bool equal(G2& a, G2& b) {
	ep2_t ta, tb;
	ep2_norm(ta, a.g);
	ep2_norm(tb, b.g);

	return (ep2_cmp(ta, tb)==CMP_EQ);
}

static inline bool equal(GT& a, GT& b) {
	return (fp12_cmp(a.g,b.g)==CMP_EQ);
}

static inline bool equal(Big& a, Big& b) {
	return (bn_cmp(a.k,b.k)==CMP_EQ);
}


//
// input/output of group elements
//
std::ostream &operator<<( std::ostream &output, const G1& G ) {
	ep_t t;
	ep_norm(t, G.g);
	char bx[1024], by[1024], bz[1024];
	fp_write_str(bx, 1024, t->x, 64);
	fp_write_str(by, 1024, t->y, 64);
	fp_write_str(bz, 1024, t->z, 64);

    output << bx << " " << by << " " << bz;
    memset(bx, 0, 1024);
    memset(by, 0, 1024);
    memset(bz, 0, 1024);
    return output;            
}

std::ostream &operator<<( std::ostream &output,  const G2& G ) { 
	char bx[1024];
	ep2_t t;
	ep2_norm(t, (ep2_st*)G.g);
	fp_write_str(bx, 1024, t->x[0], 64); output << bx << " ";
	fp_write_str(bx, 1024, t->x[1], 64); output << bx << " ";

	fp_write_str(bx, 1024, t->y[0], 64); output << bx << " ";
	fp_write_str(bx, 1024, t->y[1], 64); output << bx << " ";

	fp_write_str(bx, 1024, t->z[0], 64); output << bx << " ";
	fp_write_str(bx, 1024, t->z[1], 64); output << bx;

    memset(bx, 0, 1024);

    return output;
}

std::ostream &operator<<( std::ostream &output, const Big& k ) { 
	char buf[1024];
	bn_write_str(buf, 1024, k.k, 64);
    output << buf;
    memset(buf, 0, 1024);

    return output;            
}

std::ostream &operator<<( std::ostream &output, const GT& G ) {
	char buf[1024];

	fp_write_str(buf, 1024, (dig_t*)G.g[0][0][0], 64); output << buf << " ";	
	fp_write_str(buf, 1024, (dig_t*)G.g[0][0][1], 64); output << buf << " ";
	fp_write_str(buf, 1024, (dig_t*)G.g[0][1][0], 64); output << buf << " ";	
	fp_write_str(buf, 1024, (dig_t*)G.g[0][1][1], 64); output << buf << " ";
	fp_write_str(buf, 1024, (dig_t*)G.g[0][2][0], 64); output << buf << " ";	
	fp_write_str(buf, 1024, (dig_t*)G.g[0][2][1], 64); output << buf << " ";

	fp_write_str(buf, 1024, (dig_t*)G.g[1][0][0], 64); output << buf << " ";	
	fp_write_str(buf, 1024, (dig_t*)G.g[1][0][1], 64); output << buf << " ";
	fp_write_str(buf, 1024, (dig_t*)G.g[1][1][0], 64); output << buf << " ";	
	fp_write_str(buf, 1024, (dig_t*)G.g[1][1][1], 64); output << buf << " ";
	fp_write_str(buf, 1024, (dig_t*)G.g[1][2][0], 64); output << buf << " ";	
	fp_write_str(buf, 1024, (dig_t*)G.g[1][2][1], 64); output << buf;

	memset(buf,0,1024);	
    return output;            
}


 inline void H(sha256_ctx ctx[1],  GT& egg) {
	uint8_t buf[8*32];
	fp12_write_bin(buf, 8*32, egg.g, 1);
	sha256_hash(buf, 8*32, ctx);
	memset(buf,0,8*32);

}

static inline void H(sha256_ctx ctx[1], const Big& k) {
	uint8_t buf[32];
	bn_write_bin(buf, 32, k.k);
	sha256_hash(buf, 32, ctx);
	memset(buf,0,32);

}

static inline void H(sha256_ctx ctx[1], const G1& x) {
	uint8_t buf[33];
	ep_write_bin(buf, 33, x.g, 1);
	sha256_hash(buf, 33, ctx);
	memset(buf,0,33);
}

 inline void H(sha256_ctx ctx[1], const G2& x) {
	uint8_t buf[65];
	ep2_write_bin(buf, 65, const_cast<ep2_st *>(x.g), 1);
	sha256_hash(buf, 65, ctx);
	memset(buf,0,65);
}


inline void H_G1(G1& p, const char* buf, int len) {
	ep_map(p.g, (const uint8_t*)buf, len);
}

std::istream &operator>>( std::istream &input,  G1& G ) { 
	std::string x,y,z;
	ep_null(G.g);
	G.g->norm = 1;
	input >> x; fp_read_str(G.g->x, x.c_str(), x.length(), 64);
	input >> y; fp_read_str(G.g->y, y.c_str(), y.length(), 64);
	input >> z; fp_read_str(G.g->z, z.c_str(), z.length(), 64);

	if (!ep_is_valid(G.g)) {
		input.setstate(std::ios::failbit);
		std::cerr << "!!! input error on [" << x << " " << y << " " << z << "]" << std::endl;
	}
    return input;
}

std::istream &operator>>( std::istream &input,  G2& G ) { 
	std::string str;
	ep2_null(G.g);
	G.g->norm = 1;
	input >> str; fp_read_str(G.g->x[0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g->x[1], str.c_str(), str.length(), 64);

	input >> str; fp_read_str(G.g->y[0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g->y[1], str.c_str(), str.length(), 64);

	input >> str; fp_read_str(G.g->z[0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g->z[1], str.c_str(), str.length(), 64);

	if (!ep2_is_valid(G.g)) {
		input.setstate(std::ios::failbit);
		std::cerr << "!!! input error2" << std::endl;
	}

    return input;            
}

std::istream &operator>>( std::istream &input,  GT& G ) { 
	std::string str;

	fp12_zero(G.g);
	input >> str; fp_read_str(G.g[0][0][0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[0][0][1], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[0][1][0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[0][1][1], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[0][2][0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[0][2][1], str.c_str(), str.length(), 64);

	input >> str; fp_read_str(G.g[1][0][0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[1][0][1], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[1][1][0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[1][1][1], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[1][2][0], str.c_str(), str.length(), 64);
	input >> str; fp_read_str(G.g[1][2][1], str.c_str(), str.length(), 64);

    return input;            
}

std::istream &operator>>( std::istream &input,  Big& k ) {
	bn_new(k.k);
	std::string str;
	input >> str;
	bn_read_str(k.k, str.c_str(), str.length(), 64);
    return input;            
}

class Params {

	public:
		G1 gg1;
		G2 gg2;
		GT eegg;

		Big minus_one;
		bn_t order;

	void print() {
		ep_param_print();
		std::cout << " =========== public parameters =========" << std::endl 
			<< gg1 <<std::endl<< gg2 <<std::endl << eegg << std::endl <<
			"========================================" << std::endl;
	}

	int setupParams() {
		if (core_init() != STS_OK) {
			core_clean();
			std::cout << "could not init" <<std::endl;
			return 0;
		}

		if (ep_param_set_any_pairf() == STS_ERR) {
			core_clean();
			std::cerr << " ERROR " << std::endl;
			return 0;
		}

		ep_curve_get_gen(gg1.g);
		ep2_curve_get_gen(gg2.g);

		fp12_zero(eegg.g);

		pp_map_k12(eegg.g, gg1.g, gg2.g);

		bn_new(order);
		bn_new(minus_one.k);
		ep_curve_get_ord(order);
		bn_sub_dig(minus_one.k, order, 1);

		return 1;
	}
};

static Params p;

static inline void add(Big& c, Big& a, Big& b) {
	bn_add(c.k, a.k, b.k);
	bn_mod_basic(c.k, c.k, p.order);
}

static inline void inverse(Big& i, Big& d) {
	bn_sub(i.k, p.order, d.k);
	if (bn_sign(i.k)==BN_NEG) {
		bn_add(i.k, i.k, p.order);
	}
}

static inline void pow(Big& y, Big& a, Big& x) {
	bn_mxp(y.k, a.k, x.k, p.order);
}

static inline void mult(Big& c, Big& a, Big& b) {
	bn_mul(c.k, a.k, b.k);
	bn_mod_basic(c.k, c.k, p.order);
}
	

// y = ax + b
static inline void eval(Big& y, Big& a, Big& x, Big& b) {
	bn_new(y.k);

	bn_mul(y.k, a.k, x.k);

	bn_add(y.k, y.k, b.k);

	bn_mod_basic(y.k, y.k, p.order);
	// y.k = a.k * x.k + b.k;
	// y.k %= Param::r;
}

// y = axc + b
static inline void eval(Big& y, Big& a, Big& x, Big& c, Big& b) {
	bn_new(y.k);

	bn_mul(y.k, a.k, x.k);
	bn_mul(y.k, y.k, c.k);

	bn_add(y.k, y.k, b.k);

	bn_mod_basic(y.k, y.k, p.order);

}


// y = 1/(a+b)
static inline void invplus(Big& y, Big& a, Big& b) {

	bn_t t, inv, gcd, d, e;

	bn_new(t); bn_new(inv); bn_new(gcd); bn_new(d); bn_new(e);
	bn_new(y.k);
	// t = a+b
	bn_add(t, a.k, b.k);
	
	bn_gcd_ext(gcd, y.k, e, t, p.order);
	if (bn_sign(y.k)==BN_NEG) {
		bn_add(y.k, y.k, p.order);
	}

}


#endif




