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


#include "groups.h"

#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
#include "anon.h"
#endif

extern "C" {
#ifndef __IPHONE_OS_VERSION_MIN_REQUIRED
#include "anon.h"
#endif

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
}

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

void usage(char* me);
void rand(char* buf, int sz);

using namespace std;

void log(const char *msg, const int detail) 	{ fprintf(stderr, "%s %d\n",msg, detail); }
void log(const char *msg, const char* detail) 	{ fprintf(stderr, "%s %s\n",msg, detail); }
void log(const char *msg, string str) 		{ fprintf(stderr, "%s %s\n",msg, str.c_str()); }

// The Okamoto signature scheme is
//     pk: w=g^x   sk: x
//     pick r,s.  sigma <-- (g^m1 t^m2 u v^s)^{1/x+r}
//
// To verify, check that
//     e(sigma, wg^r) = e(g, g^m1 t^m2 u v^s)

class SIG {
public:
	G1 sigma;
	Big r,s;

	SIG() {
		zero(sigma);
		zero(r);
		zero(s);
	}

	int read(const char* str) {
		istringstream v(str);
		if (v >> sigma >> r >> s) { return 1; }
		log("SIG.read:", "failed");
		return 0;
	}
};

class ANONVK {
public:
	G1 gg, tt, uu, vv;
	G2 ww;

	int read(const char* txt) {
		string s(txt);
		istringstream in(s);
		string t,b;
		int a = ( (in >> t >> gg >> tt >> uu >> vv >> ww >> b) 
				&& t == "==========ANONLOGIN_VK_BEG==========" 
				&& b == "===========ANONLOGIN_VK_END==========" );
		if (!a) log("ANONVK.read:", "failed");
		return a;
	}

	string str() {
		ostringstream out;
		out << "==========ANONLOGIN_VK_BEG==========" << endl <<
			gg << endl << tt << endl << uu << endl << vv << endl << ww << endl <<
			"===========ANONLOGIN_VK_END==========";
		return out.str();
	}

	// (sigma, r, s)
	//     e(sigma, wg^r) = e(g^m1 t^m2 u v^s, g2)
	int verifySignature(string m1, Big zm2, SIG& sig, Params& p) {

		GT lleft, rright;
		G1 tq,tr,ts;
		G2 uq;

		// transform msg into int
		Big zm1;
		const char* cmsg = m1.c_str();
		set_int(zm1, cmsg, m1.length());

		mult(tq, gg, zm1);
		mult(tr, tt, zm2);
		mult(ts, vv, sig.s);

		add(tq, tq, tr);
		add(tq, tq, uu);
		add(tq, tq, ts);

		atepair(rright, p.gg2, tq);

		mult(uq, p.gg2, sig.r);
		add(uq, uq, ww);

		atepair(lleft, uq, sig.sigma);

		if ( !equal(lleft, rright)) {
			log(" Left sig != right sig. Signature check failure.\n", "");
			cout << "left "<< lleft << endl << endl << "right " << rright << endl;
			return 0;
		}
		return 1;		
	}
};

class ANONSK {
public:
	Big xx;
	G1 gg, tt, uu, vv;
	G2 ww;

	string str() {
		ostringstream out;
		out <<  "==========ANONLOGIN_SK_BEG==========" << endl 
			<< gg << endl << tt << endl << uu << endl << vv << endl << ww << endl << xx << endl <<
			"===========ANONLOGIN_SK_END==========";
		return out.str();
	}

	int readFromFile(string filename) {
		ifstream is(filename);
		if (!is.is_open()) {
			log("ANONSK.readFromFile failed:", filename);
			return 0;
		}
		return readkey(is);
	}

	int readkey(istream& is) {
		string t,b;
		int a = ( (is >> t >>  gg >> tt >> uu >> vv >> ww>> xx >> b) 
				&& t == "==========ANONLOGIN_SK_BEG==========" 
				&& b == "===========ANONLOGIN_SK_END==========" );
		if (!a) log("ANONSK.readkey:", "failed");
		return a;
	}

	int read(const char* k) {
		string s(k);
		istringstream in(s);
		return readkey(in);
	}

	string sign(Big vid, string idstr) {
		Big rr, ss;
		rand_int(rr);
		rand_int(ss);

		// compute sigma <- ( g^m1 t^vid u v^s )^{1/x+r}
		G1 sigma, t,t2;
		Big id, inv;

		const char* cmsg = idstr.c_str();
		int len = idstr.length();
		set_int(id, cmsg, len);

		mult(t, gg, id);
		mult(t2, tt, vid);
		add(t, t, t2);
		add(t, t, uu);
		mult(t2, vv, ss);
		add(t, t, t2);

		invplus(inv, xx, rr);

		mult(sigma, t, inv);

		ostringstream out;
		out << sigma << " " << rr << " " << ss << endl;
		return out.str();
	}

};


class Cred {
public:
	Big id, sid;
	string userid;

	SIG sig;

	G1 alpha;

	Cred() { zero(alpha); }
	
	Cred(const char* usrid) {
		userid = string(usrid);
		int len = strlen(usrid);
		set_int(id, usrid, len);
		rand_int(sid);
		rand_int(sig.s);	

		zero(alpha);
	}

	string str() {
		ostringstream out;
		out << "==========ANONLOGIN_CRED_BEG==========" << endl 
			 << userid << endl << sid << endl <<
			 sig.sigma << endl << sig.r << endl << sig.s << endl <<
			"===========ANONLOGIN_CRED_END==========";
		return out.str();
	}

	int read(const char* str) {
		istringstream in(str);
		return read(in);
	}

	int read(istream& is) {
		string t,b;
		if (!(is >> t)) { 
			log("Cred.read:", "failed");
                	return 0;
                }
		std::getline(is, userid);	// consume newline from topline
		std::getline(is, userid);	// read userid entirely
		int len = userid.length();
		if (len>31) {			// fail on long address
			log("Cred.read: len", len);
			return 0;
		}
		set_int(id, userid.c_str(), len);

		return ( (is >> sid >> sig.sigma >> sig.r >> sig.s >> b)
			 && t=="==========ANONLOGIN_CRED_BEG==========" 
			 && b=="===========ANONLOGIN_CRED_END==========" );

	}
};

// ======= MAKE Cred =======================================================

void makeKey(ANONVK& vk, ANONSK& sk, Params& p) {
	rand_int(sk.xx);

	Big tt;
	rand_int(tt);
	mult(vk.gg, p.gg1, tt);

	rand_int(tt);
	mult(vk.tt, p.gg1, tt);

	rand_int(tt);
	mult(vk.uu, p.gg1, tt);

	rand_int(tt);
	mult(vk.vv, p.gg1, tt);

	zero(tt);

	mult(vk.ww, p.gg2, sk.xx);

	copy(sk.gg, vk.gg);
	copy(sk.tt, vk.tt);
	copy(sk.uu, vk.uu);
	copy(sk.vv, vk.vv);
	copy(sk.ww, vk.ww);

}

// returns 1 on success. writes keys into buffers
int makeKey(char vk[2048], char sk[2048])
{
	ANONVK ravk; ANONSK rask;
	makeKey(ravk, rask, p);

	string v = ravk.str();
	string s = rask.str();
	if (v.size()>2000 || s.size()>2000) { return 0; } // prevents buffer overwrite

	std::copy(v.begin(), v.end(), vk);
	vk[v.size()] = '\0'; // terminating 0
	std::copy(s.begin(), s.end(), sk);
	sk[s.size()] = '\0'; 

	return 1;
}

// initializes a new cred struture
const char* makeCred(const char* uid) {
	Cred c(uid);
	return strdup(c.str().c_str());	// return a copy, caller does memory mgmt
}

// ===============================================================
// ===================== REGISTRATION message RO ==============================
#define REGNUMZK 4

class REGZKMSG {
public:

	// first
	Big b1, b2;
	G1 gamma;

	Big challenge;

	// third messages
	Big z1,z2, i1, i2;

	REGZKMSG() {
		rand_int(b1); rand_int(b2); 
		zero(z1); zero(z2); zero(i1); zero(i2); zero(challenge); zero(gamma);
	}

	string str() {
		ostringstream out;
		out << gamma << endl << challenge << endl << z1 << " " << z2 << endl;
		return out.str();
	}

	friend istream &operator>>( istream &input,  REGZKMSG& zk ) { 
		input >> zk.gamma >> zk.challenge >> zk.z1 >> zk.z2; 
		return input;
	}

	void computeFirstProofMessage(ANONVK& ravk) {
		G1 t2;
		mult(gamma, ravk.tt, b1);
		mult(t2, ravk.vv, b2);
		add(gamma, gamma, t2);
		normalize(gamma, gamma);
	}

	void computeThirdProofMessage(Cred& cred, Big& ccc) {
		eval(z1, ccc, cred.sid, 	b1);	// z1 = c*sid + b1  (mod p)
		eval(z2, ccc, cred.sig.s,   b2);	// z2 = c*s   + b2  (mod p)
		i1 = cred.sid;
		i2 = cred.sig.s;
	}

	void updateThirdProofMessage() {
		add(z1, z1, i1);
		add(z2, z2, i2);
	}

	int verifyProof(G1& alpha, ANONSK& rask) {
		// check that ravk.tt^{z1} * ravk.vv^{z2} = alpha^c * gamma
		G1 tt, tt2, lleft, rright;
		mult(tt, rask.tt, z1);
		mult(tt2, rask.vv, z2);
		add(lleft, tt, tt2);
		normalize(lleft, lleft);

		mult(tt, alpha, challenge);
		add(rright, tt, gamma);
		normalize(rright, rright);

		if ( !equal(lleft, rright)) {
			log(" Left proof != right proof in server response.\n", "");
			cout << "alpha " << alpha << endl << "gamma " << gamma << endl << "z1: " << z1 << endl << "z2: " << z2 << endl;
			cout << "left "<< lleft << endl << endl << "right " << rright << endl;
			return 0;		
		}

		return 1;
	}

};

template<class T>
void H(sha256_ctx ctx[1], T& ravk, G1& alpha, Params& p) {
	H(ctx, p.gg1);
	H(ctx, p.gg2);
	H(ctx, ravk.gg);
	H(ctx, ravk.tt);
	H(ctx, ravk.uu);
	H(ctx, ravk.vv);
	H(ctx, ravk.ww);
	H(ctx, alpha);
}

const char* OnlineExtractableNIZK(G1& alpha, Cred& c, ANONVK& ravk, Params& p) {
	sha256_ctx ctx[1];
	sha256_begin(ctx);

	H(ctx, ravk, alpha, p);

	REGZKMSG zk[REGNUMZK];

	for(int i=0; i<REGNUMZK; i++) {
		zk[i].computeFirstProofMessage(ravk);
		H(ctx, zk[i].gamma);
	}

	for(int i=0; i<REGNUMZK; i++) {
		Big ccc;
		rand_int(ccc);
		sha256_ctx cci;
		unsigned char hval[SHA256_DIGEST_SIZE];
		int cnt = 0;

		zk[i].computeThirdProofMessage(c, ccc);

		do {
			inc(ccc);
			zk[i].updateThirdProofMessage();

			cci = ctx[0]; // copy hash context of prefix
			H(&cci, zk[i].z1);
			H(&cci, zk[i].z2);
			sha256_end(hval, &cci);

			cnt++;
		} while ( hval[0] != 0 || (hval[1]&0xf)!= 0 );
		// this ending condition requres 12 bits of hash to be 0

		zk[i].challenge = ccc;
	}

	ostringstream out;
	for(int i=0; i<REGNUMZK; i++) {
		out << zk[i].str() << endl;
	}

	return strdup(out.str().c_str());
}

const char* registerUserMessage(const char* cred, const char* vk) {
	Cred c;
	ANONVK ravk;
	if (!c.read(cred) || !ravk.read(vk)) {
		return NULL;
	}

	ostringstream buffer;

	// alpha = (tt^{sid} vv^{s})
	G1 t,t2;

	mult(t, ravk.tt, c.sid);
	mult(t2, ravk.vv, c.sig.s);
	add(c.alpha, t, t2);
	normalize(c.alpha, c.alpha);

	const char* proof = OnlineExtractableNIZK(c.alpha, c, ravk, p);

	buffer << c.userid << endl << c.alpha << endl << proof << endl;

    if (proof) { memset((void*)proof, 0, strlen(proof)); free((void*)proof); proof=NULL; }

	return strdup(buffer.str().c_str());
}


const char* registerServerResponse(const char* userid, const char* usermsg, const char* raskey) {
	ANONSK rask;
	if (!rask.read(raskey)) {
		log("Could not read raskey. ",raskey);
		return "";
	}

	// parse the message
	istringstream in(usermsg);
	G1 tt, tt2, aalpha;
	string uidOrig;

	// uidOrig is what the user thinks it user name is. use this to verify the proof
	// but use the server-provided userid for signing
	// this code assumes that the caller checks name consistency
	if (! (in >> uidOrig >> aalpha) ) {
		log("Could not read input user message.\n", "");
		return "";
	}

	REGZKMSG zk[REGNUMZK];
	sha256_ctx ctx[1], cci;
	sha256_begin(ctx);
	unsigned char hval[SHA256_DIGEST_SIZE];

	H(ctx, rask, aalpha, p);

	bool retval = true;

	// no early exits of loop
	for(int i=0; i<REGNUMZK; i++) {
		if (!(in >> zk[i]) || !zk[i].verifyProof(aalpha, rask)) {
			retval = false;
		}
		H(ctx, zk[i].gamma);
	}

	// check hash
	for(int i=0; i<REGNUMZK; i++) {
		cci = ctx[0];
		H(&cci, zk[i].z1);
		H(&cci, zk[i].z2);
		sha256_end(hval, &cci);

	 	if ( hval[0] != 0 || (hval[1]&0xf)!= 0 ) {
	 		log("Hash of proof is not valid.","");
	 		retval = false;
	 	}

	}

	if (!retval) { return ""; }

	log("Verification of Proof Succeeded.","");

	// sign the id
	// 		sigma =( g^{id} t^{sid} u v^s )^{1/(x+r)}
	Big id, rr, inv;
	rand_int(rr);

	G1 sigma;

	// transform userid into bigint
	int len = strlen(userid);
	set_int(id, userid, len);

	mult(tt, rask.gg, id);
	add(tt2, tt, aalpha);
	add(tt, tt2, rask.uu);

	// inv = 1/(x+r)
	invplus(inv, rr, rask.xx);

	mult(sigma, tt, inv);

	// output to string
	ostringstream out;
	out << sigma << " " << rr << endl;

	zero(sigma); zero(rr); zero(inv);

	string res = out.str();
	if (res.length()>0) {
		return strdup( res.c_str() );
	}

	return "";

}

// verifies the server message and produces the credential
const char* registerUserFinal(const char* userid, const char* servermsg, const char* cred, const char* vk) {
	Cred c;
	ANONVK ravk;
	if (!c.read(cred) || !ravk.read(vk)) {
		return NULL;
	}

	// update the userid from server
	string uu = string(userid);
	c.userid = uu;

	istringstream in(servermsg);

	if (! (in >> c.sig.sigma >> c.sig.r) ) {
		return NULL;
	}

	if (!ravk.verifySignature(c.userid, c.sid, c.sig, p)) {
		log("Invalid signature in registerUserFinal",c.userid); 
		return NULL;
	}

	log("Signature verified in registerUserFinal.","");

	return strdup(c.str().c_str());
}


// ==========================================================================
// ===================== MAKE SURVEY messages ==============================

// emails is a "\n" and/or " "-delimmitted string of email addresses.
// simplified calling this function from golang
// the output sig list contains <name>, <sig>
// the comma is used to delimit in case the name has spaces in it. 
// thus, name cannot have a , in it. We assume names are comma-free email addresses

// returns 1 on success, 0 on error
// initializes a survey structure with vid, key
// use the extendSurvey method to add participants
int createSurvey(survey* s) {

	if (!s) { return 0; }

	s->sigs = s->vid = s->vavk = s->vask = NULL;
	s->cnt  = 0;

	ANONVK vk; ANONSK sk;
	makeKey(vk, sk, p);
	Big vid;
	rand_int(vid);

	string vavk = vk.str();
	s->vavk = strdup(vavk.c_str());

	string vask = sk.str();
	s->vask = strdup(vask.c_str());

	ostringstream out;
	out << vid;
	s->vid = strdup(out.str().c_str());

	return 1;
}



// public version of this method to extend a survey with new 
// participants.
// returns -1 on error
int extendSurvey(const char* emails, survey *s) {
	if (!emails || !s) { return 0; }
	ANONSK sk;
	Big vid;
	istringstream in(s->vid);
	if (!sk.read(s->vask) || !(in >> vid)) { return -1; }

	int cnt = 0;
	char* copy = strdup(emails);	// need copy to use strsep
	if (!copy) { return -1; }
	ostringstream sigs;
	char *token = copy, *p=copy;

	while (cnt<2048 && (token=strsep(&p, "\n"))!=NULL) {
		string email(token);
		if (email.find(",") == string::npos) {
			sigs << email << ", " << sk.sign(vid, email);
			cnt++;
		}
	}
	if (s->sigs == NULL) {
		s->sigs = strdup(sigs.str().c_str());
		s->cnt = cnt;
	} else {
		// extend sigs
		ostringstream newsigs;
		newsigs << s->sigs << endl << sigs.str();
		free((void*)s->sigs);
		s->sigs = strdup(newsigs.str().c_str());
		s->cnt += cnt;
	}

	if (copy) { free(copy); copy = NULL; }
	return cnt;
}

void freeSurvey(survey* s) {
	if (!s) { return; }
	if (s->vid) { free((void*)s->vid); }
	if (s->vavk) { free((void*)s->vavk); }
    if (s->vask) { memset((void*)s->vask,0,strlen(s->vask)); free((void*)s->vask); }
	if (s->sigs) { free((void*)s->sigs); }
	s->cnt = 0;
	memset(s,0,sizeof(survey));
}

void freeSurveyResponse(survey_response* sr) {
	if (!sr) return;
	if (sr->msg) { free((void*)sr->msg); }
	if (sr->token) { free((void*)sr->token); }
	memset(sr,0,sizeof(survey_response));
}

// ======================= SUBMIT messages =========================================================

void H1(const char* vidstr, G1& Hvid) {
	sha256_ctx ctx[1];
	sha256_begin(ctx);
	H(ctx, vidstr);
	unsigned char hval[SHA256_DIGEST_SIZE];
	sha256_end(hval, ctx);
	H_G1(Hvid, (const char*)hval, SHA256_DIGEST_SIZE);
	memset(hval, 0, SHA256_DIGEST_SIZE);
}


class ZKMSG {
public:

	Big d, hd, y, yp, ypp, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, e1, e2;
	G1 J1, J2;
	G2 B, hB, alpha;

	GT E1, E2;

	G1 D, F, H, beta, delta, gamma, gamma2, eta;

	// challenge
	Big chal;

	// third messages
	Big z1,z2,z3,z4,z5,z6,z7,z8,z9,z10,z11,z12,z13,z14;
	Big    i2,i3,i4,i5,   i7,i8,i9			  ,i13;    // variables to handle incremental updates
	G1  j1,j2;

	ZKMSG() {
		rand_int(d);  rand_int(hd); rand_int(b1); 
		rand_int(b2); rand_int(b3); rand_int(b4);
		rand_int(b5); rand_int(b6); rand_int(b7);
		rand_int(b8); rand_int(b9); rand_int(b10); 
		rand_int(b11);rand_int(b12);rand_int(b13);
		rand_int(b14); 
		rand_int(y), rand_int(yp); rand_int(ypp);
		rand_int(e1); rand_int(e2);
	}

	string str() {
		ostringstream out;
		out << B << endl << hB << endl << D << endl << F << endl << this->H << endl <<
			alpha << endl << beta << endl << 
			E1 << endl << E2 << endl <<
			delta << endl << gamma << endl << gamma2 << endl << eta << endl <<
			chal << endl <<
			z1 << " " << z2 << " " << z3 << " " << z4 << " " <<
			z5 << " " << z6 << " " << z7 << " " << z8 << " " << 
			z9 << " " << z10 << " " << z11 << " " << z12 << " " <<
			z13 << " " << z14 <<
			endl <<
			j1 << endl << 
			j2 << endl;
		return out.str();
	}

	friend istream &operator>>( istream &input,  ZKMSG& zk ) { 
		input >> zk.B >> zk.hB >> zk.D >> zk.F >> zk.H >>
			zk.alpha >> zk.beta >>
			zk.E1 >> zk.E2 >> 
			zk.delta >> zk.gamma >> zk.gamma2 >> zk.eta >> 
			zk.chal >>
			zk.z1 >> zk.z2 >> zk.z3 >> zk.z4 >> 
			zk.z5 >> zk.z6 >> zk.z7 >> zk.z8 >> 
			zk.z9 >> zk.z10 >> zk.z11 >> zk.z12 >>
			zk.z13 >> zk.z14 >>
			zk.j1 >> zk.j2;
		return input;
	}

	void computeFirstProofMessage(SIG& sig, ANONVK& ravk, G1& C, G1& Hvid, Big& vid, Big& id, SIG& sigvid, ANONVK& vavk) {
        
		mult(J1, p.gg1, e1);		// J1 <- g^e {random grp element}
		mult(J2, p.gg1, e2);		

		// B  <- (wg^r)^d
		mult(B, p.gg2, sig.r);
		add(B, B, ravk.ww);
		mult(B, B, d);

		// hB  <- (wg^hr)^hd
		mult(hB, p.gg2, sigvid.r);
		add(hB, hB, vavk.ww);
		mult(hB, hB, hd);

		G2 aa2;
		GT tte, ttf, ttt;
		G1 t1, t2;


		// D <-- g^d hg^hd u^y
		mult(D, ravk.gg, d);
		mult(t1, vavk.gg, hd);
		add(D,D,t1);
		mult(t1, ravk.uu, y);
		add(D,D,t1);

		// F <-- D^id t^yp 
		mult(F, D, id);
		mult(t1, ravk.tt, yp);
		add(F,F,t1);

		// H <-- t^{id*y} v^ypp
		Big te;
		mult(te, id, y);
		mult(this->H, ravk.tt, te);
		mult(t1, ravk.vv, ypp);
		add(this->H,this->H,t1);

		// alpha  <- w^{b1} g^{b2} w^{b6} g^{b7}
		mult(alpha, ravk.ww, b1);
		mult(aa2, p.gg2, b2);
		add(alpha, alpha, aa2);
		mult(aa2, vavk.ww, b6);
		add(alpha, alpha, aa2);
		mult(aa2, p.gg2, b7);
		add(alpha, alpha, aa2);

		// beta  <- C^{b1} H_vid^{-b4} 
        mult(beta, C, b1);
        Big ib4;
        inverse(ib4, b4);
        mult(t1, Hvid, ib4);
        add(beta, beta, t1);

        // delta <- g^b1 hg^b6 u^b10
        mult(delta, ravk.gg, b1);
        mult(t1, vavk.gg, b6);
        add(delta, delta, t1);
        mult(t1, ravk.uu, b10);
        add(delta, delta, t1);

        // gamma <- D^b11 t^b12
        mult(gamma, D, b11);
        mult(t1, ravk.tt, b12);
        add(gamma, gamma, t1);

        // gamma2 <- g^b3 hg^b8 u^b13 t^b12
        mult(gamma2, ravk.gg, b3);
        mult(t1, vavk.gg, b8);
        add(gamma2, gamma2, t1);
        mult(t1, ravk.uu, b13);
        add(gamma2, gamma2, t1);
        mult(t1, ravk.tt, b12);
        add(gamma2, gamma2, t1);

        // eta <- t^b13 v^b14
        mult(eta, ravk.tt, b13);
        mult(t1, ravk.vv, b14);
        add(eta, eta, t1);

		// E1 <- e(J1,B)^{-1} e(g^{b3} t^{b4} u^{b1} v^{b5}, g2)
		atepair(ttt, B, J1);
		pow(tte, ttt, p.minus_one);

		mult(t1, ravk.gg, b3);
		mult(t2, ravk.tt, b4);
		add(t1, t1, t2);
		mult(t2, ravk.uu, b1);
		add(t1, t1, t2);
		mult(t2, ravk.vv, b5);
		add(t1, t1, t2);
		atepair(ttf, p.gg2, t1);
		mult(E1, tte, ttf);



		// E2 <- e(J2,Bp)^{-1} e(g^{b8} (t^{vid}u)^{b6} v^{b9}, g2)
		atepair(ttt, hB, J2);
		pow(tte, ttt, p.minus_one);

		mult(t1, vavk.gg, b8);

		mult(t2, vavk.tt, vid);	// t^vid
		add(t2, vavk.uu, t2);	// t^vid*u
		mult(t2, t2, b6);		// (t^vid*u)^b1

		add(t1, t1, t2);

		mult(t2, vavk.vv, b9);
		add(t1, t1, t2);

		atepair(ttf, p.gg2, t1);
		mult(E2, tte, ttf);
        
	}


	void computeThirdProofMessage(Big& id, Big& sid, SIG& sig, SIG& sigvid, ANONVK& ravk, Big& cc) {
		
		eval(z1, cc, d, b1);		// z1 = b1 + c(d)

		mult(i2, sig.r, d);			// z2 = b2 + c(r  * d)
		eval(z2, cc, i2, b2);

		mult(i3, id, d);			// z3 = b3 + c(id * d)
		eval(z3, cc, i3, b3);
		
		mult(i4, sid, d);			// z4 = b4 + c(sid * d)
		eval(z4, cc, i4, b4);

		mult(i5, sig.s, d);			// z5 = b5 + c(s * d)
		eval(z5, cc, i5, b5);

		eval(z6, cc, hd, b6);

		mult(i7, sigvid.r, hd);		// z7 = b7 + c(hr * hd)
		eval(z7, cc, i7, b7);

		mult(i8, id, hd);			// z8 = b8 + c(id * hd)
		eval(z8, cc, i8, b8);

		mult(i9, sigvid.s, hd);		// z9 = b9 + c(s' * d)
		eval(z9, cc, i9, b9);

		eval(z10, cc, y, b10);		// z10 = b10 + c(y)
		eval(z11, cc, id, b11);		// z11 = b11 + c(id)

		eval(z12, cc, yp, b12);		// z12 = b12 + c(y')

		mult(i13, id, y);			// z13 = b13 + c(id * y)
		eval(z13, cc, i13, b13);

		eval(z14, cc, ypp, b14);	// z14 = b13 + c(ypp)

		G1 tt;
		mult(tt, sig.sigma, cc);		// j1 = \sigma^c * J1
		add(j1, tt, J1);

		mult(tt, sigvid.sigma, cc);		// j2 = \sigma'^c * J2
		add(j2, tt, J2);
	}

	// this method is an optimization to avoid having to recompute proofs
	// can only be called after computeThirdMessage has been called and
	// only works for updating the challenge by 1
	void updateThirdProofMessage(SIG& sig, SIG& sigvid, Big id) {
		// z1 = b1 + c(d)
		add(z1, z1, d);
		add(z2, z2, i2);
		add(z3, z3, i3);
		add(z4, z4, i4);
		add(z5, z5, i5);
		add(z6, z6, hd);
		add(z7, z7, i7);
		add(z8, z8, i8);
		add(z9, z9, i9);
		add(z10, z10, y);
		add(z11, z11, id);
		add(z12, z12, yp);
		add(z13, z13, i13);
		add(z14, z14, ypp);

		// j1 = \sigma^c * J1
		add(j1, j1, sig.sigma);

		// j2 = \sigma'^c * j2
		add(j2, j2, sigvid.sigma);

	}

	// after the proof has been read, verifies the equations
	bool verifyProof(const char* vidstr, G1& C, ANONVK& ravk, ANONVK& vavk, Params& p) {

		G2 l1, r1, r2, t1;

		Big vid;
		istringstream v(vidstr);
		if (!(v >> vid)) {
			return false;
		}

		// aB^c hB^c = w^z1 * g^z2 * w'^z6 * g^z7
		mult(l1, B, chal);
		add(l1, l1, alpha);
		mult(t1, hB, chal);
		add(l1, l1, t1);

		mult(r1, ravk.ww, z1);
		mult(r2, p.gg2, z2);
		add(r1, r1, r2);
		mult(r2, vavk.ww, z6);
		add(r1, r1, r2);
		mult(r2, p.gg2, z7);
		add(r1, r1, r2);

        // 1 = beta * C^-z1 * H(vid)^z4 
        G1 Hvid, r3, l3;
        H1(vidstr, Hvid);
        
        mult(r3, Hvid, z4);
        //Big iz1;
        //inverse(iz1, z1);
        //mult(t3, C, iz1);
        //add(r3, r3, t3);
        add(r3, r3, beta);
        normalize(r3, r3);
        
        mult(l3, C, z1);
        normalize(l3,l3);

        
		// E1 = e(j1, B)^{-1} * e(g2, g^z3 t^z4 u^z1 v^z5)
		GT r1a, r1b, E1r, ttt;
		G1 rt1, gz3, tz4, uz1, vz5;
        
		atepair(ttt, B, j1);
		pow(r1a, ttt, p.minus_one);

		mult(gz3, ravk.gg, z3);
		mult(tz4, ravk.tt, z4);
		mult(uz1, ravk.uu, z1);
		mult(vz5, ravk.vv, z5);

		add(rt1, gz3, tz4);
		add(rt1, rt1, uz1);
		add(rt1, rt1, vz5);

		atepair(r1b, p.gg2, rt1);

		mult(E1r, r1a, r1b);

		// E2 = e(j2, Bp)^{-1} * e(g2, g^z3 (t^vid u)^z1 v^z7)
		GT r2a, r2b, E2r;
		G1 rt2, tu, vz7;


		atepair(r2a, hB, j2);

		pow(r2a, r2a, p.minus_one);

		mult(gz3, vavk.gg, z8);
		mult(tu, vavk.tt, vid);
		add(tu, tu, vavk.uu);
		mult(tu, tu, z6);
		mult(vz7, vavk.vv, z9);

		add(rt2, gz3, tu);
		add(rt2, rt2, vz7);

		atepair(r2b, p.gg2, rt2);

		mult(E2r, r2a, r2b);

		// delta D^c = g^z1 hg^z6 u^z10
		G1 l4, r4, t4;
		mult(l4, D, chal);
		add(l4, l4, delta);
		normalize(l4,l4);

		mult(r4, ravk.gg, z1);
		mult(t4, vavk.gg, z6);
		add(r4,r4,t4);
		mult(t4, ravk.uu, z10);
		add(r4,r4,t4);
		normalize(r4,r4);

		// gamma F^c = D^z11 t^z12
		G1 l5, r5, t5, l7;
		mult(t5, F, chal);
		add(l5, t5, gamma);
		add(l7, t5, gamma2);
		normalize(l5,l5);
		normalize(l7,l7);

		mult(r5, D, z11);
		mult(t5, ravk.tt, z12);
		add(r5,r5,t5);
		normalize(r5,r5);

		// gamma2 F^c = g^z3 hg^z8 u^{z13} t^{z12}
		G1 r7;
		mult(r7, ravk.gg, z3);
		add(r7,r7,t5);	// add tt^z12 since it is precomputed
		mult(t5, vavk.gg, z8);
		add(r7, r7, t5);
		mult(t5, ravk.uu, z13);
		add(r7, r7, t5);
		normalize(r7,l7);

		// eta H^c = t^{z13} v^{z14}
		G1 l6, r6, t6;
		mult(l6, H, chal);
		add(l6, l6, eta);
		mult(r6, ravk.tt, z13);
		mult(t6, ravk.vv, z14);
		add(r6,r6,t6);
		normalize(l6,r6);
		normalize(r6,r6);

		if (equal(l1,r1) && equal(E1,E1r) && equal(E2,E2r) && equal(l3,r3)
			&& equal(l4,r4) && equal(l5,r5) && equal(l7,l7) && equal(l6,r6)
			) {
			return true;
		} else {
            std::cerr << " VERIFY FAILURE " << endl;
            std::cerr << "1:  " << l1 << "\n    " << r1 << " " << equal(l1,r1) << endl;
//            std::cerr << "2:  " << l1p << "\n    " << r1p << endl;
			std::cerr << "3:  " << E1 << "\n    " << E1r << endl;
			std::cerr << "4:  " << E2 << "\n    " << E2r << endl;
			std::cerr << "l3:  " << l3 << "\n    " << r3 << " e:" << equal(l3,r3) << endl;
			std::cerr << "l4:  " << l4 << "\n    " << r4 << " e:" << equal(l4,r4) << endl;
			std::cerr << "l5:  " << l5 << "\n    " << r5 << " e:" << equal(l5,r5)<< endl;
			std::cerr << "l6:  " << l6 << "\n    " << r6 << " e:" << equal(l6,r6)<< endl;
			std::cerr << "l7:  " << l7 << "\n    " << r7 << " e:" << equal(l7,r7)<< endl;

		}

		return false;
	}

};

void H(sha256_ctx ctx[1], const char* msg, Big& vid, G1& C, Params& p, ANONVK& ravk) {
	H(ctx, msg);
	H(ctx, vid);
	H(ctx, C);
	H(ctx, p.gg1);
	H(ctx, p.gg2);
	H(ctx, ravk.gg);
	H(ctx, ravk.tt);
	H(ctx, ravk.uu);
	H(ctx, ravk.vv);
	H(ctx, ravk.ww);
}

void H(sha256_ctx ctx[1], ZKMSG& zk) {
	H(ctx, zk.B);
	H(ctx, zk.hB);
	H(ctx, zk.D);
	H(ctx, zk.F);
	H(ctx, zk.H);
	H(ctx, zk.E1);
	H(ctx, zk.E2);
	H(ctx, zk.alpha);
	H(ctx, zk.beta);
	H(ctx, zk.gamma);
	H(ctx, zk.delta);
	H(ctx, zk.eta);
}

void H2(sha256_ctx ctx[1], ZKMSG& zk) {
	H(ctx, zk.z1);
	H(ctx, zk.z2);
	H(ctx, zk.z3);
	H(ctx, zk.z4);
	H(ctx, zk.z5);
	H(ctx, zk.z6);
	H(ctx, zk.z7);
	H(ctx, zk.z8);
	H(ctx, zk.z9);
	H(ctx, zk.z10);
	H(ctx, zk.z11);
	H(ctx, zk.z12);
	H(ctx, zk.z13);
	H(ctx, zk.z14);
	H(ctx, zk.j1);
	H(ctx, zk.j2);
}

const char* OnlineExtractableNIZK(const char* msg, Cred& cred, ANONVK& ravk, G1& C, G1& Hvid, Big& vid, SIG& sigvid, ANONVK& vavk, Params& p) {
#define NUMZK 1

	sha256_ctx ctx[1];
	sha256_begin(ctx);

	H(ctx, msg, vid, C, p, ravk);

	ZKMSG zk[NUMZK];

	//auto start = std::chrono::high_resolution_clock::now();
	for(int i=0; i<NUMZK; i++) {
		zk[i].computeFirstProofMessage(cred.sig, ravk, C, Hvid, vid, cred.id, sigvid, vavk);
		H(ctx, zk[i]);
	}
	//auto elapsed = std::chrono::high_resolution_clock::now() - start;
	//long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

	//printf(" first msg: %lld  %lld/per\n", microseconds, microseconds/NUMZK);
	// int iter = 0;
	// long long msec = 0;
    
	for(int i=0; i<NUMZK; i++) {
		Big ccc;
		rand_int(ccc);
		sha256_ctx cci;
		unsigned char hval[SHA256_DIGEST_SIZE];
		int cnt = 0;
        
		zk[i].computeThirdProofMessage(cred.id, cred.sid, cred.sig, sigvid, ravk, ccc);
        
		do {
			inc(ccc);
			zk[i].updateThirdProofMessage(cred.sig, sigvid, cred.id);

			cci = ctx[0]; // copy hash context of prefix
			H2(&cci, zk[i]);
			sha256_end(hval, &cci);

			cnt++;
		} while ( hval[0] != 0 || (hval[1]&0xf)!= 0 );
		// this ending condition requres 12 bits of hash to be 0

		zk[i].chal = ccc;
	}

	ostringstream out;
	out << msg << endl << C << endl;
    
	for(int i=0; i<NUMZK; i++) {
		out << zk[i].str() << endl;
	}

	return strdup(out.str().c_str());
}

// [msg, cred, ravk, [attrsig, vidstr, vavk]_{1,...,n} ]
// the uidsig should just be sigma1 sigma2
const char* submitMessage(const char* msg, const char* cred, const char* ravk_str, const char* uidsig, const char* vidstr, const char* vavk_str)
{
	ANONVK ravk, vavk;
	Cred c;

	if (!msg || !cred || !ravk_str) {
		log("Invalid input.", "");
		return NULL;
	}
	
	if (!ravk.read(ravk_str) || !c.read(cred)) { 
		log("Could not read ravk or cred.",""); 
		return NULL;
	}

	if (!ravk.verifySignature(c.userid, c.sid, c.sig, p)) {
		std::cerr << " Could not verify cred signature\n";
		return NULL;
	}

	// Parse vid-sig if necessary
/*	bool clause = false; */
	SIG sigvid;
	Big vid;
	if (uidsig!=NULL && vavk_str!=NULL) {
/*		clause = true; */
		istringstream in(vidstr);

		if (!vavk.read(vavk_str) || !sigvid.read(uidsig) || !(in >> vid) ||
			!vavk.verifySignature(c.userid, vid, sigvid, p)
			)
		{
			log("Could not verify vavk or signature.\n", uidsig);
			return NULL;			
		}
	}

	// 2. Compute PRF C = H(vid)^{sid}
	G1 Hvid, C;
	H1(vidstr, Hvid);
	mult(C, Hvid, c.sid);
    
	return OnlineExtractableNIZK(msg, c, ravk, C, Hvid, vid, sigvid, vavk, p);
}


// it is important that the vidstr that is submitted here corresponds to the vavk that is given
// otherwise, cheating is possible
int verifyMessage(const char* proof, const char* ravk_str, const char* vidstr, const char* vavk_str, survey_response* sr) {

	ANONVK ravk, vavk;
/*	bool clause = false; */
    
	if (!proof || !ravk_str || !sr || !ravk.read(ravk_str)) {
		log("Invalid proof inputs","");
		return 0;
	}
	if (vidstr && !vavk.read(vavk_str)) {
		log("Invalid vavk inputs",vidstr);
		return 0;		
	} else { /* clause = true; */ }
    
	sr->msg = sr->token = NULL;

	istringstream in(proof);

	G1 C, Hvid;
	Big vid;

	char msg[4096];

	if (!in.getline(msg, 4095)) {
		log("Could not read submitted message from input.", "");
		return 0;
	}

	H1(vidstr, Hvid);

	istringstream invid(vidstr);
	if (!(invid>>vid)) { return 0; }

	ZKMSG zk[NUMZK];

	if (!(in >> C)) {
		log("Could not parse token string.",proof);
		return 0;
	}

	// if (!equal(vvid, vvidin)) { 
	// 	log("vvid and vvidin are not the same",""); 
	// 	return 0; 
	// }

	// 4. Check all NIZK
	sha256_ctx ctx[1], cci;
	sha256_begin(ctx);
	unsigned char hval[SHA256_DIGEST_SIZE];
	H(ctx, msg, vid, C, p, ravk);

	bool retval = true;

	for(int i=0; i<NUMZK; i++) {
		if (!(in >> zk[i]) || !zk[i].verifyProof(vidstr, C, ravk, vavk, p)) {
            std::cerr << "  !!!!!!!! zkfails: " << zk[i].str() << endl;
			retval = false;
		}
		H(ctx, zk[i]);

	}

	// check the hash for zeroes
	for(int i=0; i<NUMZK; i++) {
		cci = ctx[0];
		H2(&cci, zk[i]);
		sha256_end(hval, &cci);

	 	if ( hval[0] != 0 || (hval[1]&0xf)!= 0 ) {
	 		log("Hash of proof is not valid.","");
	 		retval = false;
	 	}
	}

	if (!retval) { return 0; }

	// output the token struct
	sr->msg = strdup(msg);
	ostringstream out;
	out << C;
	sr->token = strdup(out.str().c_str());

	return 1;

}

// =========================================================================
// =========================================================================

void initAnonize() {
	if (!p.setupParams()) {
		log("Cannot initialize math libraries. Exiting.","");
	}
}




