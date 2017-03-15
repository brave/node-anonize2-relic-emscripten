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

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>


extern "C" {
#include "anon.h"
}

void pretty(const char* str, const char* title) {
	printf("%s:\n",title);
	const char *p = str;
	do {
		char *l = strchr(p, '\n');
		if (l) {
			printf("         %.*s\n", (int)(l-p),p);
			p = l+1;
		} else { 
			printf("         %s\n", p);
			p = l;
		}
	} while (p);
}

int main() {

	initAnonize();

	for(int i=0; i<1; i++) {

	// make keys

		char RAVK[2048], RASK[2048];
		if (!makeKey(RAVK,RASK)) {
			fprintf(stderr, "!!!! error making keys.");
			exit(1);
		}
		printf("%s\n\n",RAVK);
		printf("%s\n\n",RASK);


		// make cred
		const char* uid = "abhi@virginia.edu";

		const char* precred = makeCred(uid);
		const char* reg1 = registerUserMessage(precred, RAVK);
		const char* reg2 = registerServerResponse(uid, reg1, RASK);
		const char* cred = registerUserFinal(uid, reg2, precred, RAVK);

		pretty(cred,"cred");

		const char* emails = "abhi@virginia.edu\nbob\nalice\nAnita\n87f98s8d97\nTasiuhfdiuashdf\neiufwueh";
		const char* emails2 = "efwefwe\nbdfsdfwew\nalfwew2ice\nAn2ita\nsdfsDfsdf\nedfsdfwewwueh";
		survey s;


		printf(" ******************************************** \n\n");

		const char* uidsig;

		if (createSurvey(&s) != 1) {
			fprintf(stderr, "!!!! ERROR CREATING Survey!\n");
			exit(1);		
		} 

		if (extendSurvey(emails, &s) != 7) {
			fprintf(stderr, "!!!! ERROR extending Survey!\n");
			exit(1);		
		}
		if (extendSurvey(emails2, &s) != 6) {
			fprintf(stderr, "!!!! ERROR extending Survey!\n");
			exit(1);		
		}


		pretty(s.vid,"vid");
		pretty(s.vavk,"vavk");
		pretty(s.sigs,"sigs");

		if (strncmp(uid,s.sigs, strlen(uid)) != 0) {
			fprintf(stderr,"!!!! error making survey\n");
			exit(1);
		} else {
			uidsig = s.sigs+ strlen(uid) + 1;
			//pretty(uidsig, "uidsig");

			const char* msg;

			auto start = std::chrono::high_resolution_clock::now();

			msg = submitMessage("[\"hello test\"]", cred, RAVK, uidsig, s.vid, s.vavk);
			auto elapsed = std::chrono::high_resolution_clock::now() - start;
			long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();


			printf("  elapsed: %lld len:%zu\n", microseconds/1, strlen(msg));

			pretty(msg,"msg");
			pretty(RAVK,"ravk");
			pretty(s.vid,"s.vid");
			pretty(s.vavk,"s.vavk");

			survey_response sr;
			int r = verifyMessage(msg, RAVK, s.vid, s.vavk, &sr);
			if (!r) {
				printf(" === fail ===\n");
				exit(1);
			} else {
				printf(" === SUCCEED ===\n");
			}

			freeSurvey(&s);
			freeSurveyResponse(&sr);
			if (msg) { free((void*)msg); msg=NULL; }
		}

		if (precred) { free((void*)precred); precred=NULL; }
		if (reg1) { free((void*)reg1); reg1=NULL; }
		if (reg2) { free((void*)reg2); reg2=NULL; }
		if (cred) { free((void*)cred); cred=NULL; }


	}



	return 0;
}
