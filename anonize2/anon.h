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

// export pure C functions to facilitate linking with GO program

#define ANONIZE_VERSION "2.0.0"

typedef struct _createsurveyresult {
	const char* vid;
	const char* vavk;
	const char* sigs;	/* newline delimmited list of signatures on (vid,uid) */
	int cnt;
	const char* vask;
} survey;

typedef struct _surveyresponse {
	const char* msg;	/* msg submitted by user */
	const char* token;	/* the F_sid(vid) that is unique but unpredicatable for ea user */
} survey_response;



/** The initAnonize method must be called before any other calls are made to 
   the library.
*/
void initAnonize();


const char* printParams();

/** the makeCred routine makes an empty credential for the uid.
    The caller must manage the memory for the string returned by makeCred
    when the call is successful.  This function returns "" on failure.
*/
const char* makeCred(const char* uid);


/** Makes a key pair for RAVK or VAVK, writes into vk and sk buffers
    Returns 1 on success, 0 on failure
*/
int makeKey(char vk[2048], char sk[2048]);


/** Creates an empty survey structure.
*/
int createSurvey(survey* s);

/** Adds emails to the survey structure
*/
int extendSurvey(const char* emails, survey* s);

/** Frees the memory associated with survey structure
*/
void freeSurvey(survey* s);
void freeSurveyResponse(survey_response* sr);


// all of these functions return strings that the caller is responsible for freeing
// when the calls are successful.  on failure, the calls return "" which should not be freed
const char* registerUserMessage(const char* cred, const char* vk);
const char* registerServerResponse(const char* userid, const char* usermsg, const char* raskey);
const char* registerUserFinal(const char* userid, const char* servermsg, const char* cred, const char* vk);

const char* submitMessage(const char* msg, const char* cred, const char* ravk_str, const char* uidsig, const char* vidstr, const char* vavk_str);
int verifyMessage(const char* proof, const char* ravk_str, const char* vidstr, const char* vavk_str, survey_response* sr);

