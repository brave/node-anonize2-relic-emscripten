#include <node.h>
extern "C" {
#include <stdlib.h>
#include "anon.h"
}

namespace NodeAnonizeRelic {
  using v8::FunctionCallbackInfo;
  using v8::Isolate;
  using v8::Local;
  using v8::Object;
  using v8::String;
  using v8::Value;
  
  void Version(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, ANONIZE_VERSION));
  }
  
  // makeKey() -> { registrarSK: '...', registrarVK: '...' }
  void MakeKey(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    char VK[2048], SK[2048];
    if (!makeKey(VK, SK)) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "makeKey failed")));
      return;
    }

    Local<Object> result = Object::New(isolate);
    result->Set(String::NewFromUtf8(isolate, "registrarSK"), String::NewFromUtf8(isolate, SK));
    result->Set(String::NewFromUtf8(isolate, "registrarVK"), String::NewFromUtf8(isolate, VK));

    args.GetReturnValue().Set(result);
  }  

  // registerServerResponse(userId, request, registrarSK) -> '...'
  void RegisterServerResponse(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 3) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    const char *result = registerServerResponse(*v8::String::Utf8Value(args[0]), *v8::String::Utf8Value(args[1]),
						*v8::String::Utf8Value(args[2]));
    if ((!result) || (*result == '\0')) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "registerServerResponse failed")));
      return;
    }

    args.GetReturnValue().Set(String::NewFromUtf8(isolate, result));
  }

  // createSurvey() -> { surveyId: '...', surveyVK: '...', surveySK: '...' }
  void CreateSurvey(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    survey s;
    if (createSurvey(&s) <= 0) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "createSurvey failed")));
      return;
    }

    Local<Object> result = Object::New(isolate);
    result->Set(String::NewFromUtf8(isolate, "surveyId"), String::NewFromUtf8(isolate, s.vid));
    result->Set(String::NewFromUtf8(isolate, "surveyVK"), String::NewFromUtf8(isolate, s.vavk));
    result->Set(String::NewFromUtf8(isolate, "surveySK"), String::NewFromUtf8(isolate, s.vask));

    args.GetReturnValue().Set(result);
    freeSurvey(&s);
  }

  // extendSurvey(surveyId: '...', surveyVK: '...', surveySK: '...', userId) -> '...'
  void ExtendSurvey(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 4) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString() || !args[3]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    /* really have to admire the way C++ does inline GC...*/
    v8::String::Utf8Value arg0(args[0]->ToString());
    v8::String::Utf8Value arg1(args[1]->ToString());
    v8::String::Utf8Value arg2(args[2]->ToString());

    survey s;
    s.vid = *arg0;
    s.vavk = *arg1;
    s.vask = *arg2;
    s.cnt = 0;
    s.sigs = NULL;

    if ((extendSurvey(*v8::String::Utf8Value(args[3]), &s) <= 0) || (!s.sigs)) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "extendSurvey failed")));
      return;
    }

    args.GetReturnValue().Set(String::NewFromUtf8(isolate, s.sigs));
    free((void *)s.sigs);
  }

  // verifyMessage(request, registrarVK, surveyId, surveyVK) -> { data: '...', token: '...' }
  void VerifyMessage(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 4) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString() || !args[3]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    survey_response r;
    if (!verifyMessage(*v8::String::Utf8Value(args[0]), *v8::String::Utf8Value(args[1]), *v8::String::Utf8Value(args[2]),
		       *v8::String::Utf8Value(args[3]), &r)) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "verifyMessage failed")));
      return;
    }

    Local<Object> result = Object::New(isolate);
    result->Set(String::NewFromUtf8(isolate, "data"), String::NewFromUtf8(isolate, r.msg));
    result->Set(String::NewFromUtf8(isolate, "token"), String::NewFromUtf8(isolate, r.token));

    args.GetReturnValue().Set(result);
    freeSurveyResponse(&r);
  }

  // makeCred(userId) -> preFlight
  void MakeCred(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 1) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    const char *result = makeCred(*v8::String::Utf8Value(args[0]));
    if ((!result) || (*result == '\0')) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "makeCred failed")));
      return;
    }

     args.GetReturnValue().Set(String::NewFromUtf8(isolate, result));
  }

  // registerUserMessage(preFlight, registrarVK) -> '...'
  void RegisterUserMessage(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 2) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString() || !args[1]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    const char *result = registerUserMessage(*v8::String::Utf8Value(args[0]), *v8::String::Utf8Value(args[1]));
    if ((!result) || (*result == '\0')) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "registerUserMessage failed")));
      return;
    }

     args.GetReturnValue().Set(String::NewFromUtf8(isolate, result));
  }

  // registerUserFinal(userId, response, preFlight, registrarVK) -> masterUserToken
  void RegisterUserFinal(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 4) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString() || !args[3]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    const char *result = registerUserFinal(*v8::String::Utf8Value(args[0]), *v8::String::Utf8Value(args[1]),
					   *v8::String::Utf8Value(args[2]), *v8::String::Utf8Value(args[3]));
    if ((!result) || (*result == '\0')) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "registerUserFinal failed")));
      return;
    }

     args.GetReturnValue().Set(String::NewFromUtf8(isolate, result));
  }

  // submitMessage(message, masterUserToken, registrarVK, userIdSignature, surveyId, surveyVK) -> '...'
  void SubmitMessage(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() != 6) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument count")));
      return;
    }
    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString() || !args[3]->IsString() || !args[4]->IsString()
	    || !args[5]->IsString()) {
      isolate->ThrowException(v8::Exception::TypeError(String::NewFromUtf8(isolate, "wrong argument syntax")));
      return;
    }

    const char *result = submitMessage(*v8::String::Utf8Value(args[0]), *v8::String::Utf8Value(args[1]),
				       *v8::String::Utf8Value(args[2]), *v8::String::Utf8Value(args[3]),
				       *v8::String::Utf8Value(args[4]), *v8::String::Utf8Value(args[5]));
    if ((!result) || (*result == '\0')) {
      isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "submitMessage failed")));
      return;
    }

     args.GetReturnValue().Set(String::NewFromUtf8(isolate, result));
  }

  void Init(Local<Object> exports) {
    initAnonize();

    NODE_SET_METHOD(exports, "version", Version);
    NODE_SET_METHOD(exports, "makeKey", MakeKey);
    NODE_SET_METHOD(exports, "registerServerResponse", RegisterServerResponse);
    NODE_SET_METHOD(exports, "createSurvey", CreateSurvey);
    NODE_SET_METHOD(exports, "extendSurvey", ExtendSurvey);
    NODE_SET_METHOD(exports, "verifyMessage", VerifyMessage);
    NODE_SET_METHOD(exports, "makeCred", MakeCred);
    NODE_SET_METHOD(exports, "registerUserMessage", RegisterUserMessage);
    NODE_SET_METHOD(exports, "registerUserFinal", RegisterUserFinal);
    NODE_SET_METHOD(exports, "submitMessage", SubmitMessage);
  }
  
  NODE_MODULE(addon, Init)
}
