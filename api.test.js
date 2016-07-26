/* jshint asi: true */

var anonize = require('.')
var underscore = require('underscore')

console.log('')
console.log('version=' + JSON.stringify(anonize.version(), null, 2))
console.log('')

var registrar = new anonize.Registrar()
console.log('registrar.publicInfo=' + JSON.stringify(registrar.publicInfo()))
console.log('')

// courtesy of http://stackoverflow.com/questions/105034/create-guid-uuid-in-javascript#2117523
var uuid = function () {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = getRandomValues(new Uint8Array(1))[0] % 16 | 0
    var v = c === 'x' ? r : (r & 0x3 | 0x8)

    return v.toString(16).toUpperCase()
  })
}
var getRandomValues = function (ab) {
  var err, i, j, octets

  if (!ab.BYTES_PER_ELEMENT) {
    err = new Error()
    err.name = 'TypeMisMatchError'
    throw err
  }
  if (ab.length > 65536) {
    err = new Error()
    err.name = 'QuotaExceededError'
    throw err
  }

  octets = require('crypto').randomBytes(ab.length * ab.BYTES_PER_ELEMENT)

  if (ab.BYTES_PER_ELEMENT === 1) ab.set(octets)
  else {
    for (i = j = 0; i < ab.length; i++, j += ab.BYTES_PER_ELEMENT) {
      ab[i] = { 2: (octets[j + 1] << 8) | (octets[j]),
                4: (octets[j + 3] << 24) | (octets[j + 2] << 16) | (octets[j + 1] << 8) | (octets[j]) }[ab.BYTES_PER_ELEMENT]
    }
  }

  return ab
}

var registrarVK = registrar.publicInfo().registrarVK

var userId = uuid()
var credential = new anonize.Credential(userId, registrarVK)
var credential_request = credential.request()
var credential_response = registrar.register(credential_request)
credential.finalize(credential_response)
console.log('credential='+JSON.stringify(credential, null, 2))
console.log('')

var server_surveyor = new anonize.Surveyor().initialize(registrarVK)
console.log('server surveyor='+JSON.stringify(server_surveyor, null, 2))
console.log('')

var signature = server_surveyor.sign(userId)
console.log('signature='+JSON.stringify(signature, null, 2))
console.log('')

var survey_getinfo = server_surveyor.publicInfo()
console.log('surveyor.publicInfo='+JSON.stringify(survey_getinfo, null, 2))
console.log('')
var client_surveyor = new anonize.Surveyor(underscore.extend({signature: signature }, survey_getinfo))
console.log('client surveyor='+JSON.stringify(client_surveyor, null, 2))
console.log('')

var submission = credential.submit(client_surveyor, { hello: 'world.' })
console.log('submission='+JSON.stringify(submission, null, 2))
console.log('')

var verification = server_surveyor.verify(submission)
console.log('verification='+JSON.stringify(verification, null, 2))
console.log('')
