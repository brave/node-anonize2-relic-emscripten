# Anonize API

    var anonize = require('node-anonize-relic')


## Registrar

    var Registrar = anonize.Registrar
    var registrar = new Registrar()

    // return the RA's public key -- GET /publickey
    roundtrip.response(registrar.publicInfo())

    // process a credential request -- POST /register
    roundtrip.response(registrar.register(roundtrip.receive()))


## Surveyor

    // fetch registrar's publickey
    var registrarVK = roundtrip.get('/publickey').registrarVK

    // create a new surveyor
    var Surveyor = anonize.Surveyor
    var surveyor = new Surveyor().initialize(registrarVK)

    // thereafter, authorize each participant as often as needed
    var signature = surveyor.sign(userId)

    // return the surveyor's public info and user signature -- GET /surveyor/current/userId
    roundtrip.response(underscore.extend({ signature: signature }, surveyor.publicInfo()))

    // verify requests from a client -- PUT /surveyor/...
    var result = surveyor.verify(roundtrip.receive())
    // verify.data = verified data from user
    // verify.token = one-time uniqueness token for user


## Client-side

    var userId = '...'
    var registrarVK = roundtrip.get('/publickey').registrarVK

    // client creates a credential
    var Crendential = anonize.Credential
    var credential = new Credential(userId, registrarVK)

    var response = roundtrip.post('/register', credential.request())
    credential.finalize(response)

    // fetch current surveyor's public info and user signature
    var surveyor = new Surveyor(JSON.parse(roundtrip.get('/surveyor/current/' + userId)))

    // client creates a request
    var response = roundtrip.put('/surveyor/' + si.parameters.vid, credential.submit(surveyor, data))
