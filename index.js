import 'dotenv/config';

import axios from "axios";

import CryptoJs from 'crypto-js';

const instance = axios.create({
    baseURL: process.env.BACKEND_URL,
    timeout: 1000
});

function clientRequest(args) {
    if (args[0] === "ping") ping();
    else if (args[0] === "invite") invite(args.slice(1));
    else if (args[0] === "signup") signup(args.slice(1));
    else if (args[0] === "login") login(args.slice(1));
    else if (args[0] === "update") update(args.slice(1));
    else console.log("invalid request: use ping, invite, signup, login, or update");
}

function ping() {
    instance.get("/").then((res) => {
        console.log("Ping: ", res.status, res.data);
    }).catch((err) => {
        console.log('ERROR: ', err.response.status, err.response.data);
    });
}

function invite([ticket, password = process.env.ADMIN_PASS]) {
    //handle no ticket
    if (!ticket || ticket === "deadbeef") post("/invite");
    //handle deadbeef password
    else if (password === "deadbeef") post("/invite", () => { return { body: { ticket } }; });
    else post("/invite", () => { return { body: { password, ticket } }; });
}

function signup([ticket, name = "User", password = "secret123"]) {
    //handle no ticket
    if (!ticket || ticket === "deadbeef") post("/signup");
    //handle deadbeef credentials
    else if (name === "deadbeef" || password === "deadbeef") post("/signup", () => { return { body: { ticket } }; });
    else post("/signup", () => { 
        //TODO
        //encrypt ticket
        //encrypt credentials
        return { body: { ticket, name } } 
    }, (res) => {
        //TODO
        //receive token, activities, updateKey
        //decrypt and break token into name, password
        //decrypt updateKey
        //Promise.resolve array
    });
}

function login([name = "User", password = "secret123"]) {
    //handle deadbeef name / password
    
    //encrypt credentials with separator
    //axios with encrypted credentials in body

    //console failure
    //or decrypt token and updateKey
    //then console name, activities, updateKey
    console.log('LOGIN');
}

function update([ update = "0", body = "deadbeef", name = "User", password = "secret123" ]) {
    //encrypt credentials with separator and tokenGen
    //encrypt key with keygen

    //handle deadbeef body:
        //axios with encrypted name and credentials, and update in header
        
        //console failure or listening

    //handle body:
        //split body string and construct update body object
        //axios with encrypted name/creds/update in header, update body in body
        //console failure
        //or decrypt new key with revealKey
        //then console new key
    console.log('UPDATE');
}

function parseUpdateBody(bodyStr) {
    //TODO
    return [];
}

function packHeaders(name, password, update) {
    //TODO
    return {
        name,
        credentials: password,
        update
    }
}

function post(url, propGenerator = () => undefined, postResponse = (res) => Promise.resolve([res.status, res.data])) {
    const props = propGenerator();
    instance.post(url, props?.body || {}, { headers: props?.headers })
        .then(postResponse)
        .then((out) => { console.log("RES: ", ...out); })
        .catch((err) => { console.log(err.response.status, err.response.data); });
}

function pack(val) {
    const litStr = `${val}`;
    return CryptoJs.AES.encrypt(litStr, `${process.env.CLIENT_KEY}`).toString();
}

function packCredentials(name, password) {
    return pack(name + process.env.CRED_SEPARATOR + password);
}

function unpackToken({ name: cName, credentials: cCred }) {
    const name = CryptoJS.AES.decrypt(cName, `${process.env.APP_SIGNATURE + process.env.OUTBOUND_NAME}`).toString(CryptoJS.enc.Utf8);
    const credentials = CryptoJS.AES.decrypt(cCred, name + `${process.env.APP_SIGNATURE + process.env.OUTBOUND_CRED}`).toString(CryptoJS.enc.Utf8);
    const [ _, password ] = credentials.split(process.env.CRED_SEPARATOR);
    return { name, password };
}

function unpackKey(updateKey, name) {
    return CryptoJS.AES.decrypt(cKeyIn, name + `${process.env.APP_SIGNATURE}${process.env.OUTBOUND_KEY}`).toString(CryptoJS.enc.Utf8);
}

clientRequest(process.argv.slice(2));

