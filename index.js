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
        const cTicket = pack(ticket);
        const cCreds = packCredentials(name, password);
        return { body: { ticket: cTicket, credentials: cCreds } };
    }, (res) => {
        const { token, activities, updateKey } = res.data;
        const { name: tName, password: tPass } = unpackToken(token);
        const key = unpackKey(updateKey, tName);
        return Promise.resolve([tName, tPass, key, activities]);
    });
}

function login([name = "User", password = "secret123"]) {
    //handle deadbeef name / password
    if (name === "deadbeef" || password === "deadbeef") post("/login");
    else post("/login", () => {
            const cCreds = packCredentials(name, password);
            return { body: { credentials: cCreds } };
        }, (res) => {
            const { token, activities, updateKey } = res.data;
            const { name: tName, password: tPass } = unpackToken(token);
            const key = unpackKey(updateKey, tName);
            return Promise.resolve([tName, tPass, key, activities]);
    });
}

function update([ update = "1", body = "deadbeef", name = "User", password = "secret123" ]) {
    //handle deadbeef name / password / update
    if (name === "deadbeef" || password === "deadbeef" || update === "deadbeef") post("/update", () => {
        const rBody = body !== "deadbeef" ? parseUpdateBody(body) : undefined;
        return { body: rBody };
    });
    else post("/update", () => {
            const headers = packHeaders(name, password, update);
            const rBody = body !== "deadbeef" ? parseUpdateBody(body) : undefined;
            return { body: rBody, headers };
        }, (res) => {
            const { updateKey } = res.data;
            const output = updateKey ? [ unpackKey(updateKey, name) ] : [ res.status, res.data ];
            return Promise.resolve(output);
    });
}.0``

function parseUpdateBody(updateStr) {
    const instructions = []
    const opStrs = updateStr.split("~z");
    for (const opStr of opStrs) {
        const [ op, ...val ] = opStr.split("^&");
        if (op === "1") {
            //delete
            const [ id ] = val;
            if (id && id !== "!?") instructions.push({ op: parseInt(op), id: parseInt(id) });
        }
        else if (op === "2") {
            //edit
            const [ id, history, name ] = val;
            if (id && id !== "!?" && history && !(history === "!?" && (!name || name === "!?"))) {
                const nVal = { history: JSON.parse(history) };
                if (name && name !== "!?") nVal.name = name;
                instructions.push({ op: parseInt(op), id: parseInt(id), val: nVal });
            }
        }
        else if (op === "3") {
            const [ id, history, name, group ] = val;
            if (
                id && id !== "!?" &&
                history && history !== "!?" &&
                name && name !== "!?" &&
                group && group !== "!?" 
            ) instructions.push({
                op: parseInt(op),
                id: parseInt(id),
                val: {
                    history: JSON.parse(history),
                    name
                }
            });
        }
    }
    return instructions.length === 0 ? undefined : instructions;
}

function packHeaders(name, password, update) {
    const token = tokenGen(name, password);
    const key = CryptoJS.AES.encrypt(update, name + `${process.env.APP_SIGNATURE + process.env.OUTBOUND_KEY}`).toString();
    return {
        name: token.name,
        credentials: token.credentials,
        update: key
    };
}

function tokenGen(name, password, mutator = (n,p) => n + (p ? process.env.CRED_SEPARATOR + p : "")) {
    const encName = CryptoJs.AES.encrypt(name, `${process.env.APP_SIGNATURE + process.env.OUTBOUND_NAME}`);
    const nameToken = encName.toString();
    const literal = mutator(name, password);
    const encCred = CryptoJs.AES.encrypt(literal, name + `${process.env.APP_SIGNATURE + process.env.OUTBOUND_CRED}`);
    const credToken = encCred.toString();
    return { name:nameToken, credentials:credToken };
}

function post(url, propGenerator = () => undefined, postResponse = (res) => Promise.resolve([res.status, res.data])) {
    const props = propGenerator();
    instance.post(url, props?.body || {}, { headers: props?.headers })
        .then(postResponse)
        .then((out) => { console.log("RES: ", ...out); })
        .catch((err) => { console.log(err.response ? [err.response.status, err.response.data] : err); });
}

function pack(val) {
    const litStr = `${val}`;
    return CryptoJs.AES.encrypt(litStr, `${process.env.CLIENT_KEY}`).toString();
}

function packCredentials(name, password) {
    return pack(name + process.env.CRED_SEPARATOR + password);
}

function unpackToken({ name: cName, credentials: cCred }) {
    const name = CryptoJs.AES.decrypt(cName, `${process.env.APP_SIGNATURE + process.env.OUTBOUND_NAME}`).toString(CryptoJs.enc.Utf8);
    const credentials = CryptoJs.AES.decrypt(cCred, name + `${process.env.APP_SIGNATURE + process.env.OUTBOUND_CRED}`).toString(CryptoJs.enc.Utf8);
    const [ _, password ] = credentials.split(process.env.CRED_SEPARATOR);
    return { name, password };
}

function unpackKey(cKeyIn, name) {
    return CryptoJs.AES.decrypt(cKeyIn, name + `${process.env.APP_SIGNATURE}${process.env.OUTBOUND_KEY}`).toString(CryptoJs.enc.Utf8);
}

clientRequest(process.argv.slice(2));

