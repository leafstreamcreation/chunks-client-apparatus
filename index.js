import 'dotenv/config';

import axios from "axios";

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
        if (res.status === 200) {
            console.log("Ping: ", res.data);
        }
        else console.log("Ping: Error");
    }).catch((err) => {
        console.log('ERROR: ', err);
    });
}

function invite([ticket, password = process.env.ADMIN_PASS]) {
    //handle no ticket
    //handle deadbeef ticket
    //handle deadbeef password
    //axios with ticket and pw in body
    
    //console ticket creation success
    //or console failure
    console.log('INVITE');
}

function signup([ticket, name = "User", password = "secret123"]) {
    //handle no ticket
    //handle deadbeef ticket / name / password

    //encrypt ticket
    //add separator and encrypt credentials
    //axios with encrypted params in body

    //console failure
    //or decrypt token and updateKey
    //then console name, activities, updateKey
    console.log('SIGNUP');
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

function update([ update = 0, body = "deadbeef", name = "User", password = "secret123" ]) {
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

clientRequest(process.argv.slice(2));

