#!/usr/bin/env node
const SMTPServer = require('smtp-server').SMTPServer;
const simpleParser = require('mailparser').simpleParser;
const express = require("express");
const basicAuth = require('express-basic-auth');
const path = require("path");
const _ = require("lodash");
const moment = require("moment");
const cli = require('cli').enable('catchall').enable('status');
const fs = require('fs');
require('dotenv').config()

const smtpAuth = process.env.SMTP_AUTH || "admin:password"
const smtpPort =  process.env.SMTP_PORT || 1025
const smtpIp = process.env.SMTP_IP || '0.0.0.0'
const httpPort = process.env.WEB_PORT || 1080
const httpIp = process.env.WEB_IP || '0.0.0.0'
const whitelist = process.env.WHITE_LIST || ""
const max = 100
const auth = process.env.WEB_AUTH || 'admin:password'
const secure = process.env.SECURE || true
const keystore = false //'Path to PKCS12 keystore used for Secure option or when using STARTTLS'
const passphrase = '' //Passphrase for PKCS12 private key
const headers = true //'Enable headers in responses'

cli.info(smtpAuth)
// const whitelist = whiteList ? whiteList.split(',') : [];

let users = null;
if (auth && !/.+:.+/.test(auth)) {
    cli.error("Please provide authentication details in USERNAME:PASSWORD format");
    console.log(process.exit(1))
}
if (auth) {
  let authConfig = auth.split(":");
  users = {};
  users[authConfig[0]] = authConfig[1];
}

const smtpUsers = smtpAuth ? smtpAuth.split(',').map(up => up.split(":")) : null;

const mails = [];

const serverOptions = {
  authOptional: true,
  maxAllowedUnauthenticatedCommands: 1000,
  onMailFrom(address, session, cb) {
    if (whitelist.length == 0 || whitelist.indexOf(address.address) !== -1) {
      cb();
    } else {
      cb(new Error('Invalid email from: ' + address.address));
    }
  },
  onAuth(auth, session, callback) {
    cli.info('SMTP login for user: ' + auth.username);
    callback(null, {
      user: auth.username
    });
  },
  onData(stream, session, callback) {
    parseEmail(stream).then(
      mail => {
        cli.debug(JSON.stringify(mail, null, 2));

        mails.unshift(mail);

        //trim list of emails if necessary
        while (mails.length > max) {
          mails.pop();
        }

        callback();
      },
      callback
    );
  }
};

if (smtpUsers) {
  serverOptions.onAuth = smtpAuthCallback;
  serverOptions.authOptional = false;
}

if (secure) {
  serverOptions.secure = true;
}

if (keystore) {
  if (!fs.existsSync(keystore)) {
    cli.error(`Keystore ${keystore} did not exists`);
    console.log(process.exit(1));
  }

  serverOptions.pfx = fs.readFileSync(keystore);
  if (passphrase)
    serverOptions.passphrase = passphrase;
  else
    cli.warn('PFX option set without passphrase');
}

cli.info(`Options = ${JSON.stringify(serverOptions)}`);

const server = new SMTPServer(serverOptions);

function smtpAuthCallback(auth, session, callback) {
  const username = auth.username;
  const password = auth.password;

  cli.info(`${username} is trying to login with password ${password}`);

  if (smtpUsers.find(e => (e[0] === username && e[1] === password)))
    callback(null, {user: username});
  else
    callback(new Error('Invalid username or password'));
}

function formatHeaders(headers) {
  const result = {};
  for (const [key, value] of headers) {
    result[key] = value;
  }
  return result;
}

function parseEmail(stream) {
  return simpleParser(stream).then(email => {
    if (headers) {
      email.headers = formatHeaders(email.headers);
    } else {
      delete email.headers;
    }
    return email;
  });
}

server.on('error', err => {
  cli.error(err);
});

server.listen(smtpPort, smtpIp);

const app = express();

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});

if (users) {
    app.use(basicAuth({
        users: users,
        challenge: true
    }));
}

const buildDir = path.join(__dirname, 'build');

app.use(express.static(buildDir));

function emailFilter(filter) {
  return email => {
    if (filter.since || filter.until) {
      const date = moment(email.date);
      if (filter.since && date.isBefore(filter.since)) {
        return false;
      }
      if (filter.until && date.isAfter(filter.until)) {
        return false;
      }
    }

    if (filter.to && _.every(email.to.value, to => to.address !== filter.to)) {
      return false;
    }

    if (filter.from && _.every(email.from.value, from => from.address !== filter.from)) {
      return false;
    }

    return true;
  }
}

app.get('/api/emails', (req, res) => {
  res.json(mails.filter(emailFilter(req.query)));
});

app.delete('/api/emails', (req, res) => {
    mails.length = 0;
    res.send();
});

app.listen(httpPort, httpIp, () => {
  cli.info("HTTP server listening on http://" + httpIp +  ":" + httpPort);
});

cli.info("SMTP server listening on " + smtpIp + ":" + smtpPort);
