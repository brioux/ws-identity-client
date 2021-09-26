'use-strict';
import { KEYUTIL, b64nltohex } from "jsrsasign";
import chai, { assert } from 'chai';
import asPromised from 'chai-as-promised';
import chaiHTTP from 'chai-http';
chai.use(chaiHTTP);
const should = chai.should();
chai.use(asPromised);

import { randomBytes } from "crypto";
import { WsIdentityClient } from '../src/index';
import { WsWallet } from "ws-wallet";
import http from "http";

function startServer(port: string): Promise<http.Server> {
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(port, () => {
      resolve(server);
    });
  });
}

describe('test', async () => {
    let server,wsServer,wsWallet;
    const port = '8700';
    before(async () => {
        // For this test to work first start WsIdentityServer
        // a prebuilt docker image is available at brioux/ws-identity:0.0.4
        // TODO run this container within the test...
        wsWallet = new WsWallet({
            host: 'ws://localhost:8700/sessions',//wsServer.hostAddress,
            keyName: "admin",
            logLevel: "debug"
        })
    });
    after(async () => {
        //await wsServer.close();
        //await server.close();
    });

    let wsSessionClient;
    it('webs-socket session client constructor ', (done) =>  {
        try{
            wsSessionClient = new WsIdentityClient({
                endpoint: 'http://localhost:8700',
                pathPrefix: '/session',
            })
            done()
        }catch(error){
            done(error)
        }
    }); 
    let sessionId: string;
    let signature;
    let pubKeyHex: string;
    it('crete new session id for pubKeyHex', async () => {
        pubKeyHex = wsWallet.getPubKeyHex();
        sessionId = await wsSessionClient.write("new",{pubKeyHex});
        signature = await wsWallet.open(sessionId);
        sessionId.should.be.string;

    })
    let wsIdClient;

    let digest
    it('should sign digest', async () =>  {

        wsIdClient = new WsIdentityClient({
            endpoint: 'http://localhost:8700',
            pathPrefix: '/identity',
            sessionId: sessionId,
            signature: signature,
        })
        digest = randomBytes(16).toString("base64");
        signature = await wsIdClient.write("sign", {digest: digest});
        signature.should.be.string
        ;
    })
    it('get public key ecdsa and verify signature', async () =>  {
        const resp = await wsIdClient.read("get-pub");
        resp.should.be.string
        const pubKeyEcdsa = new KEYUTIL.getKey(resp);
        const verified = pubKeyEcdsa.verifyHex(
            b64nltohex(digest),
            b64nltohex(signature),
            pubKeyHex
        );
        verified.should.be.true
    })
})