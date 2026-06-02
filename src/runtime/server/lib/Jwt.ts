import fs from 'node:fs'
import path from 'node:path'
import consola from 'consola'
import * as jose from 'jose'
import { addConsolaPrefix } from '../../lib/addConsolaPrefix'

const Algorithm_RSA256 = 'RS256'
const PUBLIC_KEY_FILENAME = 'auth.pem.pub'
const PRIVATE_KEY_FILENAME = 'auth.pem'
const KEY_PATH = 'data/auth'

type KeyPair = { publicKey: jose.CryptoKey, privateKey: jose.CryptoKey }

export default class Jwt {
  keypair: KeyPair

  constructor(keypair: KeyPair) {
    this.keypair = keypair
  }

  static async init() {
    const publicKeyFile = path.resolve(process.cwd(), KEY_PATH, PUBLIC_KEY_FILENAME)
    const privateKeyFile = path.resolve(process.cwd(), KEY_PATH, PRIVATE_KEY_FILENAME)
    const keyPath = path.resolve(process.cwd(), KEY_PATH)

    let keyPair: KeyPair
    if (!fs.existsSync(privateKeyFile)) {
      consola.success(addConsolaPrefix(`Generating new JWT Private Key at ${keyPath}`))
      fs.mkdirSync(keyPath, { recursive: true })
      keyPair = await jose.generateKeyPair(Algorithm_RSA256, { extractable: true })
      const spkiPem = await jose.exportSPKI(keyPair.publicKey)
      fs.writeFileSync(publicKeyFile, spkiPem)
      const pkcs8Pem = await jose.exportPKCS8(keyPair.privateKey)
      fs.writeFileSync(privateKeyFile, pkcs8Pem)
    } else {
      const publicKeyFileData = fs.readFileSync(publicKeyFile, 'utf8')
      const privateKeyFileData = fs.readFileSync(privateKeyFile, 'utf8')
      keyPair = {
        publicKey: await jose.importSPKI(publicKeyFileData, Algorithm_RSA256),
        privateKey: await jose.importPKCS8(privateKeyFileData, Algorithm_RSA256),
      }
      consola.info(addConsolaPrefix(`Loaded JWT keys from at ${keyPath}`))
    }

    return new Jwt(keyPair)
  }

  async createJwt({
    payload,
    issuer,
    audience,
    expirationTime,
  }: {
    payload: jose.JWTPayload,
    issuer: string,
    audience: string,
    expirationTime: string,
  }) {
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: Algorithm_RSA256 })
      .setIssuedAt()
      .setIssuer(issuer)
      .setAudience(audience)
      .setExpirationTime(expirationTime)
      .sign(this.keypair.privateKey)
  }

  async validate({
    jwt,
    audience,
    issuer,
  }: {
    jwt: string,
    audience: string,
    issuer: string
  }) {
    const { payload } = await jose.jwtVerify(jwt, this.keypair.publicKey, {
      issuer,
      audience,
    })
    if (payload.exp == null || payload.exp * 1000 < +new Date()) {
      throw new jose.errors.JWTExpired('Authorization expired.', payload)
    }
    return payload
  }
}
