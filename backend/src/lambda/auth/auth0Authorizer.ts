import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify} from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
// import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = 'https://dev--smdmfal.us.auth0.com/.well-known/jwks.json';

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJYDRL5HxEpRQDMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi0tc21kbWZhbC51cy5hdXRoMC5jb20wHhcNMjIwOTE3MTQ0MjI1WhcN
MzYwNTI2MTQ0MjI1WjAkMSIwIAYDVQQDExlkZXYtLXNtZG1mYWwudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp3Rj1++tlEoRvlXn
T0bkUhWsGN9mSkCo+2ld3RDRUPKBkUTSrn5OgRuFOCGAJ+i2ydQrZYEHlj/zP0m2
VN/VyzJquaQt7J0+X/72J+58aE/sJXE05R6Doc3UejRwtDdOvB0FkeM1OiRBfFtl
wUrF1gznRdoqR00sTTeYfyAxUXJlkI1KliFmuV0a90hbYfntgnld7Hix1mKIrfLU
ju7M8IBmPhbs9mvvvpYRSb6Fum0VYeheY0w9lKj7F4CSO1kMcxvkr1OV2aVRIIfM
m7K+Iqx0m7kFsBc2GP3dYWHrF57+VF0AhijYZnqMOCHmB3z250fwYlTwhpQWUcjb
QzKQewIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLns0CTg6o
8QnksNNXVoAESI0DkzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AADGESTLYFaFp4WbtMeCo9dRR6kj3gKFDeph6qqjbK3oSz2OyhXnw5AvfEu/AjKj
6hMceabueNonN27v4o4BB4oHycMLNO+WSY3ivKVdAd7ldVgmTrcIGDXGvJYUkDx0
EoPN3FSrZyQoG/SUwwyojN45KcxqSQ4nCjYmNpbDLZ43WCFb/G7tNacNgkjsuY4Z
FOqQOBgQgrYaigy9yoBrV9bts8a2asmO0AFy8CwfvJrsOkH3k+o26oWZJAO0DvCE
ZbbYhhE9t1CC6trk51v7ZOztB7qkDZsm9WoH/1hXXOnw+LmkrrzPvzCIPsgdx8Dc
WZtTupn6Vt+y9jSrHlr8/Fo=
-----END CERTIFICATE-----`;

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
//  const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
