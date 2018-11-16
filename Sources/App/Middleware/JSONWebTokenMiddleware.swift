

import Vapor
import JWT
import Fluent
import Foundation

struct JWTConfig {
    
    static let `default` = JWTConfig(signer: JWTSigner.hs256(key: "yLhpjF7mDKE5miyR7uVBEbwv"),
                                     expirationTime: 1000)
    var signer: JWTSigner
    var expirationTime: TimeInterval
}

class JSONWebTokenMiddleware: Middleware {
    
    var jwtConfig = JWTConfig.default
    
    func respond(to request: Request, chainingTo next: Responder) throws -> Future<Response> {
        
        try JWTHelper.extractJWT(from: request, config: jwtConfig)
        return try next.respond(to: request)
    }
}

struct JWTUser: JWTPayload {
    let userId: UUID
    let exp: ExpirationClaim
    
    func verify(using signer: JWTSigner) throws {
        // nothing to verify
    }
}

struct JWTHelper {
    
    static func user(from request: Request, config: JWTConfig = .default) throws -> Future<User> {
        let jwt = try extractJWT(from: request, config: config)
        
        return User.query(on: request).filter(\User.id == jwt.payload.userId).first().map {
            guard let user = $0 else {
                throw Abort(.notFound, reason: "a user with this id was not found" , identifier: nil)
            }
            
            return user
        }
    }
    
    static func jwt(for userId: UUID, config: JWTConfig = .default) throws -> (token: String, expTime: TimeInterval) {
    
        
        let jwtUser = JWTUser(userId: userId,
                              exp: ExpirationClaim(value: Date(timeIntervalSinceNow: config.expirationTime)))
        
        // create JWT and sign
        let data = try JWT(payload: jwtUser).sign(using: config.signer)
        return (String(data: data, encoding: .utf8) ?? "", config.expirationTime)
    }
    
    static func refreshJWT(for request: Request, config: JWTConfig = .default) throws -> (token: String, expTime: TimeInterval) {
        let jwt = try extractJWT(from: request, config: config)
        
        return try self.jwt(for: jwt.payload.userId)
    }
    
    @discardableResult static func extractJWT(from request: Request, config: JWTConfig = .default) throws -> JWT<JWTUser> {
        
        // Fetches the token from `Authorization: Bearer <token>` header
        guard let bearer = request.http.headers.bearerAuthorization else {
            throw Abort(.unauthorized)
        }
        
        // Parse JWT from token string, using HS-256 signer
        let jwt = try JWT<JWTUser>(from: bearer.token, verifiedUsing: config.signer)
        
        // Check the expiration date on the JWT
        try jwt.payload.exp.verifyNotExpired()
        
        return jwt
    }
}
