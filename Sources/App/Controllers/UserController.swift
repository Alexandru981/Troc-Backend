
import Vapor
import Fluent
import Foundation
import Crypto
import JWT

final class UserController: RouteCollection {
    
    func boot(router: Router) throws {
        let users = router.grouped("users")
        
        users.post(User.self, use: create)
        users.post(UserToRegister.self, at: "register", use: registerUser)
        users.post(UserCredetials.self, at: "login", use: login)
        users.get("refresh", use: refreshToken)
        users.get(use: index)
        users.get(User.parameter, use: show)
        users.delete(User.parameter, use: delete)
        
    }
    
    func registerUser(_ request: Request, newUser: UserToRegister) throws -> Future<HTTPResponseStatus> {
        
        return User.query(on: request).filter(\.email == newUser.email).first().flatMap { existingUser in
            
            guard existingUser == nil else {
                throw Abort(.badRequest, reason: "a user with this email already exists" , identifier: nil)
            }
            
            let digest = try request.make(BCryptDigest.self)
            let hashedPassword = try digest.hash(newUser.password)
            let persistedUser = User(email: newUser.email,
                                     password: hashedPassword,
                                     name: newUser.name,
                                     role: .user)
            
            
            return persistedUser.save(on: request).transform(to: .created)
        }
    }
    
    func login(_ request: Request, credentials: UserCredetials) throws -> Future<LoggedInUser> {
        return User.query(on: request).filter(\.email == credentials.email).first().map { existingUser in
            
            guard let existingUser = existingUser else {
                throw Abort(.notFound, reason: "a user with this email does not exist" , identifier: nil)
            }
            
            guard try BCrypt.verify(credentials.password, created: existingUser.password) else {
                throw Abort(.unauthorized, reason: "invalid authorization" , identifier: nil)
            }
            
            let jwt = try JWTHelper.jwt(for: existingUser.id!)
            
            return LoggedInUser(user: existingUser,
                                token: jwt.token,
                                tokenExpiration: jwt.expTime)
            
        }
    }//Test
    
    func refreshToken(_ request: Request) throws -> JWTResponse {
        let jwt = try JWTHelper.refreshJWT(for: request)
        return JWTResponse(token: jwt.token,
                           tokenExpiration: jwt.expTime)
    }
    
    func index(_ request: Request)throws -> Future<[User]> {
        return User.query(on: request).all()
    }
    
    func show(_ request: Request)throws -> Future<User> {
        return try request.parameters.next(User.self)
    }
    
    func create(_ request: Request, _ user: User)throws -> Future<User> {
        return user.create(on: request)
    }
    
    
    
    func delete(_ request: Request) throws -> Future<HTTPStatus> {
        return try request.parameters.next(User.self).delete(on: request).transform(to: .noContent)
    }
}

struct UserToRegister: Content {
    let email: String
    let password: String
    let name: String
}

struct UserCredetials: Content {
    let email: String
    let password: String
}

struct LoggedInUser: Content {
    let user: User
    let token: String
    let tokenExpiration: TimeInterval
}

struct JWTResponse: Content {
    let token: String
    let tokenExpiration: TimeInterval
}
