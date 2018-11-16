
import Vapor
import Foundation
import FluentPostgreSQL
import Authentication

enum UserRole: String, PostgreSQLEnum {
    case user
    case admin
}

struct User: Content {
    var id: UUID?
    private(set) var email: String
    private(set) var password: String
    var name: String
    var role: UserRole {
        return UserRole(rawValue: _role) ?? .user
    }
    private var _role: String
}

extension User {
    init(email: String, password: String, name: String, role: UserRole = .user) {
        self.email = email
        self.password = password
        self.name = name
        self._role = role.rawValue
    }
}

extension User: Migration {}
extension User: Model {
    typealias Database = PostgreSQLDatabase
    
    static var idKey: WritableKeyPath<User, UUID?> {
        return \.id
    }
}

extension User: Parameter {}
extension User: PasswordAuthenticatable {
    /// See `PasswordAuthenticatable`.
    static var usernameKey: WritableKeyPath<User, String> {
        return \.email
    }
    
    /// See `PasswordAuthenticatable`.
    static var passwordKey: WritableKeyPath<User, String> {
        return \.password
    }
}
