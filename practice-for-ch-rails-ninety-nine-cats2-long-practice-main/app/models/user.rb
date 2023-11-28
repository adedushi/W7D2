class User < ApplicationRecord
    validates :username, :session_token, :password_digest, presence: true
    validates :username, :session_token, uniqueness: true

    def self.find_by_credentials(username, password)
        user =  User.find_by(username: username)
            return nil if user.nil?

        if user.is_password?(password)
            return user
        else
            return nil
        end
        
    end

    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        BCrypt::Password.new(password_digest).is_password?(password)
    end

    def reset_session_token!
        self.session_token = generate_unique_session_token
        self.save!
        self.session_token
    end

    private

    def generate_unique_session_token
        session_token = SecureRandom::urlsafe_base64(16)
        return session_token unless User.exists?(session_token: session_token)
    end

    def ensure_sessions_token
        self.session_token ||= generate_unique_session_token
    end

end
