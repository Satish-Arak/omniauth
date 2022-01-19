class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable, :omniauthable, omniauth_providers: [:github]

        def self.from_omniauth(access_token)
          data = access_token.info
          user = User.where(email: data['email']).first
      
          # Uncomment the section below if you want users to be created if they don't exist
          unless user
              user = User.create(email: data['email'],
                password: Devise.friendly_token[0,20]
            )
          end
          user
      end
end

# The reason why you're getting a 404 error is that you're 
# not setting the client_id query parameter. You should create an 
# OAuth Application in your settings and use the client_id you get there.

# So, the URL should look something like this:

# https://github.com/login/oauth/authorize?client_id=a8a7ab5b5b4c3c21c&...