import bcrypt

new_salt = bcrypt.gensalt()

print(new_salt)