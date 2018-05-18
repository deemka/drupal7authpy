"""
Python port of Drupal 7 password hashing functions
from includes/password.inc.
"""
import hashlib
from os import urandom
from binascii import unhexlify
# from math import ceil

#
# The standard log2 number of iterations for password stretching. This should
# increase by 1 every Drupal version in order to counteract increases in the
# speed and power of computers available to crack the hashes.
DRUPAL_HASH_COUNT = 15

# The minimum allowed log2 number of iterations for password stretching.
DRUPAL_MIN_HASH_COUNT = 7

# The maximum allowed log2 number of iterations for password stretching.
DRUPAL_MAX_HASH_COUNT = 30

# The expected (and maximum) number of characters in a hashed password.
DRUPAL_HASH_LENGTH = 55

# Base64 mapping string
ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


#
# Parse the log2 iteration count from a stored hash or setting string.
#
def _password_get_count_log2(setting):
    return ITOA64.index(setting[3])


#
# Hash a password using a secure stretched hash.
#
# By using a salt and repeated hashing the password is "stretched". Its
# security is increased because it becomes much more computationally costly
# for an attacker to try to break the hash by brute-force computation of the
# hashes of a large number of plain-text words or strings to find a match.
#
# @param $algo
#   The string name of a hashing algorithm usable by hash(), like 'sha256'.
# @param $password
#   Plain-text password up to 512 bytes (128 to 512 UTF-8 characters) to hash.
# @param $setting
#   An existing hash or the output of _password_generate_salt().  Must be
#   at least 12 characters (the settings and salt).
#
# @return
#   A string containing the hashed password (and salt) or FALSE on failure.
#   The return string will be truncated at DRUPAL_HASH_LENGTH characters max.
#
def _password_crypt(algo, password, setting):
    # Prevent DoS attacks by refusing to hash large passwords.
    if len(password) > 512:
        return False
    # The first 12 characters of an existing hash are its setting string.
    setting = setting[:12]

    if setting[0] != '$' or setting[2] != '$':
        return False

    count_log2 = _password_get_count_log2(setting)

    # Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
    if count_log2 < DRUPAL_MIN_HASH_COUNT or count_log2 > DRUPAL_MAX_HASH_COUNT:
        return False

    salt = setting[4:12]
    # Hashes must have an 8 character salt.
    if len(salt) != 8:
        return False
    # Convert the base 2 logarithm into an integer.
    count = 1 << count_log2

    # We rely on the hash() function being available in PHP 5.2+.
    hash_ = hashlib.sha512(salt.encode('utf-8', 'strict') + password.encode('utf-8', 'strict')).hexdigest()

    for i in range(count):
        hash_ = hashlib.sha512(unhexlify(hash_) + password.encode('utf-8', 'strict')).hexdigest()

    hash_ = unhexlify(hash_)
    len_ = len(hash_)
    output = setting + _password_base64_encode(hash_, len_)

    # expected = 12 + int(ceil((8 * len_) / 6)) + 1
    # print(expected, len(output))
    # return output[:DRUPAL_HASH_LENGTH] if expected == len(output) else False
    return output[:DRUPAL_HASH_LENGTH]


#
# Encodes bytes into printable base 64 using the *nix standard from crypt().
#
# @param $input
#   The string containing bytes to encode.
# @param $count
#   The number of characters (bytes) to encode.
#
# @return
#   Encoded string
#
def _password_base64_encode(hstr, count):
    output = ''
    i = 0
    while i < count:
        value = hstr[i]
        i += 1
        output += ITOA64[value & 0x3f]
        if i < count:
            value |= hstr[i] << 8
            output += ITOA64[(value >> 6) & 0x3f]
        if i >= count:
            break
        i += 1
        if i < count:
            value |= hstr[i] << 16

        output += ITOA64[(value >> 12) & 0x3f]
        if i >= count:
            break

        output += ITOA64[(value >> 18) & 0x3f]
        i += 1

    return output


#
# Generates a random base 64-encoded salt prefixed with settings for the hash.
#
# Proper use of salts may defeat a number of attacks, including:
#  - The ability to try candidate passwords against multiple hashes at once.
#  - The ability to use pre-hashed lists of candidate passwords.
#  - The ability to determine whether two users have the same (or different)
#    password without actually having to guess one of the passwords.
#
# @param $count_log2
#   Integer that determines the number of iterations used in the hashing
#   process. A larger value is more secure, but takes more time to complete.
#
# @return
#   A 12 character string containing the iteration count and a random salt.
#
def _password_generate_salt(count_log2):
    output = '$S$'
    output += ITOA64[count_log2]
    output += _password_base64_encode(urandom(6), 6)
    return output


#
# Hash a password using a secure hash.
#
# @param $password
#   A plain-text password.
# @param $count_log2
#   Optional integer to specify the iteration count. Generally used only during
#   mass operations where a value less than the default is needed for speed.
#
# @return
#   A string containing the hashed password (and a salt), or FALSE on failure.
#
def user_hash_password(password, count_log2=None):
    if count_log2 is None:
        count_log2 = DRUPAL_HASH_COUNT

    return _password_crypt('sha512', password, _password_generate_salt(count_log2))


#
# Check whether a plain text password matches a stored hashed password.
#
# Alternative implementations of this function may use other data in the
# $account object, for example the uid to look up the hash in a custom table
# or remote database.
#
# @param $password
#   A plain-text password
# @param $account
#   A user object with at least the fields from the {users} table.
#
# @return
#   TRUE or FALSE.
#
def user_check_password(password, stored_hash):
    hash = _password_crypt('sha512', password, stored_hash)
    return (hash and stored_hash == hash)


def test(passwd=None, stored_hash=None):
    if passwd is None and stored_hash is None:
        passwd = 'password'
        stored_hash = 'stored_hash'

    print("Password hash of '{}' is {}".format(passwd, user_hash_password(passwd)))
    print("Stored hash is {}".format('valid' if user_check_password(passwd, stored_hash) else 'not valid'))

if __name__ == '__main__':
    test()
