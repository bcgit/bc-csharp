using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class BlowfishParameters
        : KeyParameter
    {
        /**
        * Blowfish takes a variable-length key, from 32 bits to 448 bits [1].
        *
        * Some implementations like OpenSSL [2] and Nettle [3] do not restrict the key size.
        * Other algorithms like bcrypt [4] assume that Blowfish supports keys up to 576 bits,
        * which is the maximum size for which all bits of the key will be used
        * to initialize the P box, assuming the designed 16 rounds.
        *
        * For interoperability, BlowfishParameters can be created with an extended key,
        * using the `extendedKey` parameter. It is not restricted in length,
        * as neither OpenSSL nor Nettle restricts it, but only the first 576 bits 
        * will be used if longer.
        *
        * [1] https://datatracker.ietf.org/doc/html/draft-schneier-blowfish-00
        * [2] https://github.com/openssl/openssl/blob/openssl-3.0/crypto/bf/bf_skey.c#L31
        * [3] https://github.com/gnutls/nettle/blob/nettle_3.8.1_release_20220727/blowfish.c#L386
        * [4] https://github.com/bcgit/bc-csharp/blob/release/v2.3/crypto/src/crypto/generators/BCrypt.cs#L587
        */
        private const int MinKeyLen = 4;
        private const int MaxKeyLen = 56;

        public BlowfishParameters(
            byte[]    key,
            bool      extendedKey = false)
            : base(key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length < MinKeyLen || (!extendedKey && key.Length > MaxKeyLen))
                throw new ArgumentException($"key length must be in range {MinKeyLen * 8} to {MaxKeyLen * 8} bits");
        }

        public bool IsExtendedKey
        {
            get { return KeyLength > MaxKeyLen; }
        }
    }
}
