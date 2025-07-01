using System;

namespace Org.BouncyCastle.Bcpg
{
    public static class AeadUtilities
    {
        /// <summary>Return the length of the IV used by the given AEAD algorithm, in octets.</summary>
        public static int GetIVLength(AeadAlgorithmTag aeadAlgorithm)
        {
            switch (aeadAlgorithm)
            {
            case AeadAlgorithmTag.Eax:
                return 16;
            case AeadAlgorithmTag.Ocb:
                return 15;
            case AeadAlgorithmTag.Gcm:
                return 12;
            default:
                throw new ArgumentException("Invalid AEAD algorithm: " + aeadAlgorithm, nameof(aeadAlgorithm));
            }
        }

        /// <summary>Return the length of the authentication tag used by the given AEAD algorithm, in octets.</summary>
        public static int GetAuthTagLength(AeadAlgorithmTag aeadAlgorithm)
        {
            switch (aeadAlgorithm)
            {
            case AeadAlgorithmTag.Eax:
            case AeadAlgorithmTag.Ocb:
            case AeadAlgorithmTag.Gcm:
                return 16;
            default:
                throw new ArgumentException("Invalid AEAD algorithm: " + aeadAlgorithm, nameof(aeadAlgorithm));
            }
        }

        /// <summary>
        /// Split a given byte array containing <pre>m</pre> bytes of key and <pre>n-8</pre> bytes of IV into two
        /// separate byte arrays.
        /// </summary>
        /// <remarks>
        /// Note that the last 8 octets of the IV is not copied; it is left as 0s.
        /// </remarks>
        /// <returns>
        /// An array with the key at index 0 and the IV at index 1
        /// </returns>
        public static byte[][] SplitMessageKeyAndIv(byte[] messageKeyAndIv, SymmetricKeyAlgorithmTag symKeyAlgorithm,
            AeadAlgorithmTag aeadAlgorithm)
        {
            int keyLen = SymmetricKeyUtilities.GetKeyLengthInOctets(symKeyAlgorithm);
            int ivLen = GetIVLength(aeadAlgorithm);

            byte[] messageKey = new byte[keyLen];
            byte[] iv = new byte[ivLen];

            Array.Copy(messageKeyAndIv, 0, messageKey, 0, keyLen);
            Array.Copy(messageKeyAndIv, keyLen, iv, 0, ivLen - 8);

            return new byte[][]{ messageKey, iv };
        }
    }
}
