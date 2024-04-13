using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    public sealed class AeadUtils
    {
        /// <summary>
        /// Return the length of the IV used by the given AEAD algorithm in octets.
        /// </summary>
        /// <param name="aeadAlgorithmTag">AEAD algorithm identifier</param>
        /// <returns>length of the IV</returns>
        /// <exception cref="ArgumentException">Thrown when aeadAlgorithmTag is unknown/invalid</exception>
        public static int GetIVLength(AeadAlgorithmTag aeadAlgorithmTag)
        {
            switch (aeadAlgorithmTag)
            {
                case AeadAlgorithmTag.Eax:
                    return 16;
                case AeadAlgorithmTag.Ocb:
                    return 15;
                case AeadAlgorithmTag.Gcm:
                    return 12;
                default:
                    throw new ArgumentException($"Invalid AEAD algorithm tag: {aeadAlgorithmTag}");
            }
        }

        /// <summary>
        /// Returns the name of the AEAD Algorithm
        /// </summary>
        /// <param name="aeadAlgorithmTag">AEAD algorithm identifier</param>
        /// <returns>name of the AEAD Algorithm</returns>
        /// <exception cref="ArgumentException"></exception>

        public static string GetAeadAlgorithmName(AeadAlgorithmTag aeadAlgorithmTag)
        {
            switch (aeadAlgorithmTag)
            {
                case AeadAlgorithmTag.Eax:
                    return "EAX";
                case AeadAlgorithmTag.Ocb:
                    return "OCB";
                case AeadAlgorithmTag.Gcm:
                    return "GCM";
                default:
                    throw new ArgumentException($"Invalid AEAD algorithm tag: {aeadAlgorithmTag}");
            }
        }

        /// <summary>
        /// Return the length of the authentication tag used by the given AEAD algorithm in octets.
        /// </summary>
        /// <param name="aeadAlgorithmTag">AEAD algorithm identifier</param>
        /// <returns>length of the auth tag</returns>
        /// <exception cref="ArgumentException">Thrown when aeadAlgorithmTag is unknown/invalid</exception>
        public static int GetAuthTagLength(AeadAlgorithmTag aeadAlgorithmTag)
        {
            switch (aeadAlgorithmTag)
            {
                case AeadAlgorithmTag.Eax:
                case AeadAlgorithmTag.Ocb:
                case AeadAlgorithmTag.Gcm:
                    return 16;
                default:
                    throw new ArgumentException($"Invalid AEAD algorithm tag: {aeadAlgorithmTag}");
            }
        }

        /// <summary>
        /// Split a given byte array containing m bytes of key and n-8 bytes of IV into
        /// two separate byte arrays.
        /// m is the key length of the cipher algorithm, while n is the IV length of the AEAD algorithm.
        /// Note, that the IV is filled with <pre>n-8</pre> bytes only, the remainder is left as 0s.
        /// </summary>
        /// <param name="messageKeyAndIv">m+n-8 bytes of concatenated message key and IV</param>
        /// <param name="cipherAlgo">symmetric cipher algorithm</param>
        /// <param name="aeadAlgo">AEAD algorithm</param>
        /// <param name="messageKey">Message key</param>
        /// <param name="iv">IV</param>
        public static void SplitMessageKeyAndIv(byte[] messageKeyAndIv, SymmetricKeyAlgorithmTag cipherAlgo, AeadAlgorithmTag aeadAlgo, out byte[] messageKey, out byte[] iv)
        {
            int keyLen = PgpUtilities.GetKeySizeInOctets(cipherAlgo);
            int ivLen = GetIVLength(aeadAlgo);

            messageKey = new byte[keyLen];
            iv = new byte[ivLen];

            Array.Copy(messageKeyAndIv, messageKey, messageKey.Length);
            Array.Copy(messageKeyAndIv, messageKey.Length, iv, 0, ivLen-8);
        }
    }
}