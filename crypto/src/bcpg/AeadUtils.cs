using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    public sealed class AeadUtils
    {
        /**
         * Return the length of the IV used by the given AEAD algorithm in octets.
         * 
         * @param aeadAlgorithmTag AEAD algorithm identifier
         * @return length of the IV
        */
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

        /**
         * Return the length of the authentication tag used by the given AEAD algorithm in octets.
         *
         * @param aeadAlgorithmTag AEAD algorithm identifier
         * @return length of the auth tag
         */
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

        /**
         * Split a given byte array containing <pre>m</pre> bytes of key and <pre>n-8</pre> bytes of IV into
         * two separate byte arrays.
         * <pre>m</pre> is the key length of the cipher algorithm, while <pre>n</pre> is the IV length of the AEAD algorithm.
         * Note, that the IV is filled with <pre>n-8</pre> bytes only, the remainder is left as 0s.
         * Return an array of both arrays with the key and index 0 and the IV at index 1.
         *
         * @param messageKeyAndIv <pre>m+n-8</pre> bytes of concatenated message key and IV
         * @param cipherAlgo      symmetric cipher algorithm
         * @param aeadAlgo        AEAD algorithm
         * @return array of arrays containing message key and IV
         */
        public static byte[][] SplitMessageKeyAndIv(byte[] messageKeyAndIv, SymmetricKeyAlgorithmTag cipherAlgo, AeadAlgorithmTag aeadAlgo)
        {
            int keyLen = PgpUtilities.GetKeySizeInOctets(cipherAlgo);
            int ivLen = GetIVLength(aeadAlgo);
            byte[] messageKey = new byte[keyLen];
            byte[] iv = new byte[ivLen];

            Array.Copy(messageKeyAndIv, messageKey, messageKey.Length);
            Array.Copy(messageKeyAndIv, messageKey.Length, iv, 0, ivLen-8);

            return new byte[][] { messageKey, iv };
        }
    }
}