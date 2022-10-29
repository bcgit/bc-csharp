using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssSignature
        : IEncodable
    {
        private int lMinus1;
        private LmsSignedPubKey[] signedPubKey;
        private LmsSignature signature;

        public HssSignature(int lMinus1, LmsSignedPubKey[] signedPubKey, LmsSignature signature)
        {
            this.lMinus1 = lMinus1;
            this.signedPubKey = signedPubKey;
            this.signature = signature;
        }

        /**
         * @param src byte[], InputStream or HSSSignature
         * @param L   The HSS depth, available from public key.
         * @return An HSSSignature instance.
         * @throws IOException
         */
        public static HssSignature GetInstance(object src, int L)
        {
            if (src is HssSignature hssSignature)
            {
                return hssSignature;
            }
            else if (src is BinaryReader binaryReader)
            {
                int lminus = BinaryReaders.ReadInt32BigEndian(binaryReader);
                if (lminus != L - 1)
                    throw new Exception("nspk exceeded maxNspk");

                LmsSignedPubKey[] signedPubKeys = new LmsSignedPubKey[lminus];
                if (lminus != 0)
                {
                    for (int t = 0; t < signedPubKeys.Length; t++)
                    {
                        signedPubKeys[t] = new LmsSignedPubKey(LmsSignature.GetInstance(src),
                            LmsPublicKeyParameters.GetInstance(src));
                    }
                }

                LmsSignature sig = LmsSignature.GetInstance(src);

                return new HssSignature(lminus, signedPubKeys, sig);
            }
            else if (src is byte[] bytes)
            {
                BinaryReader input = null;
                try // 1.5 / 1.6 compatibility
                {
                    input = new BinaryReader(new MemoryStream(bytes));
                    return GetInstance(input, L);
                }
                finally
                {
                    if (input != null) input.Close();
                }
            }
            else if (src is MemoryStream memoryStream)
            {
                return GetInstance(Streams.ReadAll(memoryStream), L);
            }

            throw new ArgumentException($"cannot parse {src}");
        }

        // FIXME
        public int GetlMinus1()
        {
            return lMinus1;
        }

        public LmsSignedPubKey[] GetSignedPubKeys()
        {
            return signedPubKey;
        }

        public LmsSignature Signature => signature;

        public override bool Equals(Object o)
        {
            if (this == o)
            {
                return true;
            }

            if (o == null || GetType() != o.GetType())
            {
                return false;
            }

            HssSignature signature1 = (HssSignature) o;

            if (lMinus1 != signature1.lMinus1)
            {
                return false;
            }

            // FIXME
            // Probably incorrect - comparing Object[] arrays with Arrays.equals

            if (signedPubKey.Length != signature1.signedPubKey.Length)
            {
                return false;
            }

            for (int t = 0; t < signedPubKey.Length; t++)
            {
                if (!signedPubKey[t].Equals(signature1.signedPubKey[t]))
                {
                    return false;
                }
            }

            return signature != null ? signature.Equals(signature1.signature) : signature1.signature == null;
        }

        public override int GetHashCode()
        {
            int result = lMinus1;
            result = 31 * result + signedPubKey.GetHashCode();
            result = 31 * result + (signature != null ? signature.GetHashCode() : 0);
            return result;
        }

        public byte[] GetEncoded()
        {
            Composer composer = Composer.Compose();
            composer.U32Str(lMinus1);
            if (signedPubKey != null)
            {
                foreach (LmsSignedPubKey sigPub in signedPubKey)
                {
                    composer.Bytes(sigPub);
                }
            }

            composer.Bytes(signature);
            return composer.Build();

        }

    }
}
