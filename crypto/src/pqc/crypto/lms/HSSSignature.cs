using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssSignature
        : IEncodable
    {
        private readonly int m_lMinus1;
        private readonly LmsSignedPubKey[] m_signedPubKey;
        private readonly LmsSignature m_signature;

        public HssSignature(int lMinus1, LmsSignedPubKey[] signedPubKey, LmsSignature signature)
        {
            m_lMinus1 = lMinus1;
            m_signedPubKey = signedPubKey;
            m_signature = signature;
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

        public int GetLMinus1()
        {
            return m_lMinus1;
        }

        // FIXME
        public LmsSignedPubKey[] GetSignedPubKeys()
        {
            return m_signedPubKey;
        }

        public LmsSignature Signature => m_signature;

        public override bool Equals(object other)
        {
            if (this == other)
                return true;
            if (!(other is HssSignature that))
                return false;

            if (this.m_lMinus1 != that.m_lMinus1)
                return false;

            if (this.m_signedPubKey.Length != that.m_signedPubKey.Length)
                return false;

            for (int t = 0; t < m_signedPubKey.Length; t++)
            {
                if (!this.m_signedPubKey[t].Equals(that.m_signedPubKey[t]))
                    return false;
            }

            return Equals(this.m_signature, that.m_signature);
        }

        public override int GetHashCode()
        {
            int result = m_lMinus1;
            result = 31 * result + m_signedPubKey.GetHashCode();
            result = 31 * result + (m_signature != null ? m_signature.GetHashCode() : 0);
            return result;
        }

        public byte[] GetEncoded()
        {
            Composer composer = Composer.Compose();
            composer.U32Str(m_lMinus1);
            if (m_signedPubKey != null)
            {
                foreach (LmsSignedPubKey sigPub in m_signedPubKey)
                {
                    composer.Bytes(sigPub);
                }
            }

            composer.Bytes(m_signature);
            return composer.Build();
        }
    }
}
