using System;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLKemPublicKeyParameters
        : MLKemKeyParameters
    {
        public static MLKemPublicKeyParameters FromEncoding(MLKemParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));

            var engine = parameters.ParameterSet.Engine;

            if (encoding.Length != engine.PublicKeyBytes)
                throw new ArgumentException("Invalid length", nameof(encoding));

            encoding = Arrays.InternalCopyBuffer(encoding);

            if (!engine.CheckEncapKeyModulus(encoding))
                throw new ArgumentException("Modulus check failed", nameof(encoding));

            return new MLKemPublicKeyParameters(parameters, encoding);
        }

        internal readonly byte[] m_encoding;

        internal MLKemPublicKeyParameters(MLKemParameters parameters, byte[] encoding)
            : base(isPrivate: false, parameters)
        {
            m_encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
        }

        internal byte[] Encoding => m_encoding;

        public byte[] GetEncoded() => Arrays.InternalCopyBuffer(m_encoding);

        // NB: Don't remove - needed by commented-out test cases
        internal Tuple<byte[], byte[]> InternalEncapsulate(byte[] randBytes)
        {
            if (randBytes.Length != MLKemEngine.SymBytes)
                throw new ArgumentException("Invalid length", nameof(randBytes));

            var engine = Parameters.ParameterSet.Engine;

            byte[] enc = new byte[engine.CipherTextBytes];
            byte[] sec = new byte[MLKemEngine.SharedSecretBytes];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            engine.KemEncrypt(Encoding.AsSpan(), randBytes.AsSpan(), enc.AsSpan(), sec.AsSpan());
#else
            engine.KemEncrypt(Encoding, randBytes, enc, 0, sec, 0);
#endif
            return Tuple.Create(enc, sec);
        }
    }
}
