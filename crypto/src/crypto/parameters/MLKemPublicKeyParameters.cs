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

            int publicKeyLength = parameters.ParameterSet.PublicKeyLength;
            if (encoding.Length != publicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            byte[] t = Arrays.CopySegment(encoding, 0, publicKeyLength - MLKemEngine.SymBytes);
            byte[] rho = Arrays.CopySegment(encoding, publicKeyLength - MLKemEngine.SymBytes, MLKemEngine.SymBytes);
            return new MLKemPublicKeyParameters(parameters, t, rho);
        }

        internal readonly byte[] m_t;
        internal readonly byte[] m_rho;

        internal MLKemPublicKeyParameters(MLKemParameters parameters, byte[] t, byte[] rho)
            : base(false, parameters)
        {
            var parameterSet = parameters.ParameterSet;
            var engine = parameterSet.GetEngine(random: null);

            if (t.Length != engine.PolyVecBytes)
                throw new ArgumentException("Invalid length", nameof(t));
            if (rho.Length != MLKemEngine.SymBytes)
                throw new ArgumentException("Invalid length", nameof(rho));

            if (!engine.CheckModulus(t))
                throw new ArgumentException("Modulus check failed for ML-KEM public key");

            m_t = t;
            m_rho = rho;
        }

        public byte[] GetEncoded() => Arrays.Concatenate(m_t, m_rho);

        // NB: Don't remove - needed by commented-out test cases
        internal Tuple<byte[], byte[]> InternalEncapsulate(byte[] randBytes)
        {
            var engine = Parameters.ParameterSet.GetEngine(random: null);

            byte[] enc = new byte[engine.CryptoCipherTextBytes];
            byte[] sec = new byte[engine.CryptoBytes];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            engine.KemEncrypt(enc.AsSpan(), sec.AsSpan(), this, randBytes.AsSpan());
#else
            engine.KemEncrypt(enc, 0, sec, 0, this, randBytes);
#endif
            return Tuple.Create(enc, sec);
        }
    }
}
