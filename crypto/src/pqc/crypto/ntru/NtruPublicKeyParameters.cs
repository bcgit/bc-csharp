using System;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    public sealed class NtruPublicKeyParameters
        : NtruKeyParameters
    {
        public static NtruPublicKeyParameters FromEncoding(NtruParameters parameters, byte[] encoding)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NtruPublicKeyParameters(parameters, encoding);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly byte[] m_publicKey;

        [Obsolete("Use 'FromEncoding' instead")]
        public NtruPublicKeyParameters(NtruParameters parameters, byte[] key)
            : base(privateKey: false, parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != parameters.PublicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(key));

            m_publicKey = (byte[])key.Clone();
        }

        public override byte[] GetEncoded() => (byte[])m_publicKey.Clone();

        [Obsolete("Use 'GetEncoded' instead")]
        public byte[] PublicKey
        {
            get => GetEncoded();
            set => throw new NotSupportedException();
        }
    }
}
