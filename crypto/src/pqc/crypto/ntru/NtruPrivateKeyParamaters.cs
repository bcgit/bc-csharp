using System;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    public sealed class NtruPrivateKeyParameters
        : NtruKeyParameters
    {
        public static NtruPrivateKeyParameters FromEncoding(NtruParameters parameters, byte[] encoding)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NtruPrivateKeyParameters(parameters, encoding);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly byte[] m_privateKey;

        [Obsolete("Use 'FromEncoding' instead")]
        public NtruPrivateKeyParameters(NtruParameters parameters, byte[] key)
            : base(privateKey: true, parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != parameters.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(key));

            m_privateKey = (byte[])key.Clone();
        }

        public override byte[] GetEncoded() => (byte[])m_privateKey.Clone();

        [Obsolete("Use 'GetEncoded' instead")]
        public byte[] PrivateKey
        {
            get => GetEncoded();
            private set => throw new NotSupportedException();
        }
    }
}
