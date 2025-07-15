using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an EC Public Key.</summary>
    public abstract class ECPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly DerObjectIdentifier m_oid;
        private readonly BigInteger m_point;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        protected ECPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            m_oid = DerObjectIdentifier.GetInstance(ReadBytesOfEncodedLength(bcpgIn));
            m_point = new MPInteger(bcpgIn).Value;
        }

        protected ECPublicBcpgKey(DerObjectIdentifier oid, ECPoint point)
        {
            m_point = MPInteger.ToMpiBigInteger(point);
            m_oid = oid;
        }

        protected ECPublicBcpgKey(DerObjectIdentifier oid, BigInteger encodedPoint)
        {
            m_point = encodedPoint;
            m_oid = oid;
        }

        public virtual BigInteger EncodedPoint => m_point;

        public virtual DerObjectIdentifier CurveOid => m_oid;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(this);

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            byte[] oid = m_oid.GetEncoded();
            bcpgOut.Write(oid, 1, oid.Length - 1);

            MPInteger.Encode(bcpgOut, m_point);
        }

        protected static byte[] ReadBytesOfEncodedLength(BcpgInputStream bcpgIn)
        {
            int length = bcpgIn.RequireByte();
            if (length == 0 || length == 0xFF)
                throw new IOException("future extensions not yet implemented");
            if (length > 127)
                throw new IOException("unsupported OID");

            byte[] buffer = new byte[2 + length];
            bcpgIn.ReadFully(buffer, 2, buffer.Length - 2);
            buffer[0] = 0x06;
            buffer[1] = (byte)length;

            return buffer;
        }
    }
}
