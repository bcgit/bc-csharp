using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    public sealed class EdDsaPublicBcpgKey
        : ECPublicBcpgKey
    {
        internal EdDsaPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="EdDsaPublicBcpgKey"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="point">The point.</param>
        public EdDsaPublicBcpgKey(DerObjectIdentifier oid, ECPoint point)
            : base(oid, point)
        {
        }

        /// <summary>Create a new <see cref="EdDsaPublicBcpgKey"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="encodedPoint">The encoded point.</param>
        public EdDsaPublicBcpgKey(DerObjectIdentifier oid, BigInteger encodedPoint)
            : base(oid, encodedPoint)
        {
        }
    }
}
