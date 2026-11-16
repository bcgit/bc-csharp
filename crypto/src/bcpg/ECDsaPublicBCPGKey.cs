using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for an ECDSA Public Key.</remarks>
    public class ECDsaPublicBcpgKey
        : ECPublicBcpgKey
    {
        /// <param name="bcpgIn">The stream to read the packet from.</param>
        protected internal ECDsaPublicBcpgKey(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="ECDsaPublicBcpgKey"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="point">The point.</param>
        public ECDsaPublicBcpgKey(DerObjectIdentifier oid, ECPoint point)
            : base(oid, point)
        {
        }

        /// <summary>Create a new <see cref="ECDsaPublicBcpgKey"/>.</summary>
        /// <param name="oid">The object identifier.</param>
        /// <param name="encodedPoint">The encoded point.</param>
        public ECDsaPublicBcpgKey(DerObjectIdentifier oid, BigInteger encodedPoint)
            : base(oid, encodedPoint)
        {
        }
    }
}
