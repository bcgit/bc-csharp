using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Elliptic curve domain parameters which also carry the object identifier of the named curve.</summary>
    public class ECNamedDomainParameters
        : ECDomainParameters
    {
        /// <summary>Look up the named domain parameters for a curve object identifier.</summary>
        /// <param name="oid">The object identifier of the curve.</param>
        /// <returns>The domain parameters, or null if the object identifier is not known.</returns>
        public static ECNamedDomainParameters LookupOid(DerObjectIdentifier oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            var x9 = ECUtilities.FindECCurveByOid(oid) ??
                throw new ArgumentException("OID is not a valid public key parameter set", nameof(oid));

            return new ECNamedDomainParameters(oid, x9);
        }

        private readonly DerObjectIdentifier m_name;

        /// <summary>Create a new <see cref="ECNamedDomainParameters"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="dp">The dp.</param>
        public ECNamedDomainParameters(DerObjectIdentifier name, ECDomainParameters dp)
            : base(dp)
        {
            m_name = name;
        }

        /// <summary>Create a new <see cref="ECNamedDomainParameters"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="x9">The x 9.</param>
        public ECNamedDomainParameters(DerObjectIdentifier name, X9ECParameters x9)
            : base(x9)
        {
            m_name = name;
        }

        /// <summary>Create a new <see cref="ECNamedDomainParameters"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="curve">The curve.</param>
        /// <param name="g">The g.</param>
        /// <param name="n">The n.</param>
        public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint g, BigInteger n)
            : base(curve, g, n)
        {
            m_name = name;
        }

        /// <summary>Create a new <see cref="ECNamedDomainParameters"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="curve">The curve.</param>
        /// <param name="g">The g.</param>
        /// <param name="n">The n.</param>
        /// <param name="h">The h.</param>
        public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint g, BigInteger n, BigInteger h)
            : base(curve, g, n, h)
        {
            m_name = name;
        }

        /// <summary>Create a new <see cref="ECNamedDomainParameters"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="curve">The curve.</param>
        /// <param name="g">The g.</param>
        /// <param name="n">The n.</param>
        /// <param name="h">The h.</param>
        /// <param name="seed">The seed.</param>
        public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint g, BigInteger n, BigInteger h,
            byte[] seed)
            : base(curve, g, n, h, seed)
        {
            m_name = name;
        }

        /// <summary>Gets the name.</summary>
        public DerObjectIdentifier Name => m_name;

        /// <inheritdoc/>
        public override X962Parameters ToX962Parameters() => new X962Parameters(Name);
    }
}
