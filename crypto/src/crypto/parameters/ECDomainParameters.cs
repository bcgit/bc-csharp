using System;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Elliptic curve domain parameters: the curve, base point, order and cofactor.</summary>
    public class ECDomainParameters
    {
        /// <summary>Create domain parameters from X9.62 parameters.</summary>
        /// <param name="x962Parameters">The X9.62 parameters, which are either named, explicit or implicit.</param>
        /// <returns>The domain parameters.</returns>
        public static ECDomainParameters FromX962Parameters(X962Parameters x962Parameters)
        {
            if (x962Parameters.IsImplicitlyCA)
                throw new NotImplementedException("implicitlyCA");

            var namedCurve = x962Parameters.NamedCurve;
            if (namedCurve != null)
                return ECNamedDomainParameters.LookupOid(namedCurve);

            var x9 = X9ECParameters.GetInstance(x962Parameters.Parameters);
            return FromX9ECParameters(x9);
        }

        /// <summary>Create domain parameters from X9.62 elliptic curve parameters.</summary>
        /// <param name="x9ECParameters">The curve parameters.</param>
        /// <returns>The domain parameters.</returns>
        public static ECDomainParameters FromX9ECParameters(X9ECParameters x9ECParameters) =>
            new ECDomainParameters(x9ECParameters);

        /// <summary>Look up the domain parameters of a named curve.</summary>
        /// <param name="name">The name of the curve.</param>
        /// <returns>The domain parameters, or null if the name is not known.</returns>
        public static ECDomainParameters LookupName(string name)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            var oid = ECUtilities.FindECCurveOid(name);
            if (oid != null)
                return ECNamedDomainParameters.LookupOid(oid);

            var x9 = ECUtilities.FindECCurveByName(name) ??
                throw new ArgumentException("Name is not a valid public key parameter set", nameof(name));

            return FromX9ECParameters(x9);
        }

        private readonly ECCurve m_curve;
        private readonly ECPoint m_g;
        private readonly BigInteger m_n;
        private readonly BigInteger m_h;
        private readonly byte[] m_seed;

        private BigInteger m_hInv;

        /// <summary>Create a copy of the given <see cref="ECDomainParameters"/>.</summary>
        /// <param name="other">The instance to copy.</param>
        public ECDomainParameters(ECDomainParameters other)
        {
            m_curve = other.Curve;
            m_g = other.G;
            m_n = other.N;
            m_h = other.H;
            m_seed = other.Seed;

            m_hInv = other.m_hInv;
        }

        /// <summary>Create a new <see cref="ECDomainParameters"/>.</summary>
        /// <param name="x9">The x 9.</param>
        public ECDomainParameters(X9ECParameters x9)
            : this(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed())
        {
        }

        /// <summary>Create a new <see cref="ECDomainParameters"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="g">The g.</param>
        /// <param name="n">The n.</param>
        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n)
            : this(curve, g, n, BigInteger.One, null)
        {
        }

        /// <summary>Create a new <see cref="ECDomainParameters"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="g">The g.</param>
        /// <param name="n">The n.</param>
        /// <param name="h">The h.</param>
        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h)
            : this(curve, g, n, h, null)
        {
        }

        /// <summary>Create a new <see cref="ECDomainParameters"/>.</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="g">The g.</param>
        /// <param name="n">The n.</param>
        /// <param name="h">The h.</param>
        /// <param name="seed">The seed.</param>
        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h, byte[] seed)
        {
            if (curve == null)
                throw new ArgumentNullException(nameof(curve));
            if (g == null)
                throw new ArgumentNullException(nameof(g));
            if (n == null)
                throw new ArgumentNullException(nameof(n));

            // we can't check for h == null here as h is optional in X9.62 as it is not required for ECDSA

            m_curve = curve;
            m_g = ValidatePublicPoint(curve, g);
            m_n = n;
            m_h = h;
            m_seed = Arrays.Clone(seed);
        }

        /// <summary>Gets the curve.</summary>
        public ECCurve Curve => m_curve;

        /// <summary>Gets the g.</summary>
        public ECPoint G => m_g;

        /// <summary>Gets the n.</summary>
        public BigInteger N => m_n;

        /// <summary>Gets the h.</summary>
        public BigInteger H => m_h;

        /// <summary>Gets the h inv.</summary>
        public BigInteger HInv =>
            Objects.EnsureSingletonInitialized(ref m_hInv, this, self => BigIntegers.ModOddInverseVar(self.N, self.H));

        /// <summary>Return the seed.</summary>
        public byte[] GetSeed() => Arrays.Clone(m_seed);

        internal byte[] Seed => m_seed;

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is ECDomainParameters other && Equals(other);

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected virtual bool Equals(ECDomainParameters other)
        {
            if (this == other)
                return true;

            return other != null
                && m_curve.Equals(other.m_curve)
                && m_g.Equals(other.m_g)
                && m_n.Equals(other.m_n);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return HashCode.Combine(m_curve, m_g, m_n);
#else
            int hc = 4;
            hc *= 257;
            hc ^= m_curve.GetHashCode();
            hc *= 257;
            hc ^= m_g.GetHashCode();
            hc *= 257;
            hc ^= m_n.GetHashCode();
            return hc;
#endif
        }

        /// <summary>Convert these domain parameters to X9.62 parameters.</summary>
        /// <returns>The X9.62 parameters.</returns>
        public virtual X962Parameters ToX962Parameters() => new X962Parameters(ToX9ECParameters());

        /// <summary>Convert these domain parameters to X9.62 elliptic curve parameters.</summary>
        /// <returns>The curve parameters.</returns>
        public virtual X9ECParameters ToX9ECParameters()
        {
            // TODO Support for choosing compressed==true?
            var g = new X9ECPoint(G, compressed: false);
            return new X9ECParameters(Curve, g, N, H, Seed);
        }

        /// <summary>Check that a scalar is a valid private scalar for this curve.</summary>
        /// <param name="d">The scalar to check.</param>
        /// <returns>The scalar, if valid.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="d"/> is null.</exception>
        /// <exception cref="ArgumentException">The scalar is not in the range <c>[1, n-1]</c>.</exception>
        public BigInteger ValidatePrivateScalar(BigInteger d)
        {
            if (d == null)
                throw new ArgumentNullException(nameof(d), "Scalar cannot be null");

            if (d.CompareTo(BigInteger.One) < 0 || (d.CompareTo(N) >= 0))
                throw new ArgumentException("Scalar is not in the interval [1, n - 1]", nameof(d));

            return d;
        }

        /// <summary>Check that a point is a valid public point for this curve.</summary>
        /// <param name="q">The point to check.</param>
        /// <returns>The point, normalized, if valid.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="q"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// The point is at infinity, not on the curve or not in the correct subgroup.
        /// </exception>
        public ECPoint ValidatePublicPoint(ECPoint q) => ValidatePublicPoint(Curve, q);

        internal static ECPoint ValidatePublicPoint(ECCurve c, ECPoint q)
        {
            if (null == q)
                throw new ArgumentNullException(nameof(q), "Point cannot be null");

            q = ECAlgorithms.ImportPoint(c, q).Normalize();

            if (q.IsInfinity)
                throw new ArgumentException("Point at infinity", nameof(q));

            if (!q.IsValid())
                throw new ArgumentException("Point not on curve", nameof(q));

            return q;
        }
    }
}
