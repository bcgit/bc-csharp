using System;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ECDomainParameters
    {
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

        public static ECDomainParameters FromX9ECParameters(X9ECParameters x9ECParameters) =>
            new ECDomainParameters(x9ECParameters);

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

        public ECDomainParameters(ECDomainParameters other)
        {
            m_curve = other.Curve;
            m_g = other.G;
            m_n = other.N;
            m_h = other.H;
            m_seed = other.Seed;

            m_hInv = other.m_hInv;
        }

        public ECDomainParameters(X9ECParameters x9)
            : this(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed())
        {
        }

        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n)
            : this(curve, g, n, BigInteger.One, null)
        {
        }

        public ECDomainParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h)
            : this(curve, g, n, h, null)
        {
        }

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

        public ECCurve Curve => m_curve;

        public ECPoint G => m_g;

        public BigInteger N => m_n;

        public BigInteger H => m_h;

        public BigInteger HInv =>
            Objects.EnsureSingletonInitialized(ref m_hInv, this, self => BigIntegers.ModOddInverseVar(self.N, self.H));

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        internal byte[] Seed => m_seed;

        public override bool Equals(object obj) => obj is ECDomainParameters other && Equals(other);

        protected virtual bool Equals(ECDomainParameters other)
        {
            return m_curve.Equals(other.m_curve)
                && m_g.Equals(other.m_g)
                && m_n.Equals(other.m_n);
        }

        public override int GetHashCode()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HashCode hc = default;
            hc.Add(m_curve);
            hc.Add(m_g);
            hc.Add(m_n);
            return hc.ToHashCode();
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

        public virtual X962Parameters ToX962Parameters() => new X962Parameters(ToX9ECParameters());

        public virtual X9ECParameters ToX9ECParameters()
        {
            // TODO Support for choosing compressed==true?
            var g = new X9ECPoint(G, compressed: false);
            return new X9ECParameters(Curve, g, N, H, Seed);
        }

        public BigInteger ValidatePrivateScalar(BigInteger d)
        {
            if (d == null)
                throw new ArgumentNullException(nameof(d), "Scalar cannot be null");

            if (d.CompareTo(BigInteger.One) < 0 || (d.CompareTo(N) >= 0))
                throw new ArgumentException("Scalar is not in the interval [1, n - 1]", nameof(d));

            return d;
        }

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
