using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    public class BasicConstraints
        : Asn1Encodable
    {
        public static BasicConstraints GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BasicConstraints basicConstraints)
                return basicConstraints;
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
            return new BasicConstraints(Asn1Sequence.GetInstance(obj));
        }

        public static BasicConstraints GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new BasicConstraints(Asn1Sequence.GetInstance(obj, explicitly));

        public static BasicConstraints GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BasicConstraints(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static BasicConstraints FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.BasicConstraints));
        }

        private readonly DerBoolean m_cA;
        private readonly DerInteger m_pathLenConstraint;

        private BasicConstraints(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_cA = Asn1Utilities.ReadOptional(seq, ref pos, DerBoolean.GetOptional) ?? DerBoolean.False;
            m_pathLenConstraint = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

		public BasicConstraints(bool cA)
        {
            m_cA = cA ? DerBoolean.True : DerBoolean.False;
            m_pathLenConstraint = null;
        }

		/**
         * create a cA=true object for the given path length constraint.
         *
         * @param pathLenConstraint
         */
        public BasicConstraints(int pathLenConstraint)
        {
            m_cA = DerBoolean.True;
            m_pathLenConstraint = new DerInteger(pathLenConstraint);
        }

        public bool IsCA() => m_cA.IsTrue;

        public BigInteger PathLenConstraint => m_pathLenConstraint?.Value;

        public DerInteger PathLenConstraintInteger => m_pathLenConstraint;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * BasicConstraints := Sequence {
         *    cA                  Boolean DEFAULT FALSE,
         *    pathLenConstraint   Integer (0..MAX) OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            if (m_cA.IsTrue)
            {
                v.Add(m_cA);
            }
            v.AddOptional(m_pathLenConstraint); // yes some people actually do this when cA is false...
            return new DerSequence(v);
        }

		public override string ToString()
        {
            if (m_pathLenConstraint == null)
				return "BasicConstraints: isCa(" + IsCA() + ")";

			return "BasicConstraints: isCa(" + IsCA() + "), pathLenConstraint = " + m_pathLenConstraint.Value;
        }
    }
}
