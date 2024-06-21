using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Misc
{
    public class IdeaCbcPar
        : Asn1Encodable
    {
		public static IdeaCbcPar GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is IdeaCbcPar ideaCbcPar)
                return ideaCbcPar;
            return new IdeaCbcPar(Asn1Sequence.GetInstance(o));
        }

        public static IdeaCbcPar GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new IdeaCbcPar(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1OctetString m_iv;

        private IdeaCbcPar(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_iv = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public IdeaCbcPar()
            : this(iv: null)
        {
        }

        public IdeaCbcPar(byte[] iv)
        {
            m_iv = iv == null ? null : new DerOctetString(iv);
        }

        public Asn1OctetString IV => m_iv;

        public byte[] GetIV() => Arrays.Clone(m_iv?.GetOctets());

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * IDEA-CBCPar ::= Sequence {
         *                      iv    OCTET STRING OPTIONAL -- exactly 8 octets
         *                  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_iv == null
                ?  DerSequence.Empty
                :  new DerSequence(m_iv);
        }
    }
}
