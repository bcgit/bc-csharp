using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Misc
{
    public class IdeaCbcPar
        : Asn1Encodable
    {
        internal Asn1OctetString iv;

		public static IdeaCbcPar GetInstance(
            object o)
        {
            if (o is IdeaCbcPar)
            {
                return (IdeaCbcPar) o;
            }

			if (o is Asn1Sequence)
            {
                return new IdeaCbcPar((Asn1Sequence) o);
            }

			throw new ArgumentException("unknown object in IDEACBCPar factory");
        }

		public IdeaCbcPar(
            byte[] iv)
        {
            this.iv = new DerOctetString(iv);
        }

		private IdeaCbcPar(
            Asn1Sequence seq)
        {
			if (seq.Count == 1)
			{
				iv = (Asn1OctetString) seq[0];
			}
        }

        public Asn1OctetString IV => iv;

        public byte[] GetIV() => Arrays.Clone(iv.GetOctets());

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
            return iv != null
                ?   new DerSequence(iv)
                :   DerSequence.Empty;
        }
    }
}
