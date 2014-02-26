using System;
using System.Collections;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class PbeS2Parameters
        : Asn1Encodable
    {
        private readonly KeyDerivationFunc func;
        private readonly EncryptionScheme scheme;

		public static PbeS2Parameters GetInstance(
			object obj)
		{
			if (obj == null || obj is PbeS2Parameters)
				return (PbeS2Parameters) obj;

			if (obj is Asn1Sequence)
				return new PbeS2Parameters((Asn1Sequence) obj);

			throw new ArgumentException("Unknown object in factory: " + obj.GetType().FullName, "obj");
		}

		public PbeS2Parameters(
            Asn1Sequence seq)
        {
			if (seq.Count != 2)
				throw new ArgumentException("Wrong number of elements in sequence", "seq");

			Asn1Sequence funcSeq = (Asn1Sequence)seq[0].ToAsn1Object();

			// TODO Not sure if this special case is really necessary/appropriate
			if (funcSeq[0].Equals(PkcsObjectIdentifiers.IdPbkdf2))
            {
				func = new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2,
					Pbkdf2Params.GetInstance(funcSeq[1]));
			}
            else
            {
                func = new KeyDerivationFunc(funcSeq);
            }

			scheme = EncryptionScheme.GetInstance(seq[1].ToAsn1Object());
        }

		public KeyDerivationFunc KeyDerivationFunc
		{
			get { return func; }
		}

		public EncryptionScheme EncryptionScheme
		{
			get { return scheme; }
		}

		public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(func, scheme);
        }
    }
}
