using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Asn1.Mozilla
{
    /**
	 * This is designed to parse
	 * the SignedPublicKeyAndChallenge created by the KEYGEN tag included by
	 * Mozilla based browsers.
     *  <pre>
     *
     *  SignedPublicKeyAndChallenge ::= SEQUENCE {
     *    publicKeyAndChallenge PublicKeyAndChallenge,
     *    signatureAlgorithm AlgorithmIdentifier,
     *    signature BIT STRING
     *  }
     *  </pre>
     */
    internal class SignedPublicKeyAndChallenge : Asn1Encodable
    {
        private Asn1Sequence            seq;
        private PublicKeyAndChallenge   publicKeyAndChallenge;
        private AlgorithmIdentifier     algorithmIdentifier;
        private DerBitString            signature;

        public PublicKeyAndChallenge PublicKeyAndChallenge
        {
            get { return publicKeyAndChallenge; }
        }

        public AlgorithmIdentifier AlgorithmIdentifier
        {
            get { return algorithmIdentifier; }
        }

        public DerBitString Signature
        {
            get { return signature; }
        }

        public static SignedPublicKeyAndChallenge GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
        }

        public static SignedPublicKeyAndChallenge GetInstance(object obj)
        {
            if (null == obj)
            {
                return null;
            }

            if (obj is SignedPublicKeyAndChallenge value)
            {
                return value;
            }

            if (obj is Asn1Sequence asn1Sequence)
            {
                return new SignedPublicKeyAndChallenge(asn1Sequence);
            }

            throw new ArgumentException(string.Format("object of unexpected type provided, type=[{0}]", obj.GetType().FullName));
        }

        public SignedPublicKeyAndChallenge(
            PublicKeyAndChallenge   publicKeyAndChallenge,
            AlgorithmIdentifier     algorithmIdentifier,
            DerBitString            signature)
        {
            this.publicKeyAndChallenge = publicKeyAndChallenge;
            this.algorithmIdentifier = algorithmIdentifier;
            this.signature = signature;
        }

        public SignedPublicKeyAndChallenge(
            Asn1Sequence seq)
        {
            this.seq = seq;

            if (seq.Count != 3)
                throw new FormatException($"Sequence contains {seq.Count} elements. Expected 3 elements");

            this.publicKeyAndChallenge = PublicKeyAndChallenge.GetInstance(seq[0]);
            this.algorithmIdentifier = AlgorithmIdentifier.GetInstance(seq[1]);
            this.signature = DerBitString.GetInstance(seq[2]);
        }

        public bool Verify()
        {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(this.PublicKeyAndChallenge.SubjectPublicKeyInfo);
            Asn1VerifierFactoryProvider factory = new Asn1VerifierFactoryProvider(publicKey);
            IVerifierFactory verifier = factory.CreateVerifierFactory(this.AlgorithmIdentifier);

            try
            {
                byte[] derEncoded = this.PublicKeyAndChallenge.GetEncoded();
                IStreamCalculator<IVerifier> streamCalculator = verifier.CreateCalculator();
                streamCalculator.Stream.Write(derEncoded, 0, derEncoded.Length);
                streamCalculator.Stream.Dispose();

                return streamCalculator.GetResult().IsVerified(this.Signature.GetOctets());
            }
            catch (Exception exception)
            {
                throw new SignatureException("exception encoding SPKAC request", exception);
            }
        }

        public override Asn1Object ToAsn1Object()
        {
            if (null == this.seq)
            {
                Asn1EncodableVector v = new Asn1EncodableVector();

                if (null == this.PublicKeyAndChallenge)
                    throw new FormatException($"{nameof(this.PublicKeyAndChallenge)} can not be null");

                if (null == this.AlgorithmIdentifier)
                    throw new FormatException($"{nameof(this.AlgorithmIdentifier)} can not be null");

                if (null == this.Signature)
                    throw new FormatException($"{nameof(this.Signature)} can not be null");

                v.Add(this.PublicKeyAndChallenge);
                v.Add(this.AlgorithmIdentifier);
                v.Add(this.Signature);

                this.seq = new DerSequence(v);
            }
            return this.seq;
        }
    }
}
