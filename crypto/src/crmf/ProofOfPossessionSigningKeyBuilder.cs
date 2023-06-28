using System;
using System.IO;
using System.Net.Security;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crmf
{
    public class ProofOfPossessionSigningKeyBuilder
    {
        private CertRequest _certRequest;
        private SubjectPublicKeyInfo _pubKeyInfo;
        private GeneralName _name;
        private PKMacValue _publicKeyMAC;

        public ProofOfPossessionSigningKeyBuilder(CertRequest certRequest)
        {
            this._certRequest = certRequest;
        }

        public ProofOfPossessionSigningKeyBuilder(SubjectPublicKeyInfo pubKeyInfo)
        {
            this._pubKeyInfo = pubKeyInfo;
        }

        public ProofOfPossessionSigningKeyBuilder SetSender(GeneralName name)
        {
            this._name = name;
            return this;
        }

        public ProofOfPossessionSigningKeyBuilder SetPublicKeyMac(PKMacBuilder generator, char[] password)
        {
            IMacFactory fact = generator.Build(password);

            return ImplSetPublicKeyMac(fact);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ProofOfPossessionSigningKeyBuilder SetPublicKeyMac(PKMacBuilder generator, ReadOnlySpan<char> password)
        {
            IMacFactory fact = generator.Build(password);

            return ImplSetPublicKeyMac(fact);
        }
#endif

        public PopoSigningKey Build(ISignatureFactory signer)
        {
            if (_name != null && _publicKeyMAC != null)
                throw new InvalidOperationException("name and publicKeyMAC cannot both be set.");

            PopoSigningKeyInput popo;
            Asn1Encodable asn1Encodable;

            if (_certRequest != null)
            {
                popo = null;
                asn1Encodable = _certRequest;
            }
            else if (_name != null)
            {
                popo = new PopoSigningKeyInput(_name, _pubKeyInfo);
                asn1Encodable = popo;
            }
            else
            {
                popo = new PopoSigningKeyInput(_publicKeyMAC, _pubKeyInfo);
                asn1Encodable = popo;
            }

            var signature = X509.X509Utilities.GenerateSignature(signer, asn1Encodable);

            return new PopoSigningKey(popo, (AlgorithmIdentifier)signer.AlgorithmDetails, signature);
        }

        private ProofOfPossessionSigningKeyBuilder ImplSetPublicKeyMac(IMacFactory macFactory)
        {
            var macValue = X509.X509Utilities.GenerateMac(macFactory, _pubKeyInfo);
            this._publicKeyMAC = new PKMacValue((AlgorithmIdentifier)macFactory.AlgorithmDetails, macValue);
            return this;
        }
    }
}
