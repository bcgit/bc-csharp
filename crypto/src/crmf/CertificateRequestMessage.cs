using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;

namespace Org.BouncyCastle.Crmf
{
    public class CertificateRequestMessage
    {
        public static readonly int popRaVerified = Org.BouncyCastle.Asn1.Crmf.ProofOfPossession.TYPE_RA_VERIFIED;
        public static readonly int popSigningKey = Org.BouncyCastle.Asn1.Crmf.ProofOfPossession.TYPE_SIGNING_KEY;
        public static readonly int popKeyEncipherment = Org.BouncyCastle.Asn1.Crmf.ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
        public static readonly int popKeyAgreement = Org.BouncyCastle.Asn1.Crmf.ProofOfPossession.TYPE_KEY_AGREEMENT;

        private readonly CertReqMsg certReqMsg;
        private readonly Controls controls;

        private static CertReqMsg ParseBytes(byte[] encoding)
       
        {        
                return CertReqMsg.GetInstance(encoding);
        }

        public CertificateRequestMessage(CertReqMsg certReqMsg)
        {
            this.certReqMsg = certReqMsg;
            this.controls = certReqMsg.CertReq.Controls;
        }

        public CertReqMsg ToAsn1Structure()
        {
            return certReqMsg; 
        }

        public CertTemplate GetCertTemplate()
        {
            return this.certReqMsg.CertReq.CertTemplate;
        }

        public bool HasControls
        {
            get { return controls != null; }
        }


        public bool HasControl(DerObjectIdentifier objectIdentifier)
        {
            return findControl(objectIdentifier) != null;
        }

        public IControl GetControl(DerObjectIdentifier type)
        {
            AttributeTypeAndValue found = findControl(type);
            if (found != null)
            {
                if (found.Type.Equals(CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions))
                {
                    return new PkiArchiveControl(PkiArchiveOptions.GetInstance(found.Value));
                }

                if (found.Type.Equals(CrmfObjectIdentifiers.id_regCtrl_regToken))
                {
                    return new RegTokenControl(DerUtf8String.GetInstance(found.Value));
                }

                if (found.Type.Equals(CrmfObjectIdentifiers.id_regCtrl_authenticator))
                {
                    return new AuthenticatorControl(DerUtf8String.GetInstance(found.Value));
                }
            }        
            return null;
        }




        public AttributeTypeAndValue findControl(DerObjectIdentifier type)
        {
            if (controls == null)
            {
                return null;
            }

            AttributeTypeAndValue[] tAndV = controls.ToAttributeTypeAndValueArray();
            AttributeTypeAndValue found = null;

            for (int i = 0; i < tAndV.Length; i++)
            {
                if (tAndV[i].Type.Equals(type))
                {
                    found = tAndV[i];
                    break;
                }
            }

            return found;
        }

        public bool HasProofOfPossession
        {
            get { return certReqMsg.Popo != null; }
        }

        public int ProofOfPossession
        {
            get { return certReqMsg.Popo.Type; }
        }

        public bool HasSigningKeyProofOfPossessionWithPkMac
        {
            get
            {
                ProofOfPossession pop = certReqMsg.Popo;

                if (pop.Type == popSigningKey)
                {
                    PopoSigningKey popoSign = PopoSigningKey.GetInstance(pop.Object);

                    return popoSign.PoposkInput.PublicKeyMac != null;
                }

                return false;

            }
        }
   
        public bool IsValidSigningKeyPop(IVerifierFactoryProvider verifierProvider)
        {
            ProofOfPossession pop = certReqMsg.Popo;
            if (pop.Type == popSigningKey)
            {
                PopoSigningKey popoSign = PopoSigningKey.GetInstance(pop.Object);
                if (popoSign.PoposkInput != null && popoSign.PoposkInput.PublicKeyMac != null)
                {
                    throw new InvalidOperationException("verification requires password check");
                }
                return verifySignature(verifierProvider, popoSign);
            }

            throw new InvalidOperationException("not Signing Key type of proof of possession");
        }



        private bool verifySignature(IVerifierFactoryProvider verifierFactoryProvider, PopoSigningKey signKey)
        {
            IVerifierFactory verifer;
            IStreamCalculator calculator;
            try
            {
                verifer = verifierFactoryProvider.CreateVerifierFactory(signKey.AlgorithmIdentifier);
                calculator = verifer.CreateCalculator();
            }
            catch (Exception ex)
            {
                throw new CrmfException("unable to create verifier: "+ex.Message, ex);
            }

            if (signKey.PoposkInput != null)
            {
                byte[] b = signKey.GetDerEncoded();
              calculator.Stream.Write(b,0,b.Length);
            }
            else
            {
                byte[] b = certReqMsg.GetDerEncoded();
                calculator.Stream.Write(b,0,b.Length);
            }

            DefaultVerifierResult result = (DefaultVerifierResult) calculator.GetResult();
      
            return result.IsVerified(signKey.Signature.GetBytes());
        }

        public byte[] GetEncoded()
        {
            return certReqMsg.GetEncoded();
        }
    }
}
