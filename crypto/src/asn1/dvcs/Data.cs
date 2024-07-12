using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.asn1.dvcs
{

 /**
 * <pre>
 * Data ::= CHOICE {
 *   message           OCTET STRING ,
 *   messageImprint    DigestInfo,
 *   certs             [0] SEQUENCE SIZE (1..MAX) OF
 *                         TargetEtcChain
 * }
 * </pre>
 */
    public class Data :Asn1Object, IAsn1Choice
    {
        private Asn1OctetString message;
        private DigestInfo messageImprint;
        private Asn1Sequence certs;


        public Data(byte[] messageBytes)
        {
            this.message = new DerOctetString(messageBytes);
        }

        public Data(Asn1OctetString message)
        {
            this.message = message;
        }

        public Data(DigestInfo messageImprint)
        {
            this.messageImprint = messageImprint;
        }

        public Data(TargetEtcChain cert)
        {
            this.certs = new DerSequence(cert);
        }

        public Data(TargetEtcChain[] certs)
        {
            this.certs = new DerSequence(certs);
        }

        private Data(Asn1Sequence certs)
        {
            this.certs = certs;
        }

        public static Data GetInstance(Object obj)
        {
            if (obj is Data)
            {
                return (Data)obj;
            }
            else if (obj is Asn1OctetString)
            {
                return new Data((Asn1OctetString)obj);
            }
            else if (obj is Asn1Sequence)
            {
                return new Data(DigestInfo.GetInstance(obj));
            }
            else if (obj is Asn1TaggedObject)
            {
                return new Data(Asn1Sequence.GetInstance((Asn1TaggedObject)obj, false));
            }
            throw new ArgumentException("Unknown object submitted to getInstance: " + obj.GetType().Name);
        }

        public static Data GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            return GetInstance(obj.GetExplicitBaseObject());
        }

        public Asn1Object ToASN1Primitive()
        {
            if (message != null)
            {
                return message.ToAsn1Object();
            }
            if (messageImprint != null)
            {
                return messageImprint.ToAsn1Object();
            }
            else
            {
                return new DerTaggedObject(false, 0, certs);
            }
        }

        public override string ToString()
        {
            if (message != null)
            {
                return "Data {\n" + message + "}\n";
            }
            if (messageImprint != null)
            {
                return "Data {\n" + messageImprint + "}\n";
            }
            else
            {
                return "Data {\n" + certs + "}\n";
            }
        }

        public Asn1OctetString GetMessage()
        {
            return message;
        }

        public DigestInfo GetMessageImprint()
        {
            return messageImprint;
        }

        public TargetEtcChain[] GetCerts()
        {
            if (certs == null)
            {
                return null;
            }

            TargetEtcChain[] tmp = new TargetEtcChain[certs.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = TargetEtcChain.GetInstance(certs[i]);
            }

            return tmp;
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return ToASN1Primitive().GetEncoding(encoding); 
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return ToASN1Primitive().GetEncodingImplicit(encoding, tagClass, tagNo); 
        }

        internal override DerEncoding GetEncodingDer()
        {
            return ToASN1Primitive().GetEncodingDer(); 
        }

        internal override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return ToASN1Primitive().GetEncodingDerImplicit(tagClass,tagNo); 
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToASN1Primitive().CallAsn1Equals(asn1Object); 
        }

        protected override int Asn1GetHashCode()
        {
            return ToASN1Primitive().CallAsn1GetHashCode();
        }
    }
}
