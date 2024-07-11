using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.asn1.dvcs
{
    /**
    * <pre>
    *     TargetEtcChain ::= SEQUENCE {
    *         target                       CertEtcToken,
    *         chain                        SEQUENCE SIZE (1..MAX) OF
    *                                         CertEtcToken OPTIONAL,
    *         pathProcInput                [0] PathProcInput OPTIONAL
    *     }
    * </pre>
    */

    public class TargetEtcChain : Asn1Object
    {
        private CertEtcToken target;
        private Asn1Sequence chain;
        private PathProcInput pathProcInput;


        public TargetEtcChain(CertEtcToken target) : this(target, null, null)
        {

        }

        public TargetEtcChain(CertEtcToken target, CertEtcToken[] chain) : this(target, chain, null)
        {

        }

        public TargetEtcChain(CertEtcToken target, PathProcInput pathProcInput) : this(target, null, pathProcInput)
        {

        }

        public TargetEtcChain(CertEtcToken target, CertEtcToken[] chain, PathProcInput pathProcInput)
        {
            this.target = target;
            if (chain != null)
            {
                this.chain = new DerSequence(chain);
            }

            this.pathProcInput = pathProcInput;
        }

        private TargetEtcChain(Asn1Sequence seq)
        {
            int i = 0;
            Asn1Encodable obj = seq[i++];
            this.target = CertEtcToken.GetInstance(obj);

            if (seq.Count > 1)
            {
                obj = seq[i++];
                if (obj is Asn1TaggedObject)
                {
                    ExtractPathProcInput(obj);
                }
                else
                {
                    this.chain = Asn1Sequence.GetInstance(obj);
                    if (seq.Count > 2)
                    {
                        obj = seq[i];
                        ExtractPathProcInput(obj);
                    }
                }
            }
        }



        public static TargetEtcChain GetInstance(object obj)
        {
            if (obj is TargetEtcChain)
            {
                return (TargetEtcChain)obj;
            }
            else if (obj != null)
            {
                return new TargetEtcChain(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }
        public static TargetEtcChain GetInstance(Asn1TaggedObject obj, bool explicid)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicid));
        }





        private void ExtractPathProcInput(Asn1Encodable obj)
        {
            Asn1TaggedObject tagged = Asn1TaggedObject.GetInstance(obj);
            switch (tagged.TagNo)
            {
                case 0:
                    this.pathProcInput = PathProcInput.GetInstance(tagged, false);
                    break;
                default:
                    throw new ArgumentException("Unknown tag encountered: " + tagged.TagNo);
            }
        }

        public Asn1Object ToASN1Primitive()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(target);
            if (chain != null)
            {
                v.Add(chain);
            }
            if (pathProcInput != null)
            {
                v.Add(new DerTaggedObject(false, 0, pathProcInput));
            }

            return new DerSequence(v);
        }


        public CertEtcToken GetTarget()
        {
            return target;
        }

        public CertEtcToken[] GetChain()
        {
            if (chain != null)
            {
                return CertEtcToken.ArrayFromSequence(chain);
            }

            return null;
        }

        public PathProcInput GetPathProcInput()
        {
            return pathProcInput;
        }

        public static TargetEtcChain[] ArrayFromSequence(Asn1Sequence seq)
        {
            var tmp = new TargetEtcChain[seq.Count];

            for (int i = 0; i < tmp.Length; i++)
            {
                tmp[i] = TargetEtcChain.GetInstance(seq[i]);
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
            return ToASN1Primitive().GetEncodingDerImplicit(tagClass, tagNo); 
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToASN1Primitive().CallAsn1Equals(asn1Object);
        }

        protected override int Asn1GetHashCode()
        {
            return ToASN1Primitive().CallAsn1GetHashCode();
        }


        public override string ToString()
        {
            var s = new System.Text.StringBuilder();
            s.Append("TargetEtcChain {\n");
            s.Append("target: " + target + "\n");
            if (chain != null)
            {
                s.Append("chain: " + chain + "\n");
            }

            if (pathProcInput != null)
            {
                s.Append("pathProcInput: " + pathProcInput + "\n");
            }

            s.Append("}\n");
            return s.ToString();
        }
    }
}
