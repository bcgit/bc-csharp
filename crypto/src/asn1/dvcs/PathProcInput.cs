using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.asn1.dvcs
{
    public class PathProcInput : Asn1Object
    {

        private PolicyInformation[] acceptablePolicySet;
        private bool inhibitPolicyMapping = false;
        private bool explicitPolicyReqd = false;
        private bool inhibitAnyPolicy = false;

        public PathProcInput(PolicyInformation[] acceptablePolicySet)
        {
            this.acceptablePolicySet = Copy(acceptablePolicySet);
        }

        public PathProcInput(PolicyInformation[] acceptablePolicySet, bool inhibitPolicyMapping, bool explicitPolicyReqd, bool inhibitAnyPolicy)
        {
            this.acceptablePolicySet = Copy(acceptablePolicySet);
            this.inhibitPolicyMapping = inhibitPolicyMapping;
            this.explicitPolicyReqd = explicitPolicyReqd;
            this.inhibitAnyPolicy = inhibitAnyPolicy;
        }


        public Asn1Object ToAsn1Primitive()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);

            {
                Asn1EncodableVector pV = new Asn1EncodableVector(acceptablePolicySet.Length);
                for (int i = 0; i != acceptablePolicySet.Length; i++)
                {
                    pV.Add(acceptablePolicySet[i]);
                }

                v.Add(new DerSequence(pV));
            }

            if (inhibitPolicyMapping)
            {
                v.Add(DerBoolean.GetInstance(inhibitPolicyMapping));
            }
            if (explicitPolicyReqd)
            {
                v.Add(new DerTaggedObject(false, 0, DerBoolean.GetInstance(explicitPolicyReqd)));
            }
            if (inhibitAnyPolicy)
            {
                v.Add(new DerTaggedObject(false, 1, DerBoolean.GetInstance(inhibitAnyPolicy)));
            }

            return new DerSequence(v);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return ToAsn1Primitive().GetEncoding(encoding);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return ToAsn1Primitive().GetEncodingImplicit(encoding, tagClass, tagNo);
        }

        internal override DerEncoding GetEncodingDer()
        {
            return ToAsn1Primitive().GetEncodingDer(); 
        }

        internal override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return ToAsn1Primitive().GetEncodingDerImplicit(tagClass, tagNo); 
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToAsn1Primitive().CallAsn1Equals(asn1Object);
        }

        protected override int Asn1GetHashCode()
        {
            return ToAsn1Primitive().CallAsn1GetHashCode();
        }


        public static PathProcInput GetInstance(object obj)
        {
            if (obj is PathProcInput)
            {
                return (PathProcInput)obj;
            }
            else if (obj != null)
            {
                Asn1Sequence seq = Asn1Sequence.GetInstance(obj);
                Asn1Sequence policies = Asn1Sequence.GetInstance(seq[0]);
                PathProcInput result = new PathProcInput(FromSequence(policies));

                for (int i = 1; i < seq.Count; i++)
                {
                    object o = seq[i];

                    if (o is DerBoolean)
                    {
                        DerBoolean x = DerBoolean.GetInstance(o);
                        result.SetInhibitPolicyMapping(x.IsTrue);
                    }
                    else if (o is Asn1TaggedObject)
                    {
                        Asn1TaggedObject t = Asn1TaggedObject.GetInstance(o);
                        DerBoolean x;
                        switch (t.TagNo)
                        {
                            case 0:
                                x = DerBoolean.GetInstance(t, false);
                                result.SetExplicitPolicyReqd(x.IsTrue);
                                break;
                            case 1:
                                x = DerBoolean.GetInstance(t, false);
                                result.SetExplicitPolicyReqd(x.IsTrue);
                                break;
                            default:
                                throw new ArgumentException("Unknown tag encountered: " + t.TagNo);
                        }
                    }
                }
                return result;
            }

            return null;
        }


        public static PathProcInput GetInstance(
            Asn1TaggedObject obj,
            bool explicid)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicid));
        }

        public override string ToString()
        {
            return "PathProcInput: {\n" +
                   "acceptablePolicySet: " +  string.Join(", ", acceptablePolicySet.ToList()) + "\n" +
                   "inhibitPolicyMapping: " + inhibitPolicyMapping + "\n" +
                   "explicitPolicyReqd: " + explicitPolicyReqd + "\n" +
                   "inhibitAnyPolicy: " + inhibitAnyPolicy + "\n" +
                   "}\n";
        }

        public PolicyInformation[] GetAcceptablePolicySet()
        {
            return Copy(acceptablePolicySet);
        }

        public bool IsInhibitPolicyMapping()
        {
            return inhibitPolicyMapping;
        }

        private void SetInhibitPolicyMapping(bool inhibitPolicyMapping)
        {
            this.inhibitPolicyMapping = inhibitPolicyMapping;
        }

        public bool IsExplicitPolicyReqd()
        {
            return explicitPolicyReqd;
        }

        private void SetExplicitPolicyReqd(bool explicitPolicyReqd)
        {
            this.explicitPolicyReqd = explicitPolicyReqd;
        }

        public bool IsInhibitAnyPolicy()
        {
            return inhibitAnyPolicy;
        }

        private void SetInhibitAnyPolicy(bool inhibitAnyPolicy)
        {
            this.inhibitAnyPolicy = inhibitAnyPolicy;
        }
        private static PolicyInformation[] FromSequence(Asn1Sequence seq)
        {
            PolicyInformation[] tmp = new PolicyInformation[seq.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = PolicyInformation.GetInstance(seq[i]);
            }

            return tmp;
        }
        private PolicyInformation[] Copy(PolicyInformation[] policySet)
        {
            PolicyInformation[] rv = new PolicyInformation[policySet.Length];

            Array.Copy(policySet, 0, rv, 0, rv.Length);

            return rv;
        }
    }
}
