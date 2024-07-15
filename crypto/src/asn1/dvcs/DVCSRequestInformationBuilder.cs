using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.asn1.dvcs
{
    /**
    * <pre>
    *     DVCSRequestInformation ::= SEQUENCE  {
    *         version                      INTEGER DEFAULT 1 ,
    *         service                      ServiceType,
    *         nonce                        Nonce OPTIONAL,
    *         requestTime                  DVCSTime OPTIONAL,
    *         requester                    [0] GeneralNames OPTIONAL,
    *         requestPolicy                [1] PolicyInformation OPTIONAL,
    *         dvcs                         [2] GeneralNames OPTIONAL,
    *         dataLocations                [3] GeneralNames OPTIONAL,
    *         extensions                   [4] IMPLICIT Extensions OPTIONAL
    *     }
    * </pre>
    */
    public class DVCSRequestInformationBuilder
    {
        private const int DEFAULT_VERSION = 1;
        private const int TAG_REQUESTER = 0;
        private const int TAG_REQUEST_POLICY = 1;
        private const int TAG_DVCS = 2;
        private const int TAG_DATA_LOCATIONS = 3;
        private const int TAG_EXTENSIONS = 4;

        private int version = DEFAULT_VERSION;

        private readonly ServiceType service;
        private DVCSRequestInformation initialInfo;

        private BigInteger nonce;
        private DVCSTime requestTime;
        private GeneralNames requester;
        private PolicyInformation requestPolicy;
        private GeneralNames dvcs;
        private GeneralNames dataLocations;
        private X509Extensions extensions;


        public ServiceType Service
        {
            get { return service; }
        }

        public int Version
        {
            get
            {
                return version;
            }

            set
            {
                if (initialInfo != null)
                {
                    throw new Exception("cannot change version in existing DVCSRequestInformation");
                }
                this.version = value;
            }
        }

        // RFC 3029, 9.1: The DVCS MAY modify the fields
        // 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure

        // RFC 3029, 9.1: The only modification
        // allowed to a 'nonce' is the inclusion of a new field if it was not
        // present, or to concatenate other data to the end (right) of an
        // existing value.
        public BigInteger Nonce
        {
            get { return nonce; }

            set
            {
                if (initialInfo != null)
                {
                    if (initialInfo.Nonce == null)
                    {
                        this.nonce = value;
                    }
                    else
                    {
                        byte[] initialBytes = initialInfo.Nonce.ToByteArray();
                        byte[] newBytes = BigIntegers.AsUnsignedByteArray(nonce);
                        byte[] nonceBytes = new byte[initialBytes.Length + newBytes.Length];

                        Array.Copy(initialBytes, 0, nonceBytes, 0, initialBytes.Length);
                        Array.Copy(newBytes, 0, nonceBytes, initialBytes.Length, newBytes.Length);

                        this.nonce = new BigInteger(nonceBytes);
                    }
                }
                else
                {
                    this.nonce = value;
                }


            }
        }

        public DVCSTime RequestTime
        {
            get { return requestTime; }

            set
            {
                if (initialInfo != null)
                {
                    throw new Exception("cannot change request time in existing DVCSRequestInformation");
                }

                this.requestTime = value;
            }
        }

        public GeneralNames Requester
        {
            get { return requester; }
           
        }

        public PolicyInformation RequestPolicy
        {
            get { return requestPolicy; }

            set
            {
                if (initialInfo != null)
                {
                    throw new Exception("cannot change request policy in existing DVCSRequestInformation");
                }

                this.requestPolicy = value;
            }
        }

        public GeneralNames DVCS
        {
            get { return dvcs; }
        }



        public GeneralNames DataLocations
        {
            get { return dataLocations; }
        }

        public X509Extensions Extensions
        {
            get { return extensions; }

            set
            {
                if (initialInfo != null)
                {
                    throw new Exception("cannot change extensions in existing DVCSRequestInformation");
                }

                this.extensions = value;
            }
        }


        public DVCSRequestInformationBuilder(ServiceType service)
        {
            this.service = service;
        }

        public DVCSRequestInformationBuilder(DVCSRequestInformation initialInfo)
        {
            this.initialInfo = initialInfo;
            this.service = initialInfo.Service;
            this.version = initialInfo.Version;
            this.nonce = initialInfo.Nonce;
            this.requestTime = initialInfo.RequestTime;
            this.requestPolicy = initialInfo.RequestPolicy;
            this.dvcs = initialInfo.DVCS;
            this.dataLocations = initialInfo.DataLocations;
        }

        public DVCSRequestInformation Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(9);

            if (version != DEFAULT_VERSION)
            {
                v.Add(new DerInteger(version));
            }
            v.Add(service);
            if (nonce != null)
            {
                v.Add(new DerInteger(nonce));
            }
            if (requestTime != null)
            {
                v.Add(requestTime);
            }

            int[] tags = new int[]{
                TAG_REQUESTER,
                TAG_REQUEST_POLICY,
                TAG_DVCS,
                TAG_DATA_LOCATIONS,
                TAG_EXTENSIONS
            };
            Asn1Encodable[] taggedObjects = new Asn1Encodable[]{
                requester,
                requestPolicy,
                dvcs,
                dataLocations,
                extensions
            };
            for (int i = 0; i < tags.Length; i++)
            {
                int tag = tags[i];
                Asn1Encodable taggedObject = taggedObjects[i];
                if (taggedObject != null)
                {
                    v.Add(new DerTaggedObject(false, tag, taggedObject));
                }
            }

            return DVCSRequestInformation.GetInstance(new DerSequence(v));
        }


        public void SetRequestor(GeneralName name)
        {
            this.requester = new GeneralNames(name); 
        }

        public void SetDvcs(GeneralName dvcs)
        {
            this.dvcs = new GeneralNames(dvcs); 
        }

        public void SetDataLocations(GeneralName dataLocations)
        {
            this .dataLocations = new GeneralNames(dataLocations);
        }
    }
}
