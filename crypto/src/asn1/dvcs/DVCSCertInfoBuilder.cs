using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.asn1.dvcs
{
 /**
 * <pre>
 *     DVCSCertInfo::= SEQUENCE  {
 *         version             Integer DEFAULT 1 ,
 *         dvReqInfo           DVCSRequestInformation,
 *         messageImprint      DigestInfo,
 *         serialNumber        Integer,
 *         responseTime        DVCSTime,
 *         dvStatus            [0] PKIStatusInfo OPTIONAL,
 *         policy              [1] PolicyInformation OPTIONAL,
 *         reqSignature        [2] SignerInfos  OPTIONAL,
 *         certs               [3] SEQUENCE SIZE (1..MAX) OF
 *                                 TargetEtcChain OPTIONAL,
 *         extensions          Extensions OPTIONAL
 *     }
 * </pre>
 */
    public class DVCSCertInfoBuilder 
    {
        private const int DEFAULT_VERSION = 1;
        private const int TAG_DV_STATUS = 0;
        private const int TAG_POLICY = 1;
        private const int TAG_REQ_SIGNATURE = 2;
        private const int TAG_CERTS = 3;

        private int version = DEFAULT_VERSION;
        private DVCSRequestInformation dvReqInfo;
        private DigestInfo messageImprint;
        private DerInteger serialNumber;
        private DVCSTime responseTime;
        private PkiStatusInfo dvStatus;
        private PolicyInformation policy;
        private Asn1Set reqSignature;
        private Asn1Sequence certs;
        private X509Extensions extensions;

       //TODO  Complete 

    }
}
