using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
    public class DVCSCertInfo //:TODO not ready 
    {
    }
}
