using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.dvcs
{
    public class DVCSRequestInfo
    {
        private DVCSRequestInformation data;

        public DVCSRequestInfo(byte[] inner) : this(DVCSRequestInformation.GetInstance(inner))
        {
           
        }

        
        public DVCSRequestInfo(DVCSRequestInformation data)
        {
            this.data = data;
        }

        public DVCSRequestInformation ToASN1Structure()
        {
            return data;
        }


        public int Version => data.Version;

        public int ServiceType => data.Service.Value.IntValue; 

        public BigInteger Nonce => data.Nonce;

        public DateTime? RequestTime
        {
            get
            {
                DVCSTime time = data.RequestTime;

                if (time == null)
                {
                    return null; 
                }

                try
                {
                    if (time.GetGenTime() != null)
                    {
                        return time.GetGenTime().ToDateTime(); 
                    }
                    else
                    {
                        TimeStampToken token = new TimeStampToken(time.GetTimeStampToken());

                        return token.TimeStampInfo.GenTime; 
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }
        }


        public GeneralNames Requestor => data.Requester;

        public PolicyInformation RequestPolicy
        {
            get
            {
                if (data.RequestPolicy != null)
                {
                    return data.RequestPolicy; 
                }
                return null;
            }
        }


        public GeneralNames DVCSNames => data.DVCS; 

        public GeneralNames DataLocations => data.DataLocations;


        public static bool Validate(DVCSRequestInfo requestInfo, DVCSRequestInfo responseInfo)
        {

            // RFC 3029, 9.1
            // The DVCS MAY modify the fields:
            // 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure.

            DVCSRequestInformation clientInfo = requestInfo.data;
            DVCSRequestInformation serverInfo = responseInfo.data;

            if (clientInfo.Version != serverInfo.Version)
            {
                return false;
            }
            if (!ClientEqualsServer(clientInfo.Service, serverInfo.Service))
            {
                return false;
            }
            if (!ClientEqualsServer(clientInfo.RequestTime, serverInfo.RequestTime))
            {
                return false;
            }
            if (!ClientEqualsServer(clientInfo.RequestPolicy, serverInfo.RequestPolicy))
            {
                return false;
            }
            if (!ClientEqualsServer(clientInfo.Extensions, serverInfo.Extensions))
            {
                return false;
            }

            // RFC 3029, 9.1. The only modification allowed to a 'nonce'
            // is the inclusion of a new field if it was not present,
            // or to concatenate other data to the end (right) of an existing value.

            if (clientInfo.Nonce != null)
            {
                if (serverInfo.Nonce == null)
                {
                    return false;
                }
                byte[] clientNonce = clientInfo.Nonce.ToByteArray();
                byte[] serverNonce = serverInfo.Nonce.ToByteArray();
                if (serverNonce.Length < clientNonce.Length)
                {
                    return false;
                }
                if (!Arrays.AreEqual(clientNonce, Arrays.CopyOfRange(serverNonce, 0, clientNonce.Length)))
                {
                    return false;
                }
            }


            return true; 
        }

        private static bool ClientEqualsServer(Object client, Object server)
        {
            return (client == null && server == null) || (client != null && client.Equals(server));
        }

    }
}
