using System;

namespace Org.BouncyCastle.Pkix
{
#if !PORTABLE
    [Serializable]
#endif
    public class PkixNameConstraintValidatorException
        : Exception
    {
        public PkixNameConstraintValidatorException(string msg)
            : base(msg)
        {
        }
    }
}
