/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This package is based on the work done by Keiron Liddle, Aftex Software
 * <keiron@aftexsw.com> to whom the Ant project is very grateful for his
 * great code.
 */

namespace Org.BouncyCastle.Utilities.Bzip2
{
    /**
    * Base class for both the compress and decompress classes.
    * Holds common arrays, and static data.
    *
    * @author <a href="mailto:keiron@aftexsw.com">Keiron Liddle</a>
    */
    public class BZip2Constants
    {
        /// <summary>The <c>baseBlockSize</c> constant, with the value <c>100000</c>.</summary>
        public const int baseBlockSize = 100000;
        /// <summary>The <c>MAX_ALPHA_SIZE</c> constant, with the value <c>258</c>.</summary>
        public const int MAX_ALPHA_SIZE = 258;
        /// <summary>The <c>MAX_CODE_LEN</c> constant, with the value <c>20</c>.</summary>
        public const int MAX_CODE_LEN = 20;
        /// <summary>The <c>MAX_CODE_LEN_GEN</c> constant, with the value <c>17</c>.</summary>
        public const int MAX_CODE_LEN_GEN = 17;
        /// <summary>The <c>RUNA</c> constant, with the value <c>0</c>.</summary>
        public const int RUNA = 0;
        /// <summary>The <c>RUNB</c> constant, with the value <c>1</c>.</summary>
        public const int RUNB = 1;
        /// <summary>The <c>N_GROUPS</c> constant, with the value <c>6</c>.</summary>
        public const int N_GROUPS = 6;
        /// <summary>The <c>G_SIZE</c> constant, with the value <c>50</c>.</summary>
        public const int G_SIZE = 50;
        /// <summary>The <c>N_ITERS</c> constant, with the value <c>4</c>.</summary>
        public const int N_ITERS = 4;
        public const int MAX_SELECTORS = 2 + (900000 / G_SIZE);
        /// <summary>The <c>NUM_OVERSHOOT_BYTES</c> constant, with the value <c>20</c>.</summary>
        public const int NUM_OVERSHOOT_BYTES = 20;
    }
}
