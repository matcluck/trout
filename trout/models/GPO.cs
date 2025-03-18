using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace trout.models
{
    public class GPO
    {
        public string guid { get; set; }
        public string name { get; set; }
        public RawSecurityDescriptor sd { get; set; }
        public int version { get; set; }

        override public string ToString()
        {
            return $"{name}: {guid}";
        }

        public GPO(string guid, string name, RawSecurityDescriptor sd, int version)
        {
            this.guid = guid;
            this.name = name;
            this.sd = sd;
            this.version = version;
        }
    }
}
