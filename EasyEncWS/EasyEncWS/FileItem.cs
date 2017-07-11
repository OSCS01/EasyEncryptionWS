using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyEncWS
{
    class FileItem
    {
        public string hashedFilename { get; set; }
        public string EncKey { get; set; }
        public string IV { get; set; }
        public string Originalfilename { get; set; }

        public string OriginalfileExt { get; set; }

        public FileItem()
        {
        }
    }
}
