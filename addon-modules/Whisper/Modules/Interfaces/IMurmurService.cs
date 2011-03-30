using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nini.Config;
using Aurora.Simulation.Base;
using log4net;
using OpenSim.Framework;
using OpenMetaverse;
using OpenMetaverse.StructuredData;

namespace Aurora.Voice.Whisper
{
    public interface IMurmurService
    {
        public class MurmurConfig
        {
            public string MurmurHost; //IP to connect to to talk with the Murmur server
            public string MetaIce; //
            public string ServerVersion; //The version of the server
            public int ServerID; //ID of the server (normally 1)
            public bool GlacierEnabled; //Is Glacier enabled
            public string GlacierIce;
            public string GlacierUser; //Glacier user
            public string GlacierPass; //Glacier pass
            public string ChannelName; //The channel to connect to
            public string IceCB;

            public void FromOSD(OSDMap map)
            {
                MurmurHost = map["MurmurHost"];
                MetaIce = map["MetaIce"];
                ServerVersion = map["ServerVersion"];
                ServerID = map["ServerID"];
                GlacierEnabled = map["GlacierEnabled"];
                GlacierIce = map["GlacierIce"];
                GlacierUser = map["GlacierUser"];
                GlacierPass = map["GlacierPass"];
                ChannelName = map["ChannelName"];
                IceCB = map["IceCB"];
            }

            public OSDMap ToOSD()
            {
                OSDMap map = new OSDMap();

                map["MurmurHost"] = MurmurHost;
                map["MetaIce"] = MetaIce;
                map["ServerVersion"] = ServerVersion;
                map["ServerID"] = ServerID;
                map["GlacierEnabled"] = GlacierEnabled;
                map["GlacierIce"] = GlacierIce;
                map["GlacierUser"] = GlacierUser;
                map["GlacierPass"] = GlacierPass;
                map["ChannelName"] = ChannelName;
                map["IceCB"] = IceCB;

                return map;
            }
        }

        MurmurConfig GetConfiguration(string regionName);
    }
}
