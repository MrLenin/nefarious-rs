/// IRC numeric reply codes.
///
/// These follow RFC 2812 and Nefarious extensions.

// Connection registration
pub const RPL_WELCOME: u16 = 1;
pub const RPL_YOURHOST: u16 = 2;
pub const RPL_CREATED: u16 = 3;
pub const RPL_MYINFO: u16 = 4;
pub const RPL_ISUPPORT: u16 = 5;

// Stats
pub const RPL_STATSLINKINFO: u16 = 211;
pub const RPL_STATSUPTIME: u16 = 242;
pub const RPL_ENDOFSTATS: u16 = 219;

// Admin
pub const RPL_ADMINME: u16 = 256;
pub const RPL_ADMINLOC1: u16 = 257;
pub const RPL_ADMINLOC2: u16 = 258;
pub const RPL_ADMINEMAIL: u16 = 259;

// Lusers
pub const RPL_LUSERCLIENT: u16 = 251;
pub const RPL_LUSEROP: u16 = 252;
pub const RPL_LUSERUNKNOWN: u16 = 253;
pub const RPL_LUSERCHANNELS: u16 = 254;
pub const RPL_LUSERME: u16 = 255;

// Time
pub const RPL_TIME: u16 = 391;

// Links
pub const RPL_LINKS: u16 = 364;
pub const RPL_ENDOFLINKS: u16 = 365;

// Info
pub const RPL_INFO: u16 = 371;
pub const RPL_ENDOFINFO: u16 = 374;

// Map (Nefarious extension)
pub const RPL_MAP: u16 = 15;
pub const RPL_MAPEND: u16 = 17;

// Trace
pub const RPL_TRACEUSER: u16 = 205;
pub const RPL_TRACESERVER: u16 = 206;
pub const RPL_TRACEEND: u16 = 262;

// Userhost/Ison
pub const RPL_USERHOST: u16 = 302;
pub const RPL_ISON: u16 = 303;

// Away
pub const RPL_AWAY: u16 = 301;
pub const RPL_UNAWAY: u16 = 305;
pub const RPL_NOWAWAY: u16 = 306;

// WHOIS
pub const RPL_WHOISUSER: u16 = 311;
pub const RPL_WHOISSERVER: u16 = 312;
pub const RPL_WHOISOPERATOR: u16 = 313;
pub const RPL_ENDOFWHO: u16 = 315;
pub const RPL_WHOISIDLE: u16 = 317;
pub const RPL_ENDOFWHOIS: u16 = 318;
pub const RPL_WHOISCHANNELS: u16 = 319;
pub const RPL_WHOISACCOUNT: u16 = 330;

// LIST
pub const RPL_LISTSTART: u16 = 321;
pub const RPL_LIST: u16 = 322;
pub const RPL_LISTEND: u16 = 323;

// Channel
pub const RPL_CHANNELMODEIS: u16 = 324;
pub const RPL_CREATIONTIME: u16 = 329;
pub const RPL_NOTOPIC: u16 = 331;
pub const RPL_TOPIC: u16 = 332;
pub const RPL_TOPICWHOTIME: u16 = 333;
pub const RPL_INVITING: u16 = 341;

// WHO
pub const RPL_WHOREPLY: u16 = 352;

// NAMES
pub const RPL_NAMREPLY: u16 = 353;
pub const RPL_ENDOFNAMES: u16 = 366;

// MOTD
pub const RPL_MOTDSTART: u16 = 375;
pub const RPL_MOTD: u16 = 372;
pub const RPL_ENDOFMOTD: u16 = 376;

// OPER
pub const RPL_YOUREOPER: u16 = 381;

// Errors
pub const ERR_NOSUCHNICK: u16 = 401;
pub const ERR_NOSUCHSERVER: u16 = 402;
pub const ERR_NOSUCHCHANNEL: u16 = 403;
pub const ERR_CANNOTSENDTOCHAN: u16 = 404;
pub const ERR_TOOMANYCHANNELS: u16 = 405;
pub const ERR_UNKNOWNCOMMAND: u16 = 421;
pub const ERR_NOMOTD: u16 = 422;
pub const ERR_NONICKNAMEGIVEN: u16 = 431;
pub const ERR_ERRONEUSNICKNAME: u16 = 432;
pub const ERR_NICKNAMEINUSE: u16 = 433;
pub const ERR_USERNOTINCHANNEL: u16 = 441;
pub const ERR_NOTONCHANNEL: u16 = 442;
pub const ERR_USERONCHANNEL: u16 = 443;
pub const ERR_NOTREGISTERED: u16 = 451;
pub const ERR_NEEDMOREPARAMS: u16 = 461;
pub const ERR_ALREADYREGISTERED: u16 = 462;
pub const ERR_PASSWDMISMATCH: u16 = 464;
pub const ERR_CHANNELISFULL: u16 = 471;
pub const ERR_UNKNOWNMODE: u16 = 472;
pub const ERR_INVITEONLYCHAN: u16 = 473;
pub const ERR_BANNEDFROMCHAN: u16 = 474;
pub const ERR_BADCHANNELKEY: u16 = 475;
pub const ERR_NOPRIVILEGES: u16 = 481;
pub const ERR_CHANOPRIVSNEEDED: u16 = 482;
pub const ERR_UMODEUNKNOWNFLAG: u16 = 501;
pub const ERR_USERSDONTMATCH: u16 = 502;
