//The ASN class is used to valide BGP AS numbers
//The ipv4 class is used to validate ipv4 + cidr addresses as well as providing the network information for that address
//

class asn{
	constructor(input_string, debug = false) {
		this.asn_regex = /^(?:6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3})$/;
		this.asn = input_string;
		this.isvalid = this.asn_regex.test(input_string);

		if (this.isvalid === true) {
			this.response = `${this.asn} is valid`;
		} else if (this.isvalid === false) {
			this.response = `[${this.asn}] is not valid`;
		}
	}	
}


class ipv4{
    constructor(address_string, cidr_required = false, debug = false) {
        // address_string (expect "xxx.xxx.xxx.xxx/xx") as string
        // cidr_required as boolean
        // debug as boolean
        this.ipv4_regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/;
        this.cidr_regex = /^(?:\d|[12]\d|3[0-2])$/;
        this.cidr_required = cidr_required;
        this.debug = debug;
        if (this.debug) {
            console.log(`The received address_string is ${address_string}`);
        }
        
        if (address_string.includes("/")) {
            [this.ipaddress, this.cidr] = address_string.split("/");
        } else {
            this.ipaddress = address_string;
            this.cidr = undefined;
        }
        
        if (this.debug) {
            console.log(`The discovered IP address is ${this.ipaddress}`);
            console.log(`The discovered CIDR is ${this.cidr}`);
          
        }
        
        if (this.cidr_required === false) { // CIDR not required so only looking at the IP address
            this.ip_isvalid = this.ipv4_regex.test(this.ipaddress);
            
            if (this.debug) {
                console.log(`this.ip_isvalid = ${this.ip_isvalid}`);
            }
            
            if (this.ip_isvalid === true && this.cidr === undefined) {
                this.response = `${this.ipaddress} is valid`
            } else if (this.ip_isvalid === false && this.cidr === undefined) {
                this.response = `[${this.ipaddress}] is not valid`
            } else if (this.cidr != undefined) { // if there is a cidr when there shouldn't be make it false
                this.ip_isvalid = false
                this.response = `This field does not accept IP address with CIDR`
            }
        } else if (this.cidr_required === true) { // CIDR required, need to look at both
            if (this.cidr === undefined) { // IP received, but CIDR missing
                this.isvalid = false // If cidr is required, but is missing the pair will always be false
                this.ip_isvalid = this.ipv4_regex.test(this.ipaddress);
                if (this.ip_isvalid === true) {
                    this.response = `${this.ipaddress} is valid, but a CIDR is missing`
                } else {
                    this.response = `[${this.ipaddress}] is not valid and a CIDR is missing`
                }
            } else if (this.cidr != undefined) { // IP received and CIDR received
                this.ip_isvalid = this.ipv4_regex.test(this.ipaddress);
                this.cidr_isvalid = this.cidr_regex.test(this.cidr);
                this.isvalid = this.ip_isvalid && this.cidr_isvalid;
                //compute subnet information if we have a valid ip and cidr
                if (this.isvalid === true) { // Both are valid
                    this.response = `${this.ipaddress}/${this.cidr} is valid`
                    if (this.cidr === "32") {
                        this.networkAddress = this.ipaddress
                        this.firstUsableAddress = this.ipaddress
                        this.lastUsableAddress = this.ipaddress
                        this.broadcastAddress = this.ipaddress
                    } else if (this.cidr === "31") {
                        [this.firstUsableAddress, this.lastUsableAddress] = this._slash31(this.ipaddress);
                        this.networkAddress = this.firstUsableAddress;
                        this.broadcastAddress = this.lastUsableAddress;
                    } else {
                        this.networkAddress = this._findNetworkAddress(this.ipaddress, this.cidr);
                        this.firstUsableAddress = this._findFirstUsableAddress(this.ipaddress, this.cidr);
                        this.lastUsableAddress = this._findLastUsableAddress(this.ipaddress, this.cidr);
                        this.broadcastAddress = this._findBroadcastAddress(this.ipaddress, this.cidr);
                    }
                } else if (this.ip_isvalid === true && this.cidr_isvalid === false) { // IP is valid, CIDR is invalid
                    this.response = `${this.ipaddress} is valid, but [/${this.cidr}] is not valid.`
                } else if (this.ip_isvalid === false && this.cidr_isvalid === true) { // IP is invalid, CIDR is valid
                    this.response = `/${this.cidr} is valid, but [${this.ipaddress}] is not valid.`
                } else if (this.ip_isvalid === false && this.cidr_isvalid === false) { // Both are invalid
                    this.response = `Both [${this.ipaddress}] and [/${this.cidr}] are not valid.`
                } 
            }
        }
    } 
    
    //functions
    _cidrToNumericSubnetMask(cidr) {
        const networkBits = 32 - parseInt(cidr, 10);
        return (Math.pow(2, 32) - 1) << networkBits >>> 0;
    }
    
    _longToIpv4(long) {
        const octet1 = (long >>> 24) & 0xFF;
        const octet2 = (long >>> 16) & 0xFF;
        const octet3 = (long >>> 8) & 0xFF;
        const octet4 = long & 0xFF;
        return `${octet1}.${octet2}.${octet3}.${octet4}`;
    }
    
    _ipv4ToLong(ip) {
        const [octet1, octet2, octet3, octet4] = ip.split('.').map(Number);
        return (octet1 << 24) + (octet2 << 16) + (octet3 << 8) + octet4;
    }

    _findLastUsableAddress(ip, cidr) {
        const numericIpAddress = this._ipv4ToLong(ip);
        const numericSubnetMask = this._cidrToNumericSubnetMask(cidr);
        const numericNetworkAddress = numericIpAddress & numericSubnetMask;
        const networkBits = 32 - parseInt(cidr, 10);
        const numericLastUsable = numericNetworkAddress + Math.pow(2, networkBits) - 2;
        return this._longToIpv4(numericLastUsable);
    }
    
    _findBroadcastAddress(ip, cidr) {
        const numericIpAddress = this._ipv4ToLong(ip);
        const numericSubnetMask = this._cidrToNumericSubnetMask(cidr);
        const numericNetworkAddress = numericIpAddress & numericSubnetMask;
        const networkBits = 32 - parseInt(cidr, 10);
        const numericBroadcast = numericNetworkAddress + Math.pow(2, networkBits) - 1;
        return this._longToIpv4(numericBroadcast);
    }
    
    _findFirstUsableAddress(ip, cidr) {
        const numericIpAddress = this._ipv4ToLong(ip);
        const numericSubnetMask = this._cidrToNumericSubnetMask(cidr);
        const numericNetworkAddress = numericIpAddress & numericSubnetMask;
        const numericFirstUsableAddress = numericNetworkAddress + 1;
        return this._longToIpv4(numericFirstUsableAddress);
    }

    _findNetworkAddress(ip, cidr) {
        const numericIpAddress = this._ipv4ToLong(ip);
        const numericSubnetMask = this._cidrToNumericSubnetMask(cidr);
        const numericNetworkAddress = numericIpAddress & numericSubnetMask;
        return this._longToIpv4(numericNetworkAddress);
    }
    _slash31(ip) {
        const [octet1, octet2, octet3, octet4] = ip.split('.').map(Number);
        const longip = (octet1 << 24) + (octet2 << 16) + (octet3 << 8) + octet4;

        let firstAddress, lastAddress;

        if (octet4 != 255) {
            if (octet4 % 2 === 0) {
                firstAddress = longip;
                lastAddress = longip + 1;
            } else {
                firstAddress = longip - 1;
                lastAddress = longip;
            }
        } else {
            firstAddress = longip - 1;
            lastAddress = longip;
        }
        return [this._longToIpv4(firstAddress), this._longToIpv4(lastAddress)];
    }
}
