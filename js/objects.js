const transformType = {1:"Route", 2:"SNAT", 3:"NAT", 4:"Magic"};
var flow = {src:"", dest:"", src_port:"", dst_port:"", tags:[]};
var transform {
	source: flow;
	dest: flow;
	Route: function() {
		this.dest.tags="Central";
	}
	SNAT: function() {
		this.dest.src="192.168.1.1";
	}
}
	
