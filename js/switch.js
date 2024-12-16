class Switch {
	constructor(switch_id, name, switch_number, model, family, serial, MAC, stack_link1, stack_link2, ports={}, portTypes=[], instance="") {
		this.switch_id = switch_id;
		this.name = name;
		this.switch_number = switch_number;
		this.model = model;
		this.family = family;
		this.serial = serial;
		this.MAC = MAC;
		if (instance == "") {
			this.instance = name+"_"+switch_number;
			this.passed_instance = "";
		} else {
			this.instance = instance;
			this.passed_instance = instance;
		}
		this.svgName = this.instance+"_svg"
		this.menuInstance = this.instance+"_menu"
		this.ports = ports
		this.portTypes = portTypes.map((x)=>x);
		this.switchSVG = document.getElementById('switches');
        this.textY_offset = 0;
		if (this.family=="6400") {
			this.svgButton_add = document.getElementById('svg-button-add');
			this.svgButton_change = document.getElementById('svg-button-change');
			this.svgButton_remove = document.getElementById('svg-button-remove');
			this.switchSVG.innerHTML = this.switchSVG.innerHTML + "<div id='switch_"+this.instance+"' oid='"+this.switch_number+"' did='"+this.switch_id+"' style='order: number'><svg style='margin-left:20px' id="+this.svgName+" viewBox='0 0 1000 990'></svg></div>";
			this.registeredCards = document.getElementById('registeredCards');
			if (this.registeredCards.innerHTML != "[]") {
				let arr = JSON.parse(this.registeredCards.innerHTML);
				let found=false;
				for (let r of arr) {
					if (r["switch_number"] == this.switch_number) { found=true; break; }
				}
				if (!found) {
					this.registeredCards.innerHTML = this.registeredCards.innerHTML.substr(0, this.registeredCards.innerHTML.length-1) + "," + '{"switch_number":"'+this.switch_number+'","switch_model":"'+this.model+'"}]';
				}
			} else {
					this.registeredCards.innerHTML = '[{"switch_number":"'+this.switch_number+'","switch_model":"'+this.model+'"}]';
			}
		} else if (this.family=="6199") { 
            this.family="4100i";
            this.switchSVG.innerHTML = this.switchSVG.innerHTML + "<div id='switch_"+this.instance+"' oid='"+this.switch_number+"' did='"+this.switch_id+"' style='order: number'><svg style='margin-left: 20px' id="+this.svgName+" viewBox='0 0 1000 990'></svg></div";
        } else {
			this.switchSVG.innerHTML = this.switchSVG.innerHTML + "<div id='drop_"+this.instance+"_zone' sid='"+this.switch_number+"' class='drop-zone'><div id='switch_"+this.instance+"' oid='"+this.switch_number+"' did='"+this.switch_id+"' draggable='true' class='draggable-switch' style='order: number'><svg style='margin-left:20px' id="+this.svgName+" viewBox='0 0 910 145'></svg></div></div>";
		}
		this.switchMenu = document.getElementById('deviceContextMenu');
		if (this.family!="6400") {
			this.switchMenu.innerHTML = this.switchMenu.innerHTML + "<div id="+this.menuInstance+" class='deviceContextMenuInstance'></div>";
		} else {
			if (this.switch_number==0) {
				this.switchMenu.innerHTML = this.switchMenu.innerHTML + "<div id="+this.menuInstance+" class='deviceContextMenuInstance6405'></div>";
			}
		}
		this.stack_link1 = stack_link1;
		this.stack_link2 = stack_link2;
		this.stack_in = this.stack_from_bigint(stack_link2);
		this.stack_out= this.stack_from_bigint(stack_link1);
		this.banks=[]
		this.shell = { chassis: 'chassis-1u', faceplate: 'faceplate-1u' };
		switch (this.model) {
			case "R0X26C":
			case "R0X29A":
			case "R0X30A":
				this.shell = { chassis: 'chassis-6405', faceplate: 'faceplate-6405' };
				this.slots = 8;
				this.totalPorts=0;
				break;
            case "JL817A":
                this.shell = { chassis: 'chassis-4100i', faceplate: 'faceplate-4100i' };
                this.banks = [
                        {ports: 4, port_type: "Copper", position_x: 260, position_y: 180, spacing: 28, portStart: 0, split_ports: true, rotate: 90, direction: "topdown"},
                        {ports: 8, port_type: "Copper", position_x: 260, position_y: 260, spacing: 28, portStart: 4, split_ports: true, rotate: 90, direction: "topdown"},
                        {ports: 2, port_type: "SFP",    position_x: 160, position_y: 242, spacing: 40, portStart: 12, split_ports: false, rotate: 90, direction: "topdown"}
                    ];
                this.totalPorts=12;
                this.textY_offset=400;
                break;
			case "R0X31A":
				this.banks = [
								{ports: 2, port_type: "Copper-NoFunc", position_x: 350, position_y: 80, spacing: 60, portStart: 0, split_ports: false}
							];
				this.totalPorts=0;
				break;
			case "R0X38B":
			case "R0X38C":
				this.banks = [
								{ports: 12, port_type: "Copper", position_x: 0, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
								{ports: 12, port_type: "Copper", position_x: 185, position_y: 10, spacing: 28, portStart: 12, split_ports: true},
								{ports: 12, port_type: "Copper", position_x: 370, position_y: 10, spacing: 28, portStart: 24, split_ports: true},
								{ports: 12, port_type: "Copper", position_x: 555, position_y: 10, spacing: 28, portStart: 36, split_ports: true}
					];
				//this.totalPorts = this.totalPorts + 48;
				this.totalPorts = 48;
				break;
			case "R0X39B":
			case "R0X39C":
			case "R0X41A":
			case "R0X41C":
				this.banks = [
								{ports: 12, port_type: "Copper", position_x: 0, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
								{ports: 12, port_type: "Copper", position_x: 185, position_y: 10, spacing: 28, portStart: 12, split_ports: true},
								{ports: 12, port_type: "Copper", position_x: 370, position_y: 10, spacing: 28, portStart: 24, split_ports: true},
								{ports: 12, port_type: "Copper", position_x: 555, position_y: 10, spacing: 28, portStart: 36, split_ports: true},
						        {ports: 4, port_type: "SFP", position_x: 820, position_y: 10, spacing: 50, portStart: 48, split_ports: true} 
					];
				//this.totalPorts = this.totalPorts + 52;
				this.totalPorts = 52;
				break;
			case "R0X42A":
			case "R0X42C":
				this.banks = [
								{ports: 8, port_type: "Copper", position_x: 270, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
								{ports: 16, port_type: "Copper", position_x: 400, position_y: 10, spacing: 28, portStart: 8, split_ports: true},
						        {ports: 4, port_type: "SFP", position_x: 820, position_y: 10, spacing: 50, portStart: 24, split_ports: true} 
					];
				//this.totalPorts = this.totalPorts + 28;
				this.totalports = 28;
				break;
			case "R0X43A":
			case "R0X43C":
				this.banks = [
								{ports: 8, port_type: "SFP", position_x: 180, position_y: 10, spacing: 40, portStart: 0, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 360, position_y: 10, spacing: 40, portStart: 8, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 540, position_y: 10, spacing: 40, portStart: 16, split_ports: true},
						        {ports: 4, port_type: "SFP", position_x: 820, position_y: 10, spacing: 50, portStart: 24, split_ports: true} 
					];
				//this.totalPorts = this.totalPorts + 28;
				this.totalports = 28;
				break;
			case "R0X44A":
			case "R0X44C":
				this.banks = [
								{ports: 8, port_type: "SFP", position_x: -35, position_y: 10, spacing: 39, portStart: 0, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 130, position_y: 10, spacing: 39, portStart: 8, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 295, position_y: 10, spacing: 39, portStart: 16, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 460, position_y: 10, spacing: 39, portStart: 24, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 625, position_y: 10, spacing: 39, portStart: 32, split_ports: true},
								{ports: 8, port_type: "SFP", position_x: 790, position_y: 10, spacing: 39, portStart: 40, split_ports: true}
					];
				//this.totalPorts = this.totalPorts + 48;
				this.totalPorts=48;
				break;
			case "R0X45A":
			case "R0X45C":
				this.banks = [
								{ports: 4, port_type: "QSFP", position_x: 180, position_y: 50, spacing: 87, portStart: 0, split_ports: false},
								{ports: 4, port_type: "QSFP", position_x: 360, position_y: 50, spacing: 87, portStart: 4, split_ports: false},
								{ports: 4, port_type: "QSFP", position_x: 540, position_y: 50, spacing: 87, portStart: 8, split_ports: false}
					];
				//this.totalPorts = this.totalPorts + 12;
				this.totalPorts=12;
				break;
			case "JL660A"	:
				this.banks = [
							   {ports: 8, port_type: "Copper", position_x: 372, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
							   {ports: 16, port_type: "Copper", position_x: 502, position_y: 10, spacing: 28, portStart: 8, split_ports: true},
						       {ports: 4, port_type: "SFP", position_x: 740, position_y: 10, spacing: 50, portStart: 24, split_ports: true} 
							];
				this.totalPorts = 28;
				break;
			case "JL659A"	:	
				this.banks = [ 
							   {ports: 8, port_type: "Copper", position_x: 0, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
							   {ports: 16, port_type: "Copper", position_x: 130, position_y: 10, spacing: 28, portStart: 8, split_ports: true},
							   {ports: 8, port_type: "Copper", position_x: 372, position_y: 10, spacing: 28, portStart: 24, split_ports: true},
							   {ports: 16, port_type: "Copper", position_x: 502, position_y: 10, spacing: 28, portStart: 32, split_ports: true},
						       {ports: 4, port_type: "SFP", position_x: 740, position_y: 10, spacing: 50, portStart: 48, split_ports: true} 
							 ];
				this.totalPorts = 52;
				break;
			case "JL658A"	:
				this.banks = [ 
							   {ports: 8, port_type: "SFP", position_x: 150, position_y: 10, spacing: 40, portStart: 0,  split_ports: true},
							   {ports: 8, port_type: "SFP", position_x: 320, position_y: 10, spacing: 40, portStart: 8,  split_ports: true},
							   {ports: 8, port_type: "SFP", position_x: 490, position_y: 10, spacing: 40, portStart: 16, split_ports: true},
						       {ports: 4, port_type: "SFP", position_x: 740, position_y: 10, spacing: 50, portStart: 24, split_ports: true} 
							 ];
				this.totalPorts = 28;
				break;
			case "JL677A"	:
				this.banks = [ 
							   {ports: 4, port_type: "SFP", position_x: 0, position_y: 10, spacing: 50, portStart: 24,  split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 400, position_y: 10, spacing: 28, portStart: 0,  split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 600, position_y: 10, spacing: 28, portStart: 12, split_ports: true}
							 ];
				this.totalPorts = 28;
				break;
			case "JL679A"	:
			case "R8N89A"	:
				this.shell = { chassis: 'chassis-small', faceplate: 'faceplate-small' };
				this.banks = [ 
							   {ports: 2, port_type: "SFP", position_x: 0, position_y: 78, spacing: 100, portStart: 14,  split_ports: false},
							   {ports: 2, port_type: "Copper", position_x: 150, position_y: 78, spacing: 60, portStart: 12,  split_ports: false},
							   {ports: 12, port_type: "Copper", position_x: 250, position_y: 10, spacing: 28, portStart: 0, split_ports: true}
							 ];
				this.totalPorts = 16;
				break;
			//Adding new 12 port 6200F switch
			case "R8Q72A":
				this.shell = { chassis: 'chassis-small', faceplate: 'faceplate-small' };
				this.banks = [ 															   					           
					           {ports: 12, port_type: "Copper", position_x: 0, position_y: 10, spacing: 28, portStart: 0, split_ports: true},					           
							   {ports: 2, port_type: "Copper", position_x: 160, position_y: 10, spacing: 60, portStart: 12, split_ports: true},							   							   
					           {ports: 2, port_type: "SFP", position_x: 228, position_y: 78, spacing: 100, portStart: 14, split_ports: false}
							 ];
				this.totalPorts = 16;
				break;
			case "JL727A"	:
			case "JL728A"	:
			case "JL728B"	:
			case "JL661A"	:
				this.banks = [	
							   {ports: 12, port_type: "Copper", position_x: 0, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 185, position_y: 10, spacing: 28, portStart: 12, split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 370, position_y: 10, spacing: 28, portStart: 24, split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 555, position_y: 10, spacing: 28, portStart: 36, split_ports: true},
						       {ports: 4, port_type: "SFP", position_x: 740, position_y: 10, spacing: 50, portStart: 48, split_ports: true} 
							];
				this.totalPorts = 52;
				break;
			case "JL675A"	:
				this.banks = [	
						       {ports: 4, port_type: "SFP", position_x: 0, position_y: 10, spacing: 50, portStart: 48, split_ports: true}, 
							   {ports: 12, port_type: "Copper", position_x: 140, position_y: 10, spacing: 28, portStart: 0, split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 325, position_y: 10, spacing: 28, portStart: 12, split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 510, position_y: 10, spacing: 28, portStart: 24, split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 695, position_y: 10, spacing: 28, portStart: 36, split_ports: true}
							];
				this.totalPorts = 52;
				break;
			case "JL678A"	:
			case "JL678A"	:
			case "R8N87A"	:
				this.banks = [ 
							   {ports: 4, port_type: "SFP", position_x: 0, position_y: 10, spacing: 50, portStart: 24,  split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 475, position_y: 10, spacing: 28, portStart: 0,  split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 675, position_y: 10, spacing: 28, portStart: 12, split_ports: true}
							 ];
				this.totalPorts = 28;
				break;
			case "JL662A"	:
			case "JL725B"	:
			case "JL725A"	:
				this.banks = [ 
							   {ports: 4, port_type: "SFP", position_x: 740, position_y: 10, spacing: 50, portStart: 24,  split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 375, position_y: 10, spacing: 28, portStart: 0,  split_ports: true},
							   {ports: 12, port_type: "Copper", position_x: 575, position_y: 10, spacing: 28, portStart: 12, split_ports: true}
							 ];
				this.totalPorts = 28;
				break;
			case "R8S89A"	:
				this.banks = [ 
							   {ports: 4, port_type: "SFP", position_x: 740, position_y: 10, spacing: 50, portStart: 24,  split_ports: true},
							   {ports: 8, port_type: "Copper", position_x: 225, position_y: 10, spacing: 33, portStart: 0,  split_ports: true},
							   {ports: 8, port_type: "Copper", position_x: 375, position_y: 10, spacing: 33, portStart: 8, split_ports: true},
							   {ports: 8, port_type: "Copper", position_x: 525, position_y: 10, spacing: 33, portStart: 16, split_ports: true}
							 ];
				this.totalPorts = 28;
				break;
		}
		this.draw();	
	}

	appendSVG(instance, element, id, x=0, y=0, port="", portType=null) {
	    let npt = element.cloneNode(true);
//	    document.getElementById(this.svgName).appendChild(npt);
	    npt.id=id;
	    npt.setAttribute("x", x);
	    npt.setAttribute("y", y);
		npt.setAttribute("switch_name",this.name);
		npt.setAttribute("switch_number",this.switch_number);
		npt.setAttribute("port",port);
		if (portType != null) {
			npt.setAttribute("port_type", portType);
		}
	    document.getElementById(this.svgName).appendChild(npt);
}

    addText(instance, txt, x=0, y=0, cl="") {
	    const svgNS = "http://www.w3.org/2000/svg";
	    let newText = document.createElementNS(svgNS, "text");
	    newText.setAttributeNS(null,"x",x);
	    newText.setAttributeNS(null,"y",y);
	    newText.setAttributeNS(null,"class",cl);
	    let textNode = document.createTextNode(txt);
	    newText.appendChild(textNode);
	    document.getElementById(this.svgName).appendChild(newText);
	}

	addPortRJ45(instance, id, x, y, nf, r=0, port=""){
		let yOffset=0;
		let npt;
	    if (r==0) {
        	        if (!nf) {
						npt = document.getElementById('rj45-up');
        	        	this.addText(instance, id, x+3, y+43, "txt");
					} else {
						npt = document.getElementById('rj45-up-nofunc');
					}
					yOffset=10;
	        }
        if (r==90) {
        	        if (!nf) {
						npt = document.getElementById('rj45-left');
        	        	this.addText(instance, id, x-20, y+20, "txt");
					} else {
						npt = document.getElementById('rj45-up-nofunc');
					}
					yOffset=10;
        }
        if (r==270) {
        	        if (!nf) {
						npt = document.getElementById('rj45-right');
        	        	this.addText(instance, id, x+35, y+20, "txt");
					} else {
						npt = document.getElementById('rj45-up-nofunc');
					}
					yOffset=10;
        }
	    if (r==180) {
					if (!nf) {
		                npt = document.getElementById('rj45-down')
			        	this.addText(instance, id, x+3, y-2, "txt");
					} else {
		                npt = document.getElementById('rj45-down-nofunc')
					}
					yOffset=6;
	        }
	    let n = document.getElementById("text_"+id);
		if (!nf) {

		try {
			if (this.ports != {} && this.ports[id].switch_name === undefined) { 
				npt.setAttribute("class", "port");
			} else {
				if (this.ports[id].shutdown) {
					npt.setAttribute("class","port portDown");
				} else {
					npt.setAttribute("class","port portUp");
					if (!this.ports[id].poe) {
						npt.setAttribute("class","port portDownPOE");
					}
				}
			}
		} catch {
			console.error ("I couldn't add an rj45 port for some reason");
			console.error ("instance {} id {} x {} y {} nf {} r {} switch {} port {}".format(instance, id, x, y, nf, r, this.switch_number, port));
		}
		} // end noFunc
	    this.appendSVG(instance, npt, instance+"_sw_"+this.switch_number+"_"+"port_"+id, x, y, id, 9);
		if (id>0){
			try {			
				if (this.ports != {} && this.ports[id].port_security_profile == 1) {					
					if (this.ports != {} && this.ports[id].vlan_access > 0) {this.addAccessIndicator(x + 6, y + yOffset + 1, id, r, "rj45"); }
					if (this.ports != {} && this.ports[id].lag > 0) { this.addPortLagIndicator(x + 8, y + yOffset, id, r, "rj45"); }
					if (this.ports != {} && this.ports[id].trunk > 0) { this.addPortTrunkIndicator(x + 5, y + yOffset, id, r, "rj45"); }
				} else if (this.ports != {} && this.ports[id].port_security_profile > 1) {
					//console.log("RJ45 with port_security_profile > 1", this.ports[id])
					this.addDynSegIndicator(x + 8, y + yOffset + 1, id, r, "rj45");
				}
			} catch {}
		}
	}

	addPortStack(stackType, x,y,id){
		let npt = document.getElementById("stackIndicator");
		if (stackType=="in") {
			this.appendSVG("", npt, "indicator", x+27, y-10, id,7);
		} else {
			this.appendSVG("", npt, "indicator", x+27, y+27, id,7);
		}
	}

	addPortLagIndicator(x, y, id, r=0, portType="rj45"){
        if (r==90 || r==270) {
            y = y - 3;
            if (portType == "sfp+") {
                y = y + 10;
                x = x - 5;
            }
        }
		let npt = document.getElementById("lagIndicator");
		this.appendSVG("", npt, "indicator", x, y, id,7);
	}

	addPortTrunkIndicator(x, y, id, r=0, portType="rj45"){
        if (r==90 || r==270) {
            y = y - 3;
            if (portType == "sfp+") {
                y = y + 10;
                x = x - 5;
            }
        }
		let npt = document.getElementById("trunkIndicator");
		//console.log("trunkIndicator", npt)
		this.appendSVG("", npt, "indicator", x, y, id,7);
	}
	
	addDynSegIndicator(x, y, id, r=0, portType="rj45") {
        if (r==90 || r==270) {
            y = y - 3;
            if (portType == "sfp+") {
                y = y + 15;
                x = x - 7;
            }
        }
		let npt = document.getElementById("dynSegIndicator");
		//console.log("DynSegIndicator npt", npt)
		this.appendSVG("", npt, "indicator", x, y, id, 7);
	}

	addAccessIndicator(x, y, id, r = 0, portType = "rj45") {
		if (r==90 || r==270) {
            y = y - 3;
            if (portType == "sfp+") {
                y = y + 15;
                x = x - 7;
            }
        }
		let npt = document.getElementById("accessIndicator");
		this.appendSVG("", npt, "indicator", x, y, id, 7);
	}

	addPortSFP(port_type, instance, id, x, y, r=0, port=""){
		let graphic = "";
		if (port_type == "QSFP") {
			graphic = "qsfp";
		} else {
			graphic = "sfp+";
		}
		let yOffset=6;
		let xOffset=0;
        let angle="";
        if (r==90) { angle = "-right"; graphic=graphic+angle; }
		try {
			switch (this.portTypes[id]) {
				case 1: if (port_type=="QSFP") { graphic="qsfp-fiber"+angle; } else { graphic="sfp-fiber"+angle; } if (this.ports != {} && this.ports[id].lag>0) { yOffset=12; xOffset=18; } else { yOffset=2; xOffset=14; } break;
				case 2: graphic="sfp-copper"+angle; if (this.ports != {} && this.ports[id].lag>0) { xOffset=15; } else { xOffset=13; } break;
			}
			let npt = document.getElementById(graphic)
			if (r==0) {
				this.addText(this.instance, id, x+3, y+43, "txt");
			} else if (r==90) {
                this.addText(this.instance, id, x-30, y+25, "txt");
            } else {
				this.addText(this.instance, id, x+3, y-2, "txt");
			}
			let n = document.getElementById("text_"+id);
			if (this.ports != {} && this.ports[id].switch_name === undefined) { 
				npt.setAttribute("class", "port");
			} else {
				if (this.ports != {} && this.ports[id].shutdown) {
					npt.setAttribute("class","port portDown");
				} else {
					npt.setAttribute("class","port portUp");
				}
			}

			this.appendSVG(this.instance, npt, this.instance+"_sw_"+this.switch_number+"_"+"port_"+id, x, y, id, this.portTypes[id]);
			if (this.stack_in.includes(id)) {this.addPortStack("in",x, y, id);}
			if (this.stack_out.includes(id)) {this.addPortStack("out",x,y,id);}
			if (id>0) {	
				if (this.ports != {} && this.ports[id].port_security_profile == 1) {
					if (this.ports != {} && this.ports[id].vlan_access > 0) {this.addAccessIndicator(x + 15, y + yOffset + 12, id, r, "sfp+"); }
					if (this.ports != {} && this.ports[id].lag > 0) { this.addPortLagIndicator(x + 15, y + yOffset, id, r, "sfp+"); }
					if (this.ports != {} && this.ports[id].trunk > 0) { this.addPortTrunkIndicator(x + 13, y + yOffset, id, r, "sfp+"); }
				} else if (this.ports != {} && this.ports[id].port_security_profile > 1) {
					//console.log("SFP with port_security_profile > 1", this.ports[id])
					this.addDynSegIndicator(x + 16, y + yOffset + 1, id, r, "sfp+");
				}
			}
		} catch {
			console.error ("I couldn't add an SFP port for some reason");
		}
	}

	addSVGButton(slot, button="", action="", x=850, y=130) {
		try {
			let npt;
			switch (button) {
				case "REMOVE":
					npt = this.svgButton_remove.cloneNode(true);
					break;
				case "CHANGE":
					npt = this.svgButton_change.cloneNode(true);
					break;
				case "ADD CARD":
				default:
					npt = this.svgButton_add.cloneNode(true);
					break;
			}
			if (npt) {
			    npt.id=this.instance+"_button_"+slot+"_"+button;
			    npt.setAttribute("x", x);
			    npt.setAttribute("y", y);
				npt.setAttribute("switch_name",this.name);
				npt.setAttribute("switch_number",this.switch_number);
				npt.setAttribute("action",action);
				npt.setAttribute("button_text",button);
				npt.setAttribute("slot",slot);
			    document.getElementById(this.svgName).appendChild(npt);
			}
		}
		catch(e){
			console.error(e);
		}
	}

	addItem(instance, svgElement, id, x, y, r=0){
	    let npt = document.getElementById(svgElement);
	    let objType = "";
	    if (svgElement=="sfp-fiber" || svgElement=="sfp+" || svgElement=="sfp-copper" || svgElement=="qsfp") { objType = "port_"; }
	    this.appendSVG(this.instance, npt, this.instance+"_"+objType+id, x, y, id);
	}

	registerButton(buttonText='', buttonClass='', buttonAction='') {
		//console.log(this.menuInstance);
		let palette = document.getElementById(this.menuInstance);
		if (palette) {
			palette.innerHTML = palette.innerHTML + "<button type='button' onClick='"+buttonAction+"; return false;' class='btn btn-success btn-sm "+buttonClass+"'>"+buttonText+"</button>";
		}
	}

	deregisterButtons() {
		let palette = document.getElementById(this.menuInstance);
		if (palette) {
			palette.innerHTML = "";
		}
	}

	stack_from_bigint(stack_int){
		let result = [];
		let x = BigInt(0);
		for (let i=0;i<64;i++) { 
			if (x==BigInt(0)) { x = BigInt(1); } else { x = BigInt(x * BigInt(2)); }
			if (BigInt(stack_int) & x) { result.push(i); }
		}
		return (result);
	}

	enableDragDrop() {
		let draggableElements = document.getElementsByClassName('draggable-switch');
		// set up draggable items
		for (let i = 0; i < draggableElements.length; i++) {
			this.dragElement(draggableElements[i]);
		}

		// set up drop zones
		let dropZones = document.getElementsByClassName('drop-zone');
		let currentDrop;
		if (dropZones.length > 1) {
		for (let dropZone of dropZones) {
			dropZone.addEventListener("dragover", e => {
				e.preventDefault();
				e.currentTarget.classList.add('drop-zone--over');
				e.currentTarget.classList.add('drop-zone--expand');
				currentDrop = e.currentTarget.id;
			});
	
			dropZone.addEventListener("dragleave", e=> {
				e.preventDefault();
				let dzs = document.getElementsByClassName('drop-zone');
				for (let i=0; i<dzs.length; i++) {
					if (dzs[i].id != currentDrop) {
						dzs[i].classList.remove('drop-zone--over');
						dzs[i].classList.remove('drop-zone--expand');
					}
				}
			});

			dropZone.addEventListener("dragend", e=> {
				e.preventDefault();
				let dzs = document.getElementsByClassName('drop-zone');
				for (let i=0; i<dzs.length; i++) {
						dzs[i].classList.remove('drop-zone--over');
						dzs[i].classList.remove('drop-zone--expand');
				}
			});

			dropZone.addEventListener("drop", e=> {
				e.preventDefault();
				let droppedElementId = e.dataTransfer.getData("text/plain");
				let droppedElement = document.getElementById(droppedElementId);
				const sourceElement = droppedElement.parentElement;
				const targetElement = e.currentTarget.firstChild;
				if (e.srcElement.hasChildNodes()) {
					let replaceSwitch = e.currentTarget.removeChild(e.currentTarget.childNodes[0]);
					e.currentTarget.appendChild(droppedElement);
					sourceElement.appendChild(replaceSwitch);
				}

				let dzs = document.getElementsByClassName('drop-zone');
				for (let i=0; i<dzs.length; i++) {
					dzs[i].classList.remove('drop-zone--over');
					dzs[i].classList.remove('drop-zone--expand');
				}
			
				window.switchApp.vue_deregister_all_buttons();
				for (let i=0; i<window.switchApp.sw.length; i++){
					window.switchApp.sw[i].deregisterButtons();
				}
				window.switchApp.areYouSureDefault = window.switchApp.areYouSureModify;
				window.switchApp.vue_register_button("Save Stack Order","gmiRed",window.switchApp.are_you_sure, "in", window.switchApp.switch_reorder_stack)
				window.switchApp.vue_register_button("Revert Stack Order","",window.switchApp.reload_page)
			});
			}
		}
	}

	returnSwitchOrder() {
		let result = [];
		let switchList = document.getElementById("switches");
		for (let i=0; i<switchList.childNodes.length; i++) {
			result.push({sid:parseInt(switchList.childNodes[i].getAttribute("sid")), did:parseInt(switchList.childNodes[i].firstChild.getAttribute("did")), nid:i+1, oid:parseInt(switchList.childNodes[i].firstChild.getAttribute("oid"))});
		}
		return (result);
	}

	dragElement(el) {
		el.addEventListener('dragstart', e => {
			e.dataTransfer.setData("text/plain", el.id);
		});
	}

	chassisButtons() {
		let arr = JSON.parse(this.registeredCards.innerHTML);
		//the first slot of a chassis is slot 0 and it isn't a functional card.
		//the second and third slots are 1 and 2 and hold the mgmt cards
		//slots 3 and above are for line cards
		for (let slot = 0; slot < this.slots; slot++){
			let found = false;
			for (let r of arr) {
				if (r["switch_number"] == slot) { 
					found=true; break; 
				}
			}
			let x_adjust = 0;
			let y_render_line = slot + 1;
			//left side mgmt card in slot 1
			if (slot==1) { x_adjust = -494; }
			//right side mgmt card in slot 2
			if (slot==2) { y_render_line = 2 ;}
			//line cards in slots 3 and above
			if (slot>2) { y_render_line = slot; }
			//if there is no card in the slot only add the "add card" button
			if (!found) {
				this.addSVGButton(slot, "ADD CARD", "", 884+x_adjust, (140*y_render_line)-138); 
			} else {
				//if there is a card in the slot add the "change" and "remove" buttons
				if (slot > 0) {
					this.addSVGButton(slot, "CHANGE", "", 784+x_adjust, (140*y_render_line)-138);
					this.addSVGButton(slot, "REMOVE", "", 884+x_adjust, (140*y_render_line)-138);
				}
			}
		}
	}

	draw() {
		var y_adjust=0;
		var x_adjust = 0;
		//if this.passed_instance == "" then we are drawing the chassis or a new switch
		//if it is != "" then we are drawing a line card
		if (this.passed_instance == "") {
			//add outline
 	        this.addItem (this.instance, this.shell.chassis, "switch-chassis", 1, 1, 0);
			//if the switch is a 6400 and the chassis switch
			if (this.family == "6400" && this.switch_number == 0) {
				this.addItem(this.instance, this.shell.chassis+"-overdraw", "switch-chassis", 1, 1, 0);
				this.addItem(this.instance, "splitBlade", "switch-chassis", 1, 1, 0);
			}
			//if the switch is not a chassis switch
        	if (this.family != "6400") { this.addItem (this.instance, this.shell.faceplate, "faceplate", 1, 1, 0); }
			this.addText (this.instance, this.family, 300, 135+this.textY_offset, "gmiDkBlueTxt");
		}
		//moves the card over to the right mgmt slot
		if (this.passed_instance != "" && this.switch_number == 2) {
			x_adjust=495;
		}
		//if it is a mgmt card
		if (this.passed_instance != "" && this.switch_number >0 && this.switch_number<3 && this.family=="6400") {
			//draw 6405 chassis -- modify this if/draw if want to add 6410
			//this.addItem (this.instance, this.shell.chassis, "switch-chassis", 1, 1, 0);
			y_adjust = 140;
		//if it is a line card
		} else if (this.passed_instance != "" && this.switch_number>2 && this.family=="6400") {		
			y_adjust = (this.switch_number - 1) * 140
		} else {
			y_adjust = 0;
		}

		this.addText (this.instance, this.switch_number, 5+x_adjust, 135+y_adjust+this.textY_offset, "gmiDkBlueTxt")
		this.addText (this.instance, this.model, 20+x_adjust, 135+y_adjust+this.textY_offset, "gmiDkBlueTxt")
		this.addText (this.instance, this.serial, 100+x_adjust, 135+y_adjust+this.textY_offset, "gmiDkBlueTxt")

 		//add all port banks
		let bank_length = this.banks.length;
		let math_mod;
		let row_y_mod;
        let row_x_mod;
		let rotation_mod;
        let y_spacing;
		for (let i = 0; i < bank_length; i++) {

			//set some variables that handle single line or dual line port banks
			if (this.banks[i].split_ports == true) {
				math_mod = 2;
				row_y_mod = [80,10];
                row_x_mod = [0,0];
				if (this.banks[i].direction && this.banks[i].direction == "topdown") {
                    rotation_mod = [180+this.banks[i].rotate,0+this.banks[i].rotate]
                    y_spacing = 40;
                    row_y_mod = [y_spacing,0];
                    row_x_mod = [this.banks[i].spacing,0];
                } else { rotation_mod = [180,0]; }
			} else {
				math_mod = 1;
				row_y_mod = [10];
                row_x_mod = [0];
				rotation_mod = [0];
                if (this.banks[i].direction && this.banks[i].direction == "topdown") {
                    y_spacing = 60;
                    row_y_mod = [y_spacing,0];
                    row_x_mod = [this.banks[i].spacing,0];
                    rotation_mod = [90];
                } else {
                    rotation_mod = [0];
                }
			}

            for (let x = 1; x <= this.banks[i].ports; x++){
                switch (this.banks[i].port_type) {
                    case "Copper":
                        if (this.banks[i].direction && this.banks[i].direction == "topdown") {
                            this.addPortRJ45(this.instance,
                                    x+this.banks[i].portStart,
                                    this.banks[i].position_x+(row_x_mod[(x%math_mod)])+x_adjust,
                                    this.banks[i].position_y+( (Math.floor((x-1)/math_mod)-((x-1)%math_mod)) * y_spacing ) + row_y_mod[x%math_mod] + y_adjust,
                                    0,
                                    rotation_mod[x % math_mod]);
                        } else {
                            this.addPortRJ45(this.instance,
                                x+this.banks[i].portStart,
                                this.banks[i].position_x+(((x+(x%math_mod))*this.banks[i].spacing)/2)+x_adjust,
                                (this.banks[i].position_y)+row_y_mod[x % math_mod]+y_adjust,
                                0,
                                rotation_mod[x % math_mod]);
                        }
                        break;
                    case "Copper-NoFunc":
                        this.addPortRJ45(this.instance,
                                x+this.banks[i].portStart,
                                this.banks[i].position_x+(((x+(x%math_mod))*this.banks[i].spacing)/2)+x_adjust,
                                (this.banks[i].position_y)+row_y_mod[x % math_mod]+y_adjust,
                                1,
                                rotation_mod[x % math_mod]);
                        break;
                    case "SFP":
                    case "QSFP":
                        if (this.banks[i].direction && this.banks[i].direction == "topdown") {
                            this.addPortSFP(this.banks[i].port_type, this.instance,
                                x+this.banks[i].portStart,
                                this.banks[i].position_x+(row_x_mod[(x%math_mod)])+x_adjust,
                                this.banks[i].position_y+( (Math.floor((x-1)/math_mod)-((x-1)%math_mod)) * y_spacing ) + row_y_mod[x%math_mod] + y_adjust,
                                rotation_mod[x % math_mod]);
                        } else {
                            this.addPortSFP(this.banks[i].port_type, this.instance,
                                x+this.banks[i].portStart,
                                this.banks[i].position_x+(((x+(x%math_mod))*this.banks[i].spacing)/2)+x_adjust,
                                (this.banks[i].position_y)+row_y_mod[x % math_mod]+y_adjust,
                                rotation_mod[x % math_mod]);
                        }
                        break;
                }
            }
	
		}
	} // end draw
} // end class
